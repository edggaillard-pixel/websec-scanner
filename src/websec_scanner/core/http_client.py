"""Thin, polite HTTP client built on httpx.

Responsibilities kept here (and out of the checks):

* a single, identifiable User-Agent,
* a hard timeout on every request,
* a thread-safe rate limiter (minimum delay between requests to the same host),
  so that concurrent checks never hammer a target,
* uniform error handling: network failures are turned into
  :class:`HttpClientError` (``request``) or swallowed into ``None``
  (``safe_get``), never leaked as raw httpx exceptions.

One client instance is created per target, which naturally scopes the rate
limiter per host.
"""

from __future__ import annotations

import threading
import time
from urllib.parse import urljoin, urlsplit

import httpx


class HttpClientError(RuntimeError):
    """Raised by :meth:`HttpClient.request` when a request cannot complete."""


class HttpClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        user_agent: str = "websec-scanner",
        rate_limit_delay: float = 0.0,
        verify_tls: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.rate_limit_delay = max(0.0, rate_limit_delay)
        self._lock = threading.Lock()
        self._last_request = 0.0
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
        )

    # -- context manager ----------------------------------------------------
    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # -- url handling -------------------------------------------------------
    def resolve(self, path_or_url: str | None) -> str:
        """Resolve a possibly relative path against the base URL."""
        if not path_or_url:
            return self.base_url
        if urlsplit(path_or_url).scheme:
            return path_or_url
        return urljoin(self.base_url, path_or_url.lstrip("/"))

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).netloc

    # -- rate limiting ------------------------------------------------------
    def _throttle(self) -> None:
        if self.rate_limit_delay <= 0:
            return
        # Serialise access so concurrent threads honour the per-host delay.
        with self._lock:
            now = time.monotonic()
            wait = self.rate_limit_delay - (now - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    # -- requests -----------------------------------------------------------
    def request(self, method: str, path_or_url: str | None = None, **kwargs) -> httpx.Response:
        """Perform a request, raising :class:`HttpClientError` on failure."""
        url = self.resolve(path_or_url)
        self._throttle()
        try:
            return self._client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise HttpClientError(f"{type(exc).__name__}: {exc}") from exc

    def get(self, path_or_url: str | None = None, **kwargs) -> httpx.Response:
        return self.request("GET", path_or_url, **kwargs)

    def safe_get(self, path_or_url: str | None = None, **kwargs) -> httpx.Response | None:
        """Like :meth:`get` but returns ``None`` instead of raising."""
        try:
            return self.get(path_or_url, **kwargs)
        except HttpClientError:
            return None

# GROGNON
