"""Scan configuration and the per-target context handed to each check."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from .http_client import HttpClient

DEFAULT_USER_AGENT = "websec-scanner/0.1 (+https://github.com/edggaillard-pixel/websec-scanner)"


@dataclass
class ScanConfig:
    """User-tunable settings for a whole scan run."""

    authorized: bool = False
    timeout: float = 10.0
    rate_limit_delay: float = 0.0
    threads: int = 8
    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True
    follow_redirects: bool = True
    lang: str = "en"
    wordlist: str | None = None  # extra wordlist path appended to the built-in one
    enabled_checks: list[str] | None = None  # None = all registered checks


@dataclass
class ScanContext:
    """Everything a single check needs to inspect one target.

    ``base_response`` is the client's GET of the target root, fetched once by the
    scanner and shared so that header/cookie/CSP checks do not each re-request
    the home page.
    """

    target: str
    client: HttpClient
    config: ScanConfig
    base_response: httpx.Response | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def lang(self) -> str:
        return self.config.lang

    @property
    def scheme(self) -> str:
        return urlsplit(self.target).scheme

    @property
    def host(self) -> str:
        return urlsplit(self.target).hostname or ""

    @property
    def port(self) -> int:
        split = urlsplit(self.target)
        return split.port or (443 if split.scheme == "https" else 80)

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

# GROGNON
