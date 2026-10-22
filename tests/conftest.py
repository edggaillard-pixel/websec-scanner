"""Shared fixtures and helpers for the test suite.

Checks are tested in isolation against mocked HTTP responses (via ``respx``),
so the suite is fast, deterministic and never touches the network.
"""

from __future__ import annotations

import httpx
import pytest

from websec_scanner.core.context import ScanConfig, ScanContext
from websec_scanner.core.http_client import HttpClient

BASE = "https://victim.test"


@pytest.fixture
def config() -> ScanConfig:
    return ScanConfig(authorized=True, lang="en", threads=2, timeout=5.0)


def make_ctx(
    config: ScanConfig,
    *,
    base_url: str = BASE,
    headers: dict | None = None,
    set_cookies: list[str] | None = None,
    status: int = 200,
    body: bytes = b"<html><body>ok</body></html>",
) -> ScanContext:
    """Build a ScanContext whose base_response is a synthetic httpx.Response."""
    client = HttpClient(base_url, user_agent=config.user_agent, verify_tls=False)
    resp_headers = httpx.Headers(headers or {})
    response = httpx.Response(
        status_code=status,
        headers=resp_headers,
        content=body,
        request=httpx.Request("GET", base_url),
    )
    if set_cookies:
        # httpx.Headers keeps repeated keys, so build it from a list of tuples.
        merged = httpx.Headers(
            list(resp_headers.multi_items()) + [("set-cookie", c) for c in set_cookies]
        )
        response = httpx.Response(
            status_code=status,
            headers=merged,
            content=body,
            request=httpx.Request("GET", base_url),
        )
    ctx = ScanContext(target=base_url, client=client, config=config)
    ctx.base_response = response
    return ctx


@pytest.fixture
def ctx_factory(config):
    created: list[ScanContext] = []

    def _factory(**kwargs) -> ScanContext:
        ctx = make_ctx(config, **kwargs)
        created.append(ctx)
        return ctx

    yield _factory
    for c in created:
        c.client.close()

# GROGNON
