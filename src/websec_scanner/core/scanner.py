"""Scan orchestration.

The scanner is the only place that knows about *running* checks: it builds a
client per target, fetches the home page once, runs every enabled check with
isolated error handling, scores the findings and assembles the
:class:`ScanResult`. Targets are scanned concurrently; a failing check never
aborts the others.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from urllib.parse import urlsplit

from .. import __version__
from .context import ScanConfig, ScanContext
from .http_client import HttpClient
from .models import ScanResult, TargetResult
from .registry import get_checks
from .scoring import score_findings


def normalize_target(raw: str) -> str:
    """Ensure a target has a scheme; default to https:// when omitted."""
    raw = raw.strip()
    if not raw:
        return raw
    if not urlsplit(raw).scheme:
        raw = "https://" + raw
    return raw.rstrip("/")


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    # -- single target ------------------------------------------------------
    def scan_target(self, raw_target: str) -> TargetResult:
        target = normalize_target(raw_target)
        result = TargetResult(target=target)
        start = time.monotonic()

        client = HttpClient(
            target,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            rate_limit_delay=self.config.rate_limit_delay,
            verify_tls=self.config.verify_tls,
            follow_redirects=self.config.follow_redirects,
        )
        try:
            ctx = ScanContext(target=target, client=client, config=self.config)
            ctx.base_response = client.safe_get()
            if ctx.base_response is None:
                result.errors.append(
                    "Target unreachable: no HTTP response from the base URL."
                )

            for check in get_checks(self.config.enabled_checks):
                try:
                    findings = check.run(ctx)
                    result.findings.extend(findings)
                    result.checks_run.append(check.id)
                except Exception as exc:  # noqa: BLE001 - isolate check failures
                    result.errors.append(f"check '{check.id}' failed: {exc}")

            result.errors.extend(ctx.errors)
        finally:
            client.close()

        result.findings.sort(key=lambda f: f.severity.rank, reverse=True)
        result.score = score_findings(result.findings)
        result.duration_s = time.monotonic() - start
        return result

    # -- many targets -------------------------------------------------------
    def scan(self, targets: list[str]) -> ScanResult:
        started = datetime.now(UTC)
        start = time.monotonic()

        workers = max(1, min(self.config.threads, len(targets)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            target_results = list(pool.map(self.scan_target, targets))

        return ScanResult(
            targets=target_results,
            scanner_version=__version__,
            started_at=started.isoformat(timespec="seconds"),
            duration_s=time.monotonic() - start,
            lang=self.config.lang,
        )

# GROGNON
