"""Detection of exposed sensitive files and directories.

A built-in wordlist (``data/sensitive_paths.txt``) maps each probed path to a
category (vcs, env, backup, config, devfile, admin) that drives the finding's
severity via the catalogue. An optional external wordlist is merged in.

Soft-404 calibration
--------------------
Many sites answer unknown paths with HTTP 200 and a generic page instead of a
real 404. To avoid false positives, the check first requests a handful of random
paths that cannot exist and records their response signatures (status code and
body length). A probed path is only reported as "exposed" when its response does
*not* look like those calibration responses. Probes run concurrently through a
thread pool, honouring the shared per-host rate limiter.
"""

from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from importlib import resources

from ..core.catalog import make_finding
from ..core.context import ScanContext
from ..core.models import Finding
from ..core.registry import Check, register

_CATEGORY_TO_FINDING = {
    "vcs": "exposed_vcs",
    "env": "exposed_env",
    "backup": "exposed_backup",
    "config": "exposed_config",
    "devfile": "exposed_devfile",
    "admin": "exposed_admin",
}

# Two bodies whose lengths are within this absolute AND relative tolerance are
# considered "the same page" for soft-404 purposes.
_LEN_ABS_TOLERANCE = 64
_LEN_REL_TOLERANCE = 0.10


@dataclass
class Baseline:
    """How the target responds to paths that are known not to exist.

    Captured by probing random paths. ``soft_200`` means the server answers
    unknown paths with a 2xx page (a soft-404), in which case a probed 2xx is
    only a hit when its body length clearly differs from the calibration pages.
    When the server returns hard errors for unknown paths, any 2xx/403 on a
    probed path is a genuine hit.
    """

    statuses: set[int] = field(default_factory=set)
    lengths: list[int] = field(default_factory=list)

    @property
    def soft_200(self) -> bool:
        return any(200 <= s < 300 for s in self.statuses)

    @property
    def soft_403(self) -> bool:
        return 403 in self.statuses

    def looks_like_soft404(self, status: int, length: int) -> bool:
        """True when (status, length) matches the server's not-found behaviour."""
        if status == 403 and self.soft_403:
            return True
        if 200 <= status < 300:
            if not self.soft_200:
                return False
            # Soft-404 site: same page if length is close to any calibration page.
            for ref in self.lengths:
                if abs(length - ref) <= max(_LEN_ABS_TOLERANCE, int(ref * _LEN_REL_TOLERANCE)):
                    return True
            return False
        return False


def load_wordlist(extra_path: str | None = None) -> list[tuple[str, str]]:
    """Return [(path, category)] from the built-in list plus an optional file."""
    entries: list[tuple[str, str]] = []

    def parse(text: str) -> None:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            path = parts[0]
            category = parts[1] if len(parts) > 1 else "devfile"
            entries.append((path, category))

    builtin = resources.files("websec_scanner.data").joinpath("sensitive_paths.txt")
    parse(builtin.read_text(encoding="utf-8"))

    if extra_path:
        with open(extra_path, encoding="utf-8") as fh:
            parse(fh.read())

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for path, category in entries:
        if path not in seen:
            seen.add(path)
            unique.append((path, category))
    return unique


@register
class ExposedFilesCheck(Check):
    id = "exposed_files"
    name = "Exposed files"
    description = "Probes for sensitive files/directories with soft-404 calibration."

    def run(self, ctx: ScanContext) -> list[Finding]:
        wordlist = load_wordlist(ctx.config.wordlist)
        baseline = self._calibrate(ctx)

        def probe(entry: tuple[str, str]) -> Finding | None:
            path, category = entry
            resp = ctx.client.safe_get(path)
            if resp is None:
                return None
            # Only 2xx and 403 are interesting (403 => the file exists but is
            # protected, still worth reporting for directories/VCS).
            if resp.status_code not in (200, 206, 403):
                return None
            length = len(resp.content or b"")
            if baseline.looks_like_soft404(resp.status_code, length):
                return None  # indistinguishable from the server's not-found page
            return self._to_finding(ctx, path, category, resp)

        workers = max(1, min(ctx.config.threads, len(wordlist)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = pool.map(probe, wordlist)

        return [f for f in results if f is not None]

    # -- helpers ------------------------------------------------------------
    def _calibrate(self, ctx: ScanContext, samples: int = 3) -> Baseline:
        """Probe random non-existent paths to learn the not-found behaviour."""
        baseline = Baseline()
        for _ in range(samples):
            rand = f"{secrets.token_hex(8)}-{secrets.token_hex(4)}.html"
            resp = ctx.client.safe_get(rand)
            if resp is not None:
                baseline.statuses.add(resp.status_code)
                baseline.lengths.append(len(resp.content or b""))
        return baseline

    def _to_finding(self, ctx: ScanContext, path: str, category: str, resp) -> Finding:
        body = (resp.text or "").lower()
        # Upgrade to a directory-listing finding when the hallmark markup shows.
        if path.endswith("/") and (
            "index of /" in body or "directory listing for" in body
        ):
            return make_finding(
                "exposed_listing",
                check=self.id,
                lang=ctx.lang,
                path=path,
                status=resp.status_code,
                evidence={"path": path, "status": resp.status_code},
            )
        finding_id = _CATEGORY_TO_FINDING.get(category, "exposed_devfile")
        return make_finding(
            finding_id,
            check=self.id,
            lang=ctx.lang,
            path=path,
            status=resp.status_code,
            evidence={
                "path": path,
                "status": resp.status_code,
                "content_type": resp.headers.get("content-type"),
                "length": len(resp.content or b""),
            },
        )

# GROGNON
