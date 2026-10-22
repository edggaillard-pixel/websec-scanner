"""robots.txt analysis.

A missing robots.txt is not a finding. When present, Disallow entries are
inspected for keywords that hint at sensitive areas (admin, backup, config,
private, ...). These are reported as INFO: robots.txt is a reconnaissance aid,
not a vulnerability by itself.
"""

from __future__ import annotations

from ..core.catalog import make_finding
from ..core.context import ScanContext
from ..core.models import Finding
from ..core.registry import Check, register

_SENSITIVE_HINTS = (
    "admin",
    "login",
    "backup",
    "config",
    "private",
    "secret",
    "db",
    "sql",
    "api",
    "internal",
    "upload",
    "tmp",
    "test",
    ".git",
    "wp-admin",
)


@register
class RobotsCheck(Check):
    id = "robots"
    name = "robots.txt"
    description = "Parses robots.txt for disallowed paths that hint at sensitive areas."

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.client.safe_get("robots.txt")
        if resp is None or resp.status_code != 200:
            return []
        content_type = resp.headers.get("content-type", "")
        # Avoid treating an HTML error/landing page as robots.txt.
        if "html" in content_type.lower():
            return []

        disallowed = self._disallowed_paths(resp.text)
        sensitive = [
            p for p in disallowed if any(h in p.lower() for h in _SENSITIVE_HINTS)
        ]
        if not sensitive:
            return []

        shown = sensitive[:15]
        return [
            make_finding(
                "robots_sensitive_paths",
                check=self.id,
                lang=ctx.lang,
                paths=", ".join(shown),
                evidence={"disallowed": disallowed, "sensitive": sensitive},
            )
        ]

    @staticmethod
    def _disallowed_paths(text: str) -> list[str]:
        paths: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                value = line.split(":", 1)[1].strip()
                if value and value != "/":
                    paths.append(value)
        return paths

# GROGNON
