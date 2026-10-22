"""Cookie attribute audit: Secure, HttpOnly and SameSite.

Set-Cookie headers are parsed from the base response. Findings are aggregated:
one finding per issue type, listing all affected cookie names, to avoid flooding
the report when many cookies share the same weakness.
"""

from __future__ import annotations

from ..core.catalog import make_finding
from ..core.context import ScanContext
from ..core.models import Finding
from ..core.registry import Check, register


def _iter_set_cookies(resp) -> list[str]:
    """Return raw Set-Cookie header values (httpx keeps every occurrence)."""
    return resp.headers.get_list("set-cookie")


@register
class CookiesCheck(Check):
    id = "cookies"
    name = "Cookie flags"
    description = "Flags cookies missing Secure, HttpOnly or SameSite."

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []
        raw_cookies = _iter_set_cookies(resp)
        if not raw_cookies:
            return []

        no_secure: list[str] = []
        no_httponly: list[str] = []
        no_samesite: list[str] = []

        for raw in raw_cookies:
            name, low = self._flags(raw)
            if not name:
                continue
            # 'Secure' only matters when the cookie is served over HTTPS.
            if ctx.is_https and "secure" not in low:
                no_secure.append(name)
            if "httponly" not in low:
                no_httponly.append(name)
            if "samesite" not in low:
                no_samesite.append(name)

        findings: list[Finding] = []
        if no_secure:
            findings.append(self._make(ctx, "cookie_missing_secure", no_secure))
        if no_httponly:
            findings.append(self._make(ctx, "cookie_missing_httponly", no_httponly))
        if no_samesite:
            findings.append(self._make(ctx, "cookie_missing_samesite", no_samesite))
        return findings

    @staticmethod
    def _flags(raw: str) -> tuple[str, set[str]]:
        """Return (cookie_name, set_of_present_attribute_keywords)."""
        parts = [p.strip().lower() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            return "", set()
        name = raw.split("=", 1)[0].strip()
        present: set[str] = set()
        for p in parts[1:]:
            key = p.split("=", 1)[0]
            present.add(key)
        return name, present

    def _make(self, ctx: ScanContext, finding_id: str, names: list[str]) -> Finding:
        return make_finding(
            finding_id,
            check=self.id,
            lang=ctx.lang,
            names=", ".join(sorted(set(names))),
            evidence={"cookies": sorted(set(names))},
        )

# GROGNON
