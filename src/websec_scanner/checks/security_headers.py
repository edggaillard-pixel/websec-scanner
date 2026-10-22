"""Audit of HTTP security response headers (excluding CSP and cookies).

Covers HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and
Permissions-Policy. CSP has its own, deeper module (:mod:`.csp`) and cookies are
handled in :mod:`.cookies`.
"""

from __future__ import annotations

from ..core.catalog import make_finding
from ..core.context import ScanContext
from ..core.models import Finding
from ..core.registry import Check, register

CHECK_ID = "security_headers"


@register
class SecurityHeadersCheck(Check):
    id = CHECK_ID
    name = "Security headers"
    description = "Checks HSTS, X-Frame-Options, X-Content-Type-Options, Referrer/Permissions-Policy."

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []
        headers = resp.headers  # case-insensitive mapping
        findings: list[Finding] = []

        # --- HSTS (only meaningful over HTTPS) ---
        if ctx.is_https:
            hsts = headers.get("strict-transport-security")
            if hsts is None:
                findings.append(make_finding("missing_hsts", check=self.id, lang=ctx.lang))
            else:
                findings.extend(self._inspect_hsts(ctx, hsts))

        # --- Clickjacking: X-Frame-Options OR CSP frame-ancestors ---
        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "")
        if xfo is None and "frame-ancestors" not in csp.lower():
            findings.append(
                make_finding("missing_x_frame_options", check=self.id, lang=ctx.lang)
            )

        # --- MIME sniffing ---
        xcto = headers.get("x-content-type-options", "")
        if xcto.strip().lower() != "nosniff":
            findings.append(
                make_finding(
                    "missing_x_content_type_options",
                    check=self.id,
                    lang=ctx.lang,
                    evidence={"value": xcto or None},
                )
            )

        # --- Referrer-Policy ---
        if "referrer-policy" not in headers:
            findings.append(
                make_finding("missing_referrer_policy", check=self.id, lang=ctx.lang)
            )

        # --- Permissions-Policy ---
        if "permissions-policy" not in headers:
            findings.append(
                make_finding("missing_permissions_policy", check=self.id, lang=ctx.lang)
            )

        return findings

    @staticmethod
    def _inspect_hsts(ctx: ScanContext, value: str) -> list[Finding]:
        directives = {}
        for part in value.split(";"):
            part = part.strip()
            if not part:
                continue
            key, _, val = part.partition("=")
            directives[key.strip().lower()] = val.strip()

        reasons: list[str] = []
        try:
            max_age = int(directives.get("max-age", "0"))
        except ValueError:
            max_age = 0
        if max_age < 31536000:  # < 1 year
            reasons.append(
                "max-age below one year" if ctx.lang == "en" else "max-age inférieur à un an"
            )
        if "includesubdomains" not in directives:
            reasons.append(
                "no includeSubDomains" if ctx.lang == "en" else "pas de includeSubDomains"
            )
        if not reasons:
            return []
        return [
            make_finding(
                "weak_hsts",
                check=CHECK_ID,
                lang=ctx.lang,
                evidence={"header": value, "max_age": max_age},
                reason=", ".join(reasons),
            )
        ]

# GROGNON
