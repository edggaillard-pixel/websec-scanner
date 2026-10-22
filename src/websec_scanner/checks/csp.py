"""Content-Security-Policy analysis.

Beyond mere presence, this inspects the policy for common weaknesses:
``unsafe-inline`` / ``unsafe-eval``, wildcard sources in script/style/default,
and missing hardening directives (``default-src``, ``base-uri``).
"""

from __future__ import annotations

from ..core.catalog import make_finding
from ..core.context import ScanContext
from ..core.models import Finding
from ..core.registry import Check, register

# Directives where a wildcard source is most dangerous.
_WILDCARD_SENSITIVE = {"default-src", "script-src", "style-src", "object-src", "connect-src"}
# Directives where unsafe-inline/unsafe-eval matter.
_SCRIPTISH = {"default-src", "script-src", "style-src"}


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP header into {directive: [sources]} (lower-cased directives)."""
    policy: dict[str, list[str]] = {}
    for segment in value.split(";"):
        tokens = segment.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        policy[name] = [t for t in tokens[1:]]
    return policy


@register
class CSPCheck(Check):
    id = "csp"
    name = "Content-Security-Policy"
    description = "Parses the CSP and flags weak or missing directives."

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []
        raw = resp.headers.get("content-security-policy")
        if not raw:
            # Absence is reported by this module (not security_headers) so the
            # CSP concern lives in one place.
            return [make_finding("missing_csp", check=self.id, lang=ctx.lang)]

        policy = parse_csp(raw)
        findings: list[Finding] = []

        for directive in _SCRIPTISH & policy.keys():
            sources = [s.strip("'\"").lower() for s in policy[directive]]
            if "unsafe-inline" in sources:
                findings.append(
                    make_finding(
                        "csp_unsafe_inline",
                        check=self.id,
                        lang=ctx.lang,
                        directive=directive,
                        evidence={"directive": directive},
                    )
                )
            if "unsafe-eval" in sources:
                findings.append(
                    make_finding(
                        "csp_unsafe_eval",
                        check=self.id,
                        lang=ctx.lang,
                        directive=directive,
                        evidence={"directive": directive},
                    )
                )

        for directive in _WILDCARD_SENSITIVE & policy.keys():
            if "*" in policy[directive]:
                findings.append(
                    make_finding(
                        "csp_wildcard_source",
                        check=self.id,
                        lang=ctx.lang,
                        directive=directive,
                        evidence={"directive": directive},
                    )
                )

        if "default-src" not in policy:
            findings.append(
                make_finding("csp_missing_default_src", check=self.id, lang=ctx.lang)
            )
        if "base-uri" not in policy:
            findings.append(
                make_finding("csp_missing_base_uri", check=self.id, lang=ctx.lang)
            )

        return findings

# GROGNON
