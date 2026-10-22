"""Detection of information disclosure through HTTP response headers.

Headers such as ``Server`` or ``X-Powered-By`` often reveal the exact component
and version in use, which lets an attacker look up known CVEs. A header that
contains a version number is reported as LOW; a technology banner without a
version is INFO.
"""

from __future__ import annotations

import re

from ..core.catalog import make_finding
from ..core.context import ScanContext
from ..core.models import Finding
from ..core.registry import Check, register

# Headers that commonly leak implementation details.
_BANNER_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
)

# A version looks like "1.2", "2.4.52", "/8.1.0", etc.
_VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)*")


@register
class HttpBannersCheck(Check):
    id = "http_banners"
    name = "Banner disclosure"
    description = "Detects version/technology disclosure in response headers."

    def run(self, ctx: ScanContext) -> list[Finding]:
        resp = ctx.base_response
        if resp is None:
            return []
        findings: list[Finding] = []
        for header in _BANNER_HEADERS:
            value = resp.headers.get(header)
            if not value:
                continue
            if _VERSION_RE.search(value):
                findings.append(
                    make_finding(
                        "banner_version_disclosure",
                        check=self.id,
                        lang=ctx.lang,
                        header=header,
                        value=value,
                        evidence={"header": header, "value": value},
                    )
                )
            else:
                findings.append(
                    make_finding(
                        "banner_tech_disclosure",
                        check=self.id,
                        lang=ctx.lang,
                        header=header,
                        value=value,
                        evidence={"header": header, "value": value},
                    )
                )
        return findings

# GROGNON
