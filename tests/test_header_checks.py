"""Tests for header-based checks: security_headers, csp, cookies, http_banners."""

from __future__ import annotations

from websec_scanner.checks.cookies import CookiesCheck
from websec_scanner.checks.csp import CSPCheck, parse_csp
from websec_scanner.checks.http_banners import HttpBannersCheck
from websec_scanner.checks.security_headers import SecurityHeadersCheck

SECURE_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
    "content-security-policy": "default-src 'self'; base-uri 'self'",
}


def ids(findings):
    return {f.id for f in findings}


# -- security_headers -------------------------------------------------------
def test_all_headers_present_no_findings(ctx_factory):
    ctx = ctx_factory(headers=SECURE_HEADERS)
    assert SecurityHeadersCheck().run(ctx) == []


def test_missing_headers_are_reported(ctx_factory):
    ctx = ctx_factory(headers={})
    found = ids(SecurityHeadersCheck().run(ctx))
    assert "missing_hsts" in found
    assert "missing_x_frame_options" in found
    assert "missing_x_content_type_options" in found
    assert "missing_referrer_policy" in found
    assert "missing_permissions_policy" in found


def test_weak_hsts_short_max_age(ctx_factory):
    ctx = ctx_factory(headers={**SECURE_HEADERS, "strict-transport-security": "max-age=100"})
    found = ids(SecurityHeadersCheck().run(ctx))
    assert "weak_hsts" in found


def test_frame_ancestors_csp_counts_as_clickjacking_protection(ctx_factory):
    headers = {k: v for k, v in SECURE_HEADERS.items() if k != "x-frame-options"}
    headers["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'"
    found = ids(SecurityHeadersCheck().run(ctx_factory(headers=headers)))
    assert "missing_x_frame_options" not in found


def test_hsts_not_checked_on_http(ctx_factory):
    ctx = ctx_factory(base_url="http://victim.test", headers={})
    found = ids(SecurityHeadersCheck().run(ctx))
    assert "missing_hsts" not in found


# -- csp --------------------------------------------------------------------
def test_parse_csp_basic():
    policy = parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline' *")
    assert policy["default-src"] == ["'self'"]
    assert "unsafe-inline" in [s.strip("'") for s in policy["script-src"]]


def test_missing_csp_reported(ctx_factory):
    found = ids(CSPCheck().run(ctx_factory(headers={})))
    assert found == {"missing_csp"}


def test_csp_weaknesses_detected(ctx_factory):
    csp = "script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src *"
    ctx = ctx_factory(headers={"content-security-policy": csp})
    found = ids(CSPCheck().run(ctx))
    assert "csp_unsafe_inline" in found
    assert "csp_unsafe_eval" in found
    assert "csp_wildcard_source" in found
    assert "csp_missing_default_src" in found
    assert "csp_missing_base_uri" in found


def test_strong_csp_clean(ctx_factory):
    csp = "default-src 'self'; script-src 'self'; base-uri 'self'; object-src 'none'"
    ctx = ctx_factory(headers={"content-security-policy": csp})
    assert CSPCheck().run(ctx) == []


# -- cookies ----------------------------------------------------------------
def test_cookie_flags_missing(ctx_factory):
    ctx = ctx_factory(set_cookies=["sid=abc; Path=/"])
    found = ids(CookiesCheck().run(ctx))
    assert found == {"cookie_missing_secure", "cookie_missing_httponly", "cookie_missing_samesite"}


def test_cookie_fully_flagged_clean(ctx_factory):
    ctx = ctx_factory(set_cookies=["sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"])
    assert CookiesCheck().run(ctx) == []


def test_cookie_secure_not_required_on_http(ctx_factory):
    ctx = ctx_factory(base_url="http://victim.test", set_cookies=["sid=abc; HttpOnly; SameSite=Lax"])
    found = ids(CookiesCheck().run(ctx))
    assert "cookie_missing_secure" not in found


def test_cookie_names_aggregated(ctx_factory):
    ctx = ctx_factory(set_cookies=["a=1; Secure; HttpOnly", "b=2; Secure; HttpOnly"])
    findings = CookiesCheck().run(ctx)
    samesite = [f for f in findings if f.id == "cookie_missing_samesite"][0]
    assert set(samesite.evidence["cookies"]) == {"a", "b"}


# -- http_banners -----------------------------------------------------------
def test_version_banner_reported(ctx_factory):
    ctx = ctx_factory(headers={"server": "Apache/2.4.52", "x-powered-by": "PHP"})
    findings = HttpBannersCheck().run(ctx)
    found = ids(findings)
    assert "banner_version_disclosure" in found  # Apache/2.4.52
    assert "banner_tech_disclosure" in found  # PHP (no version)


def test_no_banner_no_finding(ctx_factory):
    assert HttpBannersCheck().run(ctx_factory(headers={})) == []

# GROGNON
