"""Tests for checks that issue their own HTTP requests: robots, exposed_files.

These use respx to mock the transport, so the HttpClient inside the context
talks to deterministic fake responses.
"""

from __future__ import annotations

import httpx
import respx

from websec_scanner.checks.exposed_files import Baseline, ExposedFilesCheck, load_wordlist
from websec_scanner.checks.robots import RobotsCheck
from websec_scanner.core.context import ScanContext
from websec_scanner.core.http_client import HttpClient

BASE = "https://victim.test"


def _ctx(config) -> ScanContext:
    client = HttpClient(BASE, verify_tls=False)
    return ScanContext(target=BASE, client=client, config=config)


def ids(findings):
    return {f.id for f in findings}


# -- robots -----------------------------------------------------------------
@respx.mock
def test_robots_sensitive_paths(config):
    respx.get(f"{BASE}/robots.txt").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            text="User-agent: *\nDisallow: /admin/\nDisallow: /public/\nDisallow: /backup/\n",
        )
    )
    ctx = _ctx(config)
    findings = RobotsCheck().run(ctx)
    ctx.client.close()
    assert ids(findings) == {"robots_sensitive_paths"}
    assert "/admin/" in findings[0].evidence["sensitive"]
    assert "/public/" not in findings[0].evidence["sensitive"]


@respx.mock
def test_robots_absent_no_finding(config):
    respx.get(f"{BASE}/robots.txt").mock(return_value=httpx.Response(404))
    ctx = _ctx(config)
    findings = RobotsCheck().run(ctx)
    ctx.client.close()
    assert findings == []


# -- exposed_files: soft-404 calibration ------------------------------------
# A realistic soft-404: a sizeable generic HTML error page.
SOFT404_BODY = "<html><head><title>Not found</title></head><body>" + ("x" * 800) + "</body></html>"


@respx.mock
def test_exposed_files_detects_git_and_env_hard_404(config):
    # Server returns hard 404 for unknown paths: any 200 is a genuine hit.
    respx.get(url__regex=rf"{BASE}/[0-9a-f]+-[0-9a-f]+\.html").mock(
        return_value=httpx.Response(404, text="Not Found")
    )
    respx.get(f"{BASE}/.git/config").mock(
        return_value=httpx.Response(200, text="[core]\n\trepositoryformatversion = 0\n")
    )
    respx.get(f"{BASE}/.env").mock(
        return_value=httpx.Response(200, text="SECRET_KEY=supersecret\nDB_PASS=hunter2\n")
    )
    respx.get(url__startswith=BASE).mock(return_value=httpx.Response(404, text="Not Found"))

    ctx = _ctx(config)
    findings = ExposedFilesCheck().run(ctx)
    ctx.client.close()
    found = ids(findings)
    assert "exposed_vcs" in found
    assert "exposed_env" in found


@respx.mock
def test_exposed_files_detects_real_hit_on_soft404_site(config):
    # Soft-404 site: unknown paths return a large 200 page; a small real file
    # whose length clearly differs must still be detected.
    respx.get(url__regex=rf"{BASE}/[0-9a-f]+-[0-9a-f]+\.html").mock(
        return_value=httpx.Response(200, text=SOFT404_BODY)
    )
    respx.get(f"{BASE}/.env").mock(
        return_value=httpx.Response(200, text="SECRET_KEY=supersecret\nDB_PASS=hunter2\n")
    )
    respx.get(url__startswith=BASE).mock(return_value=httpx.Response(200, text=SOFT404_BODY))

    ctx = _ctx(config)
    findings = ExposedFilesCheck().run(ctx)
    ctx.client.close()
    assert "exposed_env" in ids(findings)


@respx.mock
def test_exposed_files_respects_soft404(config):
    # Every path (including real ones) returns the same soft-404 page: no hits.
    respx.get(url__startswith=BASE).mock(return_value=httpx.Response(200, text=SOFT404_BODY))
    ctx = _ctx(config)
    findings = ExposedFilesCheck().run(ctx)
    ctx.client.close()
    assert findings == []  # no false positives


def test_baseline_soft404_length_tolerance():
    b = Baseline(statuses={200}, lengths=[900])
    assert b.soft_200
    assert b.looks_like_soft404(200, 905)  # within tolerance -> same page
    assert not b.looks_like_soft404(200, 40)  # small file -> real hit


def test_baseline_hard_404_any_200_is_hit():
    b = Baseline(statuses={404}, lengths=[9])
    assert not b.soft_200
    assert not b.looks_like_soft404(200, 40)  # 200 is meaningful -> hit


def test_wordlist_loads_builtin_and_extra(tmp_path):
    extra = tmp_path / "extra.txt"
    extra.write_text("custom/secret.txt config\n# comment\n", encoding="utf-8")
    entries = load_wordlist(str(extra))
    paths = [p for p, _ in entries]
    assert ".git/config" in paths  # built-in
    assert "custom/secret.txt" in paths  # extra

# GROGNON
