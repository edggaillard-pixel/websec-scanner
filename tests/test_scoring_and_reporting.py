"""Tests for the scoring engine and the report renderers."""

from __future__ import annotations

import json

from websec_scanner import __version__
from websec_scanner.core.catalog import make_finding
from websec_scanner.core.models import RiskLevel, ScanResult, Severity, TargetResult
from websec_scanner.core.scoring import HIGH_THRESHOLD, score_findings
from websec_scanner.reporting import render_html, render_json


def _f(fid, **kw):
    return make_finding(fid, check="test", lang="en", **kw)


def test_empty_is_low():
    score = score_findings([])
    assert score.level is RiskLevel.LOW
    assert score.points == 0


def test_single_critical_forces_high():
    # One critical finding, even with few points elsewhere, must be HIGH.
    score = score_findings([_f("exposed_env", path="/.env", status=200)])
    assert score.level is RiskLevel.HIGH
    assert score.counts["critical"] == 1


def test_points_accumulate_to_medium_then_high():
    mediums = [_f("missing_hsts") for _ in range(2)]  # 8 + 8 = 16 >= 15
    assert score_findings(mediums).level is RiskLevel.MEDIUM

    many = [_f("missing_hsts") for _ in range(6)]  # 48 >= 40
    assert many and score_findings(many).points >= HIGH_THRESHOLD
    assert score_findings(many).level is RiskLevel.HIGH


def test_counts_cover_all_severities():
    score = score_findings([_f("missing_hsts")])
    assert set(score.counts) == {s.label for s in Severity}


def _sample_result() -> ScanResult:
    findings = [
        _f("exposed_env", path="/.env", status=200),
        _f("missing_hsts"),
        _f("banner_version_disclosure", header="Server", value="Apache/2.4.52"),
    ]
    tr = TargetResult(target="https://victim.test", findings=findings)
    tr.score = score_findings(findings)
    return ScanResult(targets=[tr], scanner_version=__version__, lang="en")


def test_render_json_roundtrip():
    result = _sample_result()
    data = json.loads(render_json(result))
    assert data["scanner_version"] == __version__
    assert data["targets"][0]["score"]["level"] == "high"
    assert len(data["targets"][0]["findings"]) == 3
    # Each finding carries OWASP + CWE references.
    assert all(f["owasp"] and f["cwe"] for f in data["targets"][0]["findings"])


def test_render_html_contains_key_elements():
    html = render_html(_sample_result(), lang="en")
    assert "Web Security Posture Report" in html
    assert "victim.test" in html
    assert "OWASP A05:2021" in html
    assert "HIGH" in html


def test_render_html_french():
    html = render_html(_sample_result(), lang="fr")
    assert "Rapport de posture de sécurité web" in html
    assert "ÉLEVÉ" in html

# GROGNON
