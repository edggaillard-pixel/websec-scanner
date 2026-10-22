"""Standalone HTML report renderer.

Renders a single self-contained HTML file (CSS inlined, no external assets) via
Jinja2, so the report can be opened offline or embedded as a portfolio demo. All
user-facing chrome (section titles, severity labels) is localised from the
``_LABELS`` table using the scan's language.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core.models import ScanResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_LABELS = {
    "en": {
        "title": "Web Security Posture Report",
        "generated": "Generated",
        "scanner": "Scanner",
        "duration": "Duration",
        "target": "Target",
        "overall": "Overall risk",
        "score": "Risk score",
        "checks_run": "Checks run",
        "errors": "Errors",
        "findings": "Findings",
        "no_findings": "No findings for this target.",
        "severity": "Severity",
        "finding": "Finding",
        "recommendation": "Recommendation",
        "references": "References",
        "evidence": "Evidence",
        "summary": "Summary",
        "disclaimer": "Non-destructive, read-only assessment. Run only against systems you are authorised to test.",
        "risk": {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"},
        "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
    },
    "fr": {
        "title": "Rapport de posture de sécurité web",
        "generated": "Généré le",
        "scanner": "Scanner",
        "duration": "Durée",
        "target": "Cible",
        "overall": "Risque global",
        "score": "Score de risque",
        "checks_run": "Contrôles exécutés",
        "errors": "Erreurs",
        "findings": "Constats",
        "no_findings": "Aucun constat pour cette cible.",
        "severity": "Sévérité",
        "finding": "Constat",
        "recommendation": "Recommandation",
        "references": "Références",
        "evidence": "Preuve",
        "summary": "Synthèse",
        "disclaimer": "Évaluation non destructive, en lecture seule. "
        "À n'exécuter que sur des systèmes que vous êtes autorisé à tester.",
        "risk": {"low": "FAIBLE", "medium": "MOYEN", "high": "ÉLEVÉ"},
        "sev": {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible", "info": "Info"},
    },
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return env


def render_html(result: ScanResult, lang: str | None = None) -> str:
    lang = lang or result.lang or "en"
    labels = _LABELS.get(lang, _LABELS["en"])
    env = _env()
    template = env.get_template("report.html.j2")
    return template.render(
        result=result.to_dict(),
        labels=labels,
        severity_order=_SEVERITY_ORDER,
        generated=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        lang=lang,
    )


def write_html(result: ScanResult, path: str | Path, lang: str | None = None) -> Path:
    path = Path(path)
    path.write_text(render_html(result, lang), encoding="utf-8")
    return path

# GROGNON
