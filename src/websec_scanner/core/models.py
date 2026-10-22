"""Data models shared across the scanner.

The whole tool is organised around a single value object, :class:`Finding`.
Checks produce findings, the scoring engine aggregates them into a
:class:`ScoreResult`, and the reporters serialise the final
:class:`ScanResult`. Keeping these as plain dataclasses makes the data trivial
to serialise to JSON and to render with Jinja2.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """Severity of a single finding, ordered from least to most serious.

    Each severity carries a default *weight* used by the scoring engine. A
    finding may override the weight (``Finding.weight``) when a specific
    occurrence deserves more or less emphasis than its class average.
    """

    INFO = ("info", 0)
    LOW = ("low", 3)
    MEDIUM = ("medium", 8)
    HIGH = ("high", 20)
    CRITICAL = ("critical", 40)

    def __init__(self, label: str, weight: int) -> None:
        self.label = label
        self.weight = weight

    @property
    def rank(self) -> int:
        """Numeric rank (0 = INFO .. 4 = CRITICAL) for sorting/comparison."""
        return list(Severity).index(self)

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank


class RiskLevel(enum.Enum):
    """Overall, human-facing risk band for a target."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    """A single observation produced by a check.

    Attributes:
        id: Stable identifier (e.g. ``"missing_hsts"``). Lets reports and tests
            reference a finding without depending on its wording.
        check: Id of the check module that produced it.
        title: Short, human-readable, localised title.
        severity: :class:`Severity` of this occurrence.
        description: What was observed and why it matters (localised).
        recommendation: How to remediate (localised).
        owasp: OWASP Top 10 (2021) category reference, e.g. ``"A05:2021"``.
        cwe: CWE reference, e.g. ``"CWE-693"``.
        evidence: Machine-readable details (header values, paths, etc.).
        weight: Scoring weight; defaults to the severity's default weight.
    """

    id: str
    check: str
    title: str
    severity: Severity
    description: str = ""
    recommendation: str = ""
    owasp: str = ""
    cwe: str = ""
    evidence: dict = field(default_factory=dict)
    weight: int | None = None

    @property
    def effective_weight(self) -> int:
        return self.severity.weight if self.weight is None else self.weight

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "check": self.check,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "recommendation": self.recommendation,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "evidence": self.evidence,
            "weight": self.effective_weight,
        }


@dataclass
class ScoreResult:
    """Outcome of the scoring engine for one target."""

    points: int
    score_0_100: int
    level: RiskLevel
    counts: dict[str, int]  # severity label -> number of findings

    def to_dict(self) -> dict:
        return {
            "points": self.points,
            "score_0_100": self.score_0_100,
            "level": self.level.value,
            "counts": self.counts,
        }


@dataclass
class TargetResult:
    """Everything the scan learned about a single target URL."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    score: ScoreResult | None = None
    checks_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "score": self.score.to_dict() if self.score else None,
            "checks_run": self.checks_run,
            "errors": self.errors,
            "duration_s": round(self.duration_s, 3),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    """Top-level result returned by the scanner for a whole run."""

    targets: list[TargetResult] = field(default_factory=list)
    scanner_version: str = ""
    started_at: str = ""
    duration_s: float = 0.0
    lang: str = "en"

    def to_dict(self) -> dict:
        return {
            "scanner_version": self.scanner_version,
            "started_at": self.started_at,
            "duration_s": round(self.duration_s, 3),
            "lang": self.lang,
            "targets": [t.to_dict() for t in self.targets],
        }

# GROGNON
