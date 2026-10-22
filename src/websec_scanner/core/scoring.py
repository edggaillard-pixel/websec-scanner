"""Risk scoring engine.

The score is intentionally simple and transparent so that a reader of the
report can reproduce it by hand:

1. Every finding contributes its ``effective_weight`` (severity default, unless
   the check overrode it).
2. ``points`` is the sum of those weights; ``score_0_100`` is ``points`` capped
   at 100 (a convenience gauge for the report).
3. The overall :class:`RiskLevel` is derived from ``points`` with one override:
   a single CRITICAL finding forces the level to HIGH, regardless of the total.

Thresholds are module-level constants so they are easy to audit and tune.
"""

from __future__ import annotations

from collections import Counter

from .models import Finding, RiskLevel, ScoreResult, Severity

# Points thresholds for the overall risk band.
MEDIUM_THRESHOLD = 15
HIGH_THRESHOLD = 40


def score_findings(findings: list[Finding]) -> ScoreResult:
    """Aggregate a list of findings into a :class:`ScoreResult`."""
    points = sum(f.effective_weight for f in findings)
    has_critical = any(f.severity is Severity.CRITICAL for f in findings)

    if has_critical or points >= HIGH_THRESHOLD:
        level = RiskLevel.HIGH
    elif points >= MEDIUM_THRESHOLD:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    counts_raw = Counter(f.severity.label for f in findings)
    # Keep a stable, ordered set of severity keys in the output.
    counts = {sev.label: counts_raw.get(sev.label, 0) for sev in Severity}

    return ScoreResult(
        points=points,
        score_0_100=min(points, 100),
        level=level,
        counts=counts,
    )

# GROGNON
