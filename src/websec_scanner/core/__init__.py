"""Core library: models, scanning engine, scoring and the check registry."""

from .context import ScanConfig, ScanContext
from .models import Finding, RiskLevel, ScanResult, ScoreResult, Severity, TargetResult
from .registry import Check, get_checks, register, registered_ids
from .scanner import Scanner, normalize_target
from .scoring import score_findings

__all__ = [
    "ScanConfig",
    "ScanContext",
    "Finding",
    "Severity",
    "RiskLevel",
    "ScoreResult",
    "TargetResult",
    "ScanResult",
    "Check",
    "register",
    "get_checks",
    "registered_ids",
    "Scanner",
    "normalize_target",
    "score_findings",
]

# GROGNON
