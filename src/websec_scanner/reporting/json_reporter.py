"""JSON report renderer.

The JSON output is simply ``ScanResult.to_dict()`` serialised with indentation
and UTF-8 preserved, so it is both human-readable and easy to consume from other
tools or a CI pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def write_json(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(render_json(result), encoding="utf-8")
    return path

# GROGNON
