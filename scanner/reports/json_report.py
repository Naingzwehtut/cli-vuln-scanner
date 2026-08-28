"""JSON report export."""
from __future__ import annotations

import json
from pathlib import Path

from scanner.models.scan import ScanResult


def generate_json_report(result: ScanResult, output_path: Path) -> Path:
    output_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return output_path
