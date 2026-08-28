"""CSV report export - one row per finding."""
from __future__ import annotations

import csv
from pathlib import Path

from scanner.models.scan import ScanResult

FIELDS = [
    "severity", "confidence", "status", "category", "title", "url",
    "owasp", "cwe", "description", "evidence", "recommendation", "detection_method",
]


def generate_csv_report(result: ScanResult, output_path: Path) -> Path:
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for finding in result.findings:
            writer.writerow({field: getattr(finding, field) for field in FIELDS})
    return output_path
