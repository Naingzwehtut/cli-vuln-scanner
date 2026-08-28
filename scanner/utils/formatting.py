"""
Risk score calculation (0-100).

Design goals:
  - Severity dominates: a single Critical should push the score high on its own.
  - Confidence discounts uncertain findings so "Potential" noise doesn't
    inflate the score as much as "Confirmed" issues.
  - Informational findings contribute nothing — they shouldn't move the score
    by themselves (see requirement in the spec).
  - Diminishing returns on volume: the 10th Medium finding shouldn't add as
    much as the 1st, otherwise a large site with many minor issues scores
    the same as one riddled with critical flaws.
"""
from __future__ import annotations

import math

from scanner.models.finding import Confidence, Finding, Severity

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 22,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 0,
}

CONFIDENCE_MULTIPLIERS = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW: 0.3,
}


def calculate_risk_score(findings: list[Finding]) -> int:
    if not findings:
        return 0

    raw_total = 0.0
    for finding in findings:
        severity = finding.severity if isinstance(finding.severity, Severity) else Severity(finding.severity)
        confidence = (
            finding.confidence if isinstance(finding.confidence, Confidence) else Confidence(finding.confidence)
        )
        raw_total += SEVERITY_WEIGHTS[severity] * CONFIDENCE_MULTIPLIERS[confidence]

    # Logarithmic dampening keeps the score bounded and prevents pure volume
    # of low-severity findings from reaching Critical territory.
    dampened = 100 * (1 - math.exp(-raw_total / 60))
    return min(100, round(dampened))


def risk_label(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 40:
        return "Moderate"
    if score <= 60:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"
