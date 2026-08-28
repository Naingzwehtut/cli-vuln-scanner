from scanner.models.finding import Confidence, Finding, Severity
from scanner.utils.formatting import calculate_risk_score, risk_label


def _finding(severity: Severity, confidence: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        title="test",
        severity=severity,
        confidence=confidence,
        category="Test",
        url="https://example.com",
        description="test",
        evidence="test",
        recommendation="test",
        detection_method="test",
    )


def test_no_findings_zero_score():
    assert calculate_risk_score([]) == 0


def test_informational_only_does_not_raise_score():
    findings = [_finding(Severity.INFO) for _ in range(20)]
    assert calculate_risk_score(findings) == 0


def test_single_critical_scores_high():
    score = calculate_risk_score([_finding(Severity.CRITICAL)])
    assert score >= 40


def test_score_is_bounded_at_100():
    findings = [_finding(Severity.CRITICAL) for _ in range(20)]
    assert calculate_risk_score(findings) <= 100


def test_low_confidence_discounts_score():
    high_conf = calculate_risk_score([_finding(Severity.HIGH, Confidence.HIGH)])
    low_conf = calculate_risk_score([_finding(Severity.HIGH, Confidence.LOW)])
    assert low_conf < high_conf


def test_risk_label_boundaries():
    assert risk_label(0) == "Low"
    assert risk_label(25) == "Moderate"
    assert risk_label(50) == "Medium"
    assert risk_label(70) == "High"
    assert risk_label(90) == "Critical"
