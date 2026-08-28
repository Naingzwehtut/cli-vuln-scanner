"""Checks for missing/misconfigured HTTP security headers."""
from __future__ import annotations

from scanner.checks.base import CheckContext, SecurityCheck
from scanner.models.finding import Confidence, Finding, FindingStatus, Severity

# header_name -> (severity, owasp, cwe, description, recommendation)
HEADER_RULES = {
    "content-security-policy": (
        Severity.MEDIUM,
        "A05:2021 - Security Misconfiguration",
        "CWE-693",
        "Content-Security-Policy header was not present. This header helps prevent "
        "cross-site scripting (XSS) and data injection attacks by controlling which "
        "resources the browser is allowed to load.",
        "Configure a Content-Security-Policy appropriate for the application, starting "
        "restrictive and loosening only as needed.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "A05:2021 - Security Misconfiguration",
        "CWE-319",
        "Strict-Transport-Security (HSTS) header was not present. Without it, browsers "
        "may allow the site to be accessed over plain HTTP, exposing traffic to "
        "downgrade and man-in-the-middle attacks.",
        "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains' once the "
        "site fully supports HTTPS.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "A05:2021 - Security Misconfiguration",
        "CWE-693",
        "X-Content-Type-Options header was not present, allowing browsers to MIME-sniff "
        "responses away from the declared Content-Type.",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "A05:2021 - Security Misconfiguration",
        "CWE-1021",
        "X-Frame-Options header was not present, which may allow the page to be "
        "embedded in a frame on another site (clickjacking risk), unless CSP "
        "frame-ancestors is used instead.",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP frame-ancestors.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "A05:2021 - Security Misconfiguration",
        "CWE-200",
        "Referrer-Policy header was not present, which may leak full URLs (including "
        "sensitive query parameters) to third parties via the Referer header.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
    "permissions-policy": (
        Severity.INFO,
        "A05:2021 - Security Misconfiguration",
        "CWE-693",
        "Permissions-Policy header was not present, so the browser applies default "
        "permissions for powerful features (camera, microphone, geolocation, etc.).",
        "Add a Permissions-Policy restricting features the application does not use.",
    ),
}


class SecurityHeadersCheck(SecurityCheck):
    name = "headers"
    description = "Checks for missing or weak HTTP security headers"

    async def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        checked_urls: set[str] = set()

        for page in context.pages:
            if page.url in checked_urls or "text/html" not in page.content_type:
                continue
            checked_urls.add(page.url)

            headers_lower = {k.lower(): v for k, v in page.headers.items()}

            for header_name, (severity, owasp, cwe, desc, rec) in HEADER_RULES.items():
                if header_name not in headers_lower:
                    findings.append(
                        Finding(
                            title=f"Missing {header_name.title().replace('-', '-')} Header",
                            severity=severity,
                            confidence=Confidence.HIGH,
                            status=FindingStatus.CONFIRMED,
                            category="Security Headers",
                            owasp=owasp,
                            cwe=cwe,
                            url=page.url,
                            description=desc,
                            evidence=f"'{header_name}' was not present in the response headers.",
                            recommendation=rec,
                            detection_method="HTTP response header inspection",
                        )
                    )

            # Weak-value spot checks (not exhaustive — flagged as Potential).
            xfo = headers_lower.get("x-frame-options", "").lower()
            if xfo and xfo not in ("deny", "sameorigin"):
                findings.append(
                    Finding(
                        title="Non-standard X-Frame-Options value",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.POTENTIAL,
                        category="Security Headers",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe="CWE-1021",
                        url=page.url,
                        description="X-Frame-Options was present but set to a non-standard value.",
                        evidence=f"X-Frame-Options: {xfo}",
                        recommendation="Use 'DENY' or 'SAMEORIGIN' unless a specific ALLOW-FROM need exists.",
                        detection_method="HTTP response header inspection",
                    )
                )

        return findings
