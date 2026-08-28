"""Flags safe-to-observe information disclosure via headers and generic error pages."""
from __future__ import annotations

from scanner.checks.base import CheckContext, SecurityCheck
from scanner.models.finding import Confidence, Finding, FindingStatus, Severity

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

VERBOSE_ERROR_MARKERS = [
    "stack trace",
    "traceback (most recent call last)",
    "django.db.utils",
    "warning: mysql_",
    "microsoft ole db provider",
    "unhandled exception",
    "at System.",
]


class InformationDisclosureCheck(SecurityCheck):
    name = "disclosure"
    description = "Checks for server/technology header disclosure and verbose error output"

    async def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        checked: set[str] = set()

        for page in context.pages:
            if page.url in checked:
                continue
            checked.add(page.url)

            headers_lower = {k.lower(): v for k, v in page.headers.items()}

            for header_name in DISCLOSURE_HEADERS:
                value = headers_lower.get(header_name)
                if value:
                    findings.append(
                        Finding(
                            title=f"Technology information disclosed via {header_name} header",
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            status=FindingStatus.INFORMATIONAL,
                            category="Information Disclosure",
                            owasp="A05:2021 - Security Misconfiguration",
                            cwe="CWE-200",
                            url=page.url,
                            description=(
                                f"The '{header_name}' response header discloses server or "
                                "framework information that could help an attacker fingerprint "
                                "the technology stack."
                            ),
                            evidence=f"{header_name}: {value}",
                            recommendation=f"Suppress or genericize the '{header_name}' header in production.",
                            detection_method="HTTP response header inspection",
                        )
                    )

            if page.html:
                lowered_body = page.html.lower()
                for marker in VERBOSE_ERROR_MARKERS:
                    if marker in lowered_body:
                        findings.append(
                            Finding(
                                title="Possible verbose error output detected",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.LOW,
                                status=FindingStatus.POTENTIAL,
                                category="Information Disclosure",
                                owasp="A05:2021 - Security Misconfiguration",
                                cwe="CWE-209",
                                url=page.url,
                                description=(
                                    "The response body contains a pattern commonly associated with "
                                    "verbose framework/database error output, which can leak internal "
                                    "implementation details."
                                ),
                                evidence=f"Matched pattern in response body: '{marker}'",
                                recommendation="Disable debug/verbose error output in production; show generic error pages instead.",
                                detection_method="Response body pattern matching",
                            )
                        )
                        break  # one finding per page is enough signal

        return findings
