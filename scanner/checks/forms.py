"""Analyzes forms discovered by the crawler. Never submits forms or handles credentials."""
from __future__ import annotations

from scanner.checks.base import CheckContext, SecurityCheck
from scanner.models.finding import Confidence, Finding, Severity


class FormsCheck(SecurityCheck):
    name = "forms"
    description = "Analyzes discovered forms for insecure submission and missing attributes"

    async def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []

        for page in context.pages:
            for form in page.forms:
                if form["has_password_field"] and not form["is_https"]:
                    findings.append(
                        Finding(
                            title="Password field in form submitted over HTTP",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="Forms",
                            owasp="A02:2021 - Cryptographic Failures",
                            cwe="CWE-319",
                            url=page.url,
                            description=(
                                "A form containing a password field submits to a non-HTTPS action "
                                "URL, meaning credentials would be transmitted in plaintext."
                            ),
                            evidence=f"Form action: {form['action']} (method: {form['method']})",
                            recommendation="Ensure all forms handling credentials submit exclusively over HTTPS.",
                            detection_method="HTML form parsing",
                        )
                    )
                elif form["has_password_field"] and form["method"] == "GET":
                    findings.append(
                        Finding(
                            title="Password field in a form using GET method",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="Forms",
                            owasp="A02:2021 - Cryptographic Failures",
                            cwe="CWE-598",
                            url=page.url,
                            description=(
                                "A form containing a password field uses the GET method, which "
                                "would place the password in the URL, browser history, and server logs."
                            ),
                            evidence=f"Form action: {form['action']} (method: GET)",
                            recommendation="Use the POST method for any form submitting sensitive data.",
                            detection_method="HTML form parsing",
                        )
                    )

        return findings
