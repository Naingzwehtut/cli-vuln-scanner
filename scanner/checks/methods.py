"""
Identifies HTTP methods the server reports as supported via the OPTIONS
method and the Allow header. Never issues DELETE/PUT/PATCH itself — this
is read-only enumeration.
"""
from __future__ import annotations

import logging

from scanner.checks.base import CheckContext, SecurityCheck
from scanner.core.http_client import SafeHttpClient, SSRFBlockedError
from scanner.models.finding import Confidence, Finding, FindingStatus, Severity

logger = logging.getLogger("scanner.checks.methods")

POTENTIALLY_RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


class HttpMethodsCheck(SecurityCheck):
    name = "methods"
    description = "Enumerates HTTP methods advertised via OPTIONS (read-only, no destructive calls)"

    async def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        client = SafeHttpClient(timeout_seconds=8.0)
        checked: set[str] = set()

        try:
            for page in context.pages:
                if page.url in checked:
                    continue
                checked.add(page.url)

                try:
                    response = await client.request(page.url, method="OPTIONS")
                except SSRFBlockedError:
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.info("OPTIONS request failed for %s: %s", page.url, exc)
                    continue

                allow_header = response.headers.get("allow")
                if not allow_header:
                    continue

                methods = {m.strip().upper() for m in allow_header.split(",")}
                risky = methods & POTENTIALLY_RISKY_METHODS
                if risky:
                    findings.append(
                        Finding(
                            title="Potentially risky HTTP methods advertised",
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            status=FindingStatus.POTENTIAL,
                            category="HTTP Methods",
                            owasp="A05:2021 - Security Misconfiguration",
                            cwe="CWE-749",
                            url=page.url,
                            description=(
                                "The server's Allow header advertises HTTP methods that are not "
                                "typically needed by a standard web application. Their presence "
                                "does not confirm exploitability — it indicates methods worth "
                                "reviewing for necessity and access control."
                            ),
                            evidence=f"Allow: {allow_header}",
                            recommendation=(
                                "Disable HTTP methods that are not required (e.g. TRACE, PUT, DELETE) "
                                "at the web server or framework level, or ensure they are properly authorized."
                            ),
                            detection_method="OPTIONS request + Allow header inspection",
                        )
                    )
        finally:
            await client.close()

        return findings
