"""Checks for a /.well-known/security.txt security contact policy."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from scanner.checks.base import CheckContext, SecurityCheck
from scanner.core.http_client import SafeHttpClient, SSRFBlockedError
from scanner.models.finding import Confidence, Finding, FindingStatus, Severity

logger = logging.getLogger("scanner.checks.security_txt")


class SecurityTxtCheck(SecurityCheck):
    name = "security_txt"
    description = "Checks whether the target publishes a /.well-known/security.txt policy"

    async def run(self, context: CheckContext) -> list[Finding]:
        parsed = urlparse(context.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        security_txt_url = f"{base}/.well-known/security.txt"

        client = SafeHttpClient(timeout_seconds=8.0)
        try:
            try:
                response = await client.request(security_txt_url, method="GET")
            except SSRFBlockedError:
                return []
            except Exception as exc:  # noqa: BLE001
                logger.info("security.txt check failed: %s", exc)
                return []

            if response.status_code != 200:
                return [
                    Finding(
                        title="No security.txt policy found",
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.INFORMATIONAL,
                        category="Security Policy",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe=None,
                        url=security_txt_url,
                        description=(
                            "No /.well-known/security.txt file was found. This file (RFC 9116) "
                            "helps security researchers report vulnerabilities responsibly."
                        ),
                        evidence=f"HTTP {response.status_code} at {security_txt_url}",
                        recommendation="Publish a security.txt file describing how to report vulnerabilities.",
                        detection_method="HTTP GET to well-known path",
                    )
                ]
            return []
        finally:
            await client.close()
