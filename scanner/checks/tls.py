"""
HTTPS/TLS checks.

Uses Python's ssl module to safely inspect the certificate presented by the
server (validity dates, issuer) without performing any active TLS attacks
(no downgrade attempts, no cipher fuzzing, no protocol-version forcing).
"""
from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanner.checks.base import CheckContext, SecurityCheck
from scanner.core.http_client import SafeHttpClient
from scanner.core.target_validator import validate_target
from scanner.models.finding import Confidence, Finding, FindingStatus, Severity

logger = logging.getLogger("scanner.checks.tls")

CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def _get_certificate_info(hostname: str, port: int = 443, timeout: float = 10.0) -> dict | None:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except (ssl.SSLError, socket.error, socket.timeout) as exc:
        logger.info("Could not retrieve certificate for %s: %s", hostname, exc)
        return None


class TlsCheck(SecurityCheck):
    name = "tls"
    description = "Checks HTTPS availability, certificate validity, and HTTP->HTTPS redirect"

    async def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(context.target_url)
        hostname = parsed.hostname
        if not hostname:
            return findings

        # 1. HTTPS availability
        if parsed.scheme != "https":
            findings.append(
                Finding(
                    title="Target does not use HTTPS by default",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="TLS/HTTPS",
                    owasp="A02:2021 - Cryptographic Failures",
                    cwe="CWE-319",
                    url=context.target_url,
                    description="The provided target URL uses plain HTTP rather than HTTPS.",
                    evidence=f"Target scheme: {parsed.scheme}",
                    recommendation="Serve the application over HTTPS and redirect all HTTP traffic to HTTPS.",
                    detection_method="URL scheme inspection",
                )
            )

        # 2. HTTP -> HTTPS redirect check (only meaningful if target given as https)
        if parsed.scheme == "https":
            http_url = f"http://{hostname}" + (f":{parsed.port}" if parsed.port else "")
            validation = validate_target(http_url)
            if validation.is_valid:
                client = SafeHttpClient(timeout_seconds=8.0)
                try:
                    response = await client.request(http_url, method="GET")
                    if not response.url.startswith("https://"):
                        findings.append(
                            Finding(
                                title="HTTP does not redirect to HTTPS",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                status=FindingStatus.POTENTIAL,
                                category="TLS/HTTPS",
                                owasp="A02:2021 - Cryptographic Failures",
                                cwe="CWE-319",
                                url=http_url,
                                description=(
                                    "Requesting the target over plain HTTP did not result in a redirect "
                                    "to HTTPS, meaning the site may be reachable insecurely."
                                ),
                                evidence=f"Final URL after request: {response.url}",
                                recommendation="Configure the server to redirect all HTTP requests to HTTPS.",
                                detection_method="HTTP request + redirect chain inspection",
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    logger.info("HTTP redirect check failed for %s: %s", http_url, exc)
                finally:
                    await client.close()

        # 3. Certificate validity / expiration
        if parsed.scheme == "https":
            port = parsed.port or 443
            cert = _get_certificate_info(hostname, port)
            if cert is None:
                findings.append(
                    Finding(
                        title="Could not verify TLS certificate",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        status=FindingStatus.POTENTIAL,
                        category="TLS/HTTPS",
                        owasp="A02:2021 - Cryptographic Failures",
                        cwe="CWE-295",
                        url=context.target_url,
                        description=(
                            "The scanner could not establish a validated TLS connection to retrieve "
                            "certificate details. This may indicate an invalid, self-signed, or "
                            "expired certificate, or a network issue."
                        ),
                        evidence="TLS handshake with certificate verification failed or timed out.",
                        recommendation="Ensure a valid certificate from a trusted CA is installed and the chain is complete.",
                        detection_method="TLS handshake with certificate verification",
                    )
                )
            else:
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
                        days_remaining = (expiry - datetime.now(timezone.utc)).days
                        if days_remaining < 0:
                            findings.append(
                                Finding(
                                    title="TLS certificate has expired",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    category="TLS/HTTPS",
                                    owasp="A02:2021 - Cryptographic Failures",
                                    cwe="CWE-298",
                                    url=context.target_url,
                                    description="The TLS certificate presented by the server has expired.",
                                    evidence=f"Certificate notAfter: {not_after}",
                                    recommendation="Renew the TLS certificate immediately.",
                                    detection_method="TLS certificate inspection",
                                )
                            )
                        elif days_remaining < 30:
                            findings.append(
                                Finding(
                                    title="TLS certificate expiring soon",
                                    severity=Severity.LOW,
                                    confidence=Confidence.HIGH,
                                    category="TLS/HTTPS",
                                    owasp="A02:2021 - Cryptographic Failures",
                                    cwe="CWE-298",
                                    url=context.target_url,
                                    description=f"The TLS certificate expires in {days_remaining} day(s).",
                                    evidence=f"Certificate notAfter: {not_after}",
                                    recommendation="Renew the TLS certificate before it expires.",
                                    detection_method="TLS certificate inspection",
                                )
                            )
                    except ValueError:
                        logger.info("Could not parse certificate expiry date: %s", not_after)

        return findings
