"""Analyzes CORS response headers for overly permissive configurations."""
from __future__ import annotations

from scanner.checks.base import CheckContext, SecurityCheck
from scanner.models.finding import Confidence, Finding, FindingStatus, Severity


class CorsCheck(SecurityCheck):
    name = "cors"
    description = "Checks for overly permissive CORS configurations"

    async def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        checked: set[str] = set()

        for page in context.pages:
            if page.url in checked:
                continue
            checked.add(page.url)

            headers_lower = {k.lower(): v for k, v in page.headers.items()}
            acao = headers_lower.get("access-control-allow-origin")
            acac = headers_lower.get("access-control-allow-credentials", "").lower()

            if not acao:
                continue

            if acao == "*" and acac == "true":
                # Browsers actually reject this combination, but servers that send it
                # usually reflect the Origin header dynamically instead — flag as Potential
                # since we didn't send a crafted Origin to confirm reflection behavior.
                findings.append(
                    Finding(
                        title="Wildcard CORS origin combined with credentials allowed",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.POTENTIAL,
                        category="CORS",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe="CWE-942",
                        url=page.url,
                        description=(
                            "The server sent Access-Control-Allow-Origin: * together with "
                            "Access-Control-Allow-Credentials: true. This combination is invalid "
                            "per spec, and servers exhibiting it often reflect the request's "
                            "Origin header dynamically instead, which would allow any site to "
                            "make authenticated cross-origin requests."
                        ),
                        evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                        recommendation=(
                            "Restrict Access-Control-Allow-Origin to a specific, trusted list of "
                            "origins when credentials are allowed."
                        ),
                        detection_method="CORS response header inspection",
                    )
                )
            elif acao == "*":
                findings.append(
                    Finding(
                        title="Wildcard CORS origin allowed",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.POTENTIAL,
                        category="CORS",
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe="CWE-942",
                        url=page.url,
                        description=(
                            "The server allows cross-origin requests from any origin. This is "
                            "often intentional for public APIs, but should be verified against "
                            "the endpoint's sensitivity."
                        ),
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        recommendation="Restrict to specific trusted origins if the endpoint returns sensitive data.",
                        detection_method="CORS response header inspection",
                    )
                )

        return findings
