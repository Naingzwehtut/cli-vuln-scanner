"""Inspects Set-Cookie headers for Secure/HttpOnly/SameSite flags. Never logs cookie values."""
from __future__ import annotations


from scanner.checks.base import CheckContext, SecurityCheck
from scanner.models.finding import Confidence, Finding, FindingStatus, Severity


def _parse_set_cookie_attrs(raw_header: str) -> dict:
    """Parse a single Set-Cookie header's name and attribute flags (never the value)."""
    parts = [p.strip() for p in raw_header.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else "unknown"
    attrs = {p.split("=")[0].strip().lower() for p in parts[1:]}
    samesite = "lax"  # browser default
    for p in parts[1:]:
        if p.lower().startswith("samesite="):
            samesite = p.split("=", 1)[1].strip().lower()
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": samesite,
    }


class CookieSecurityCheck(SecurityCheck):
    name = "cookies"
    description = "Checks cookies for Secure, HttpOnly, and SameSite attributes"

    async def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        is_https = context.target_url.startswith("https://")

        for page in context.pages:
            raw_cookies = page.headers.get("set-cookie")
            if not raw_cookies:
                continue

            # httpx/http.client may fold multiple Set-Cookie headers into one string
            # separated by newlines depending on the client; handle both cases.
            cookie_lines = raw_cookies.split("\n") if "\n" in raw_cookies else [raw_cookies]

            for line in cookie_lines:
                attrs = _parse_set_cookie_attrs(line)
                cookie_name = attrs["name"]

                if is_https and not attrs["secure"]:
                    findings.append(
                        Finding(
                            title=f"Cookie '{cookie_name}' missing Secure attribute",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="Cookie Security",
                            owasp="A05:2021 - Security Misconfiguration",
                            cwe="CWE-614",
                            url=page.url,
                            description=(
                                "A cookie was set over HTTPS without the Secure attribute, "
                                "meaning it could also be sent over an insecure HTTP connection."
                            ),
                            evidence=f"Cookie name: {cookie_name} (value not logged)",
                            recommendation="Set the Secure attribute on all cookies served over HTTPS.",
                            detection_method="Set-Cookie header inspection",
                        )
                    )

                if not attrs["httponly"]:
                    findings.append(
                        Finding(
                            title=f"Cookie '{cookie_name}' missing HttpOnly attribute",
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            status=FindingStatus.POTENTIAL,
                            category="Cookie Security",
                            owasp="A05:2021 - Security Misconfiguration",
                            cwe="CWE-1004",
                            url=page.url,
                            description=(
                                "A cookie did not set the HttpOnly attribute, meaning it may be "
                                "readable by client-side JavaScript, increasing exposure in an XSS scenario."
                            ),
                            evidence=f"Cookie name: {cookie_name} (value not logged)",
                            recommendation=(
                                "Set HttpOnly on cookies that don't need to be read by client-side script "
                                "(e.g. session identifiers)."
                            ),
                            detection_method="Set-Cookie header inspection",
                        )
                    )

                if attrs["samesite"] == "none" and not attrs["secure"]:
                    findings.append(
                        Finding(
                            title=f"Cookie '{cookie_name}' uses SameSite=None without Secure",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="Cookie Security",
                            owasp="A05:2021 - Security Misconfiguration",
                            cwe="CWE-1275",
                            url=page.url,
                            description=(
                                "SameSite=None requires the Secure attribute; modern browsers reject "
                                "such cookies, which can also indicate a misconfiguration."
                            ),
                            evidence=f"Cookie name: {cookie_name} (value not logged)",
                            recommendation="Pair SameSite=None with the Secure attribute, or use a stricter SameSite value.",
                            detection_method="Set-Cookie header inspection",
                        )
                    )

        return findings
