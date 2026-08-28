"""
Target validation and SSRF protection.

This module is the primary safety boundary of the scanner. Every target URL
must pass through `validate_target()` before any HTTP request is made against
it — including every URL discovered by the crawler, not just the initial
user-supplied target.

Strategy: resolve the hostname to concrete IP addresses and reject the target
if ANY resolved address falls into a private, loopback, link-local, reserved,
or known cloud-metadata range. Blocking by hostname string alone is not
sufficient (DNS rebinding, alternate IP notations, etc.), so validation is
IP-based after resolution.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata endpoints — commonly used for SSRF-based credential theft.
# These are blocked regardless of the IP-range checks below, since some are
# link-local (already covered) but we make the intent explicit.
BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",       # AWS / Azure / GCP / OpenStack metadata
    "metadata.google.internal",
    "metadata.azure.com",
}

# Ports that are almost never legitimate web-app targets and are commonly
# used to pivot into internal services (databases, caches, admin panels).
BLOCKED_PORTS = {
    22, 23, 25, 110, 135, 137, 138, 139, 143,
    445, 1433, 1521, 2049, 3306, 3389, 5432,
    5900, 6379, 9200, 11211, 27017,
}


@dataclass
class ValidationResult:
    is_valid: bool
    reason: str | None = None
    resolved_ips: list[str] | None = None
    normalized_url: str | None = None


def _is_blocked_ip(ip_str: str) -> tuple[bool, str | None]:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Could not parse resolved address: {ip_str}"

    if ip.is_loopback:
        return True, "Target resolves to a loopback address"
    if ip.is_private:
        return True, "Target resolves to a private IP range"
    if ip.is_link_local:
        return True, "Target resolves to a link-local address (includes cloud metadata range)"
    if ip.is_reserved:
        return True, "Target resolves to a reserved IP range"
    if ip.is_multicast:
        return True, "Target resolves to a multicast address"
    if ip.is_unspecified:
        return True, "Target resolves to an unspecified address"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        # IPv4-mapped IPv6 addresses can be used to smuggle past naive IPv4-only checks.
        mapped_blocked, mapped_reason = _is_blocked_ip(str(ip.ipv4_mapped))
        if mapped_blocked:
            return True, f"Target resolves to an IPv4-mapped blocked address: {mapped_reason}"
    return False, None


def _resolve_all_ips(hostname: str) -> list[str]:
    """Resolve ALL addresses for a hostname (both A and AAAA records)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for '{hostname}': {exc}") from exc
    return sorted({info[4][0] for info in infos})


def validate_target(raw_url: str) -> ValidationResult:
    """
    Validate a target URL before it is ever requested.

    Call this for the initial scan target AND for every URL the crawler
    discovers — a same-domain link can still resolve to a different,
    disallowed IP if DNS changes between requests, so re-validation on
    every request is required, not optional.
    """
    raw_url = raw_url.strip()

    try:
        parsed = urlparse(raw_url)
    except ValueError as exc:
        return ValidationResult(is_valid=False, reason=f"Malformed URL: {exc}")

    if parsed.scheme not in ALLOWED_SCHEMES:
        return ValidationResult(
            is_valid=False,
            reason=f"Scheme '{parsed.scheme}' not allowed — only http/https are permitted",
        )

    hostname = parsed.hostname
    if not hostname:
        return ValidationResult(is_valid=False, reason="URL has no hostname")

    hostname_lower = hostname.lower()
    if hostname_lower in ("localhost", "0.0.0.0") or hostname_lower in BLOCKED_METADATA_HOSTS:
        return ValidationResult(is_valid=False, reason=f"Hostname '{hostname}' is explicitly blocked")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port in BLOCKED_PORTS:
        return ValidationResult(is_valid=False, reason=f"Port {port} is blocked (non-web service port)")

    # If the hostname is already a literal IP, validate it directly.
    try:
        literal_ip = ipaddress.ip_address(hostname)
        blocked, reason = _is_blocked_ip(str(literal_ip))
        if blocked:
            return ValidationResult(is_valid=False, reason=reason)
        resolved_ips = [str(literal_ip)]
    except ValueError:
        # Not a literal IP — resolve via DNS and check every returned address.
        try:
            resolved_ips = _resolve_all_ips(hostname)
        except ValueError as exc:
            return ValidationResult(is_valid=False, reason=str(exc))

        if not resolved_ips:
            return ValidationResult(is_valid=False, reason="DNS resolution returned no addresses")

        for ip_str in resolved_ips:
            blocked, reason = _is_blocked_ip(ip_str)
            if blocked:
                return ValidationResult(
                    is_valid=False,
                    reason=f"{reason} ({ip_str})",
                    resolved_ips=resolved_ips,
                )

    normalized = parsed._replace(fragment="").geturl()
    return ValidationResult(
        is_valid=True,
        resolved_ips=resolved_ips,
        normalized_url=normalized,
    )


def is_same_domain(base_url: str, candidate_url: str) -> bool:
    """Used by the crawler to stay within the authorized target's domain."""
    base_host = urlparse(base_url).hostname or ""
    candidate_host = urlparse(candidate_url).hostname or ""
    return base_host.lower() == candidate_host.lower()
