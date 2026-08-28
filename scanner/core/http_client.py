"""
HTTP client wrapper used by everything in the scanner.

Every request goes through here so that safety limits (timeout, max response
size, redirect handling, target re-validation) are enforced in exactly one
place rather than re-implemented per check.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from scanner.core.rate_limiter import RateLimiter
from scanner.core.target_validator import validate_target

logger = logging.getLogger("scanner.http_client")

MAX_RESPONSE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_REDIRECTS = 5


@dataclass
class SafeResponse:
    url: str
    status_code: int
    headers: httpx.Headers
    text: str
    elapsed_seconds: float
    request_method: str


class SSRFBlockedError(Exception):
    """Raised when a request target fails validate_target() — never bypass this."""


class SafeHttpClient:
    """
    Async HTTP client that:
      - re-validates the target (and every redirect hop) against SSRF rules
      - enforces request timeout and max response size
      - enforces rate limiting
      - follows redirects manually so each hop can be validated
    """

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        rate_limit_rps: float = 5.0,
        user_agent: str = "WebVulnScanner/0.1 (authorized-testing)",
    ) -> None:
        self._rate_limiter = RateLimiter(rate_limit_rps)
        self._timeout = httpx.Timeout(timeout_seconds)
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=False,  # we handle redirects manually to re-validate each hop
            headers={"User-Agent": user_agent},
        )
        self.requests_made = 0

    async def close(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        url: str,
        method: str = "GET",
        max_redirects: int = MAX_REDIRECTS,
    ) -> SafeResponse:
        current_url = url
        for _ in range(max_redirects + 1):
            validation = validate_target(current_url)
            if not validation.is_valid:
                raise SSRFBlockedError(f"Blocked request to '{current_url}': {validation.reason}")

            await self._rate_limiter.acquire()
            self.requests_made += 1

            response = await self._client.request(method, current_url)

            if response.status_code in (301, 302, 303, 307, 308) and "location" in response.headers:
                next_url = httpx.URL(current_url).join(response.headers["location"])
                logger.info("Following redirect %s -> %s", current_url, next_url)
                current_url = str(next_url)
                continue

            body = await self._read_limited(response)
            return SafeResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers=response.headers,
                text=body,
                elapsed_seconds=response.elapsed.total_seconds() if response.elapsed else 0.0,
                request_method=method,
            )

        raise SSRFBlockedError(f"Too many redirects starting from '{url}'")

    @staticmethod
    async def _read_limited(response: httpx.Response) -> str:
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_SIZE_BYTES:
            return ""  # oversized responses are treated as empty rather than fully downloaded
        raw = response.content
        if len(raw) > MAX_RESPONSE_SIZE_BYTES:
            raw = raw[:MAX_RESPONSE_SIZE_BYTES]
        try:
            return raw.decode(response.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            return raw.decode("utf-8", errors="replace")
