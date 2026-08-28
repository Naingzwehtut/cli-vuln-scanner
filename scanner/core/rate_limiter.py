"""Simple async token-bucket rate limiter, used to keep scan traffic polite."""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        self._interval = 1.0 / requests_per_second
        self._lock = asyncio.Lock()
        self._last_request_time: float | None = None

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if self._last_request_time is not None:
                elapsed = now - self._last_request_time
                wait_time = self._interval - elapsed
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
            self._last_request_time = time.monotonic()
