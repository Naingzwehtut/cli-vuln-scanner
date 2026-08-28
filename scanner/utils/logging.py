"""Structured logging setup. Never log secrets — see redact() helper."""
from __future__ import annotations

import logging
import sys

SENSITIVE_KEYS = {"password", "authorization", "cookie", "set-cookie", "token", "api_key", "apikey", "secret"}


def redact(key: str, value: str) -> str:
    """Use this whenever logging a header/field that might be sensitive."""
    if key.lower() in SENSITIVE_KEYS:
        return "***REDACTED***"
    return value


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s"))

    root = logging.getLogger("scanner")
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)
