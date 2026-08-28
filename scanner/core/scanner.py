"""Top-level scan orchestrator: validate target -> crawl -> run checks -> score."""
from __future__ import annotations

import logging
from collections.abc import Callable

from scanner.checks.base import CheckContext, SecurityCheck
from scanner.checks.cookies import CookieSecurityCheck
from scanner.checks.cors import CorsCheck
from scanner.checks.disclosure import InformationDisclosureCheck
from scanner.checks.forms import FormsCheck
from scanner.checks.headers import SecurityHeadersCheck
from scanner.checks.methods import HttpMethodsCheck
from scanner.checks.security_txt import SecurityTxtCheck
from scanner.checks.tls import TlsCheck
from scanner.core.crawler import crawl
from scanner.core.http_client import SafeHttpClient
from scanner.core.target_validator import validate_target
from scanner.models.scan import PROFILE_CHECKS, ScanConfig, ScanProfile, ScanResult, ScanStatus
from scanner.utils.formatting import calculate_risk_score

logger = logging.getLogger("scanner.core.scanner")

# Registry mapping check name -> class. Adding a new check to the scanner
# only requires registering it here and adding it to PROFILE_CHECKS.
CHECK_REGISTRY: dict[str, type[SecurityCheck]] = {
    "headers": SecurityHeadersCheck,
    "cookies": CookieSecurityCheck,
    "tls": TlsCheck,
    "cors": CorsCheck,
    "methods": HttpMethodsCheck,
    "disclosure": InformationDisclosureCheck,
    "security_txt": SecurityTxtCheck,
    "forms": FormsCheck,
}

ProgressCallback = Callable[[ScanResult, str], None]


async def run_scan(config: ScanConfig, on_progress: ProgressCallback | None = None) -> ScanResult:
    result = ScanResult(target_url=config.target_url, config=config)

    def report(stage: str) -> None:
        if on_progress:
            on_progress(result, stage)

    validation = validate_target(config.target_url)
    if not validation.is_valid:
        result.status = ScanStatus.FAILED
        result.error = f"Target validation failed: {validation.reason}"
        report("failed")
        return result

    result.mark_started()
    report("started")

    client = SafeHttpClient(
        timeout_seconds=config.timeout_seconds,
        rate_limit_rps=config.rate_limit_rps,
    )

    try:
        result.status = ScanStatus.CRAWLING
        report("crawling")

        crawl_result = await crawl(
            client,
            validation.normalized_url or config.target_url,
            max_depth=config.max_depth,
            max_pages=config.max_pages,
            same_domain_only=config.same_domain_only,
        )
        result.pages_scanned = len(crawl_result.pages)
        result.requests_made = client.requests_made

        result.status = ScanStatus.ANALYZING
        report("analyzing")

        profile = config.profile if isinstance(config.profile, ScanProfile) else ScanProfile(config.profile)
        check_names = PROFILE_CHECKS[profile]

        context = CheckContext(
            target_url=config.target_url,
            pages=crawl_result.pages,
            resolved_ips=validation.resolved_ips or [],
        )

        for check_name in check_names:
            check_cls = CHECK_REGISTRY.get(check_name)
            if not check_cls:
                logger.warning("Unknown check '%s' in profile — skipping", check_name)
                continue
            check = check_cls()
            try:
                findings = await check.run(context)
                result.findings.extend(findings)
                logger.info("Check '%s' found %d finding(s)", check_name, len(findings))
            except Exception as exc:  # noqa: BLE001 — one check failing must not kill the scan
                logger.error("Check '%s' raised an exception: %s", check_name, exc)

        result.requests_made = client.requests_made
        result.risk_score = calculate_risk_score(result.findings)
        result.mark_completed()
        report("completed")

    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan failed with an unexpected error")
        result.status = ScanStatus.FAILED
        result.error = str(exc)
        report("failed")
    finally:
        await client.close()

    return result
