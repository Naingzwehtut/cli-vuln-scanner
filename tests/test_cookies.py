import pytest

from scanner.checks.base import CheckContext
from scanner.checks.cookies import CookieSecurityCheck
from scanner.core.crawler import CrawledPage


def _page(set_cookie: str) -> CrawledPage:
    return CrawledPage(
        url="https://example.com/",
        status_code=200,
        content_type="text/html",
        headers={"set-cookie": set_cookie},
        html="<html></html>",
    )


@pytest.mark.asyncio
async def test_flags_missing_secure_over_https():
    context = CheckContext(
        target_url="https://example.com",
        pages=[_page("sessionid=SUPERSECRETVALUE; Path=/; HttpOnly")],
    )
    findings = await CookieSecurityCheck().run(context)
    assert any("Secure" in f.title for f in findings)
    # Ensure the raw cookie value never leaks into evidence.
    assert all("SUPERSECRETVALUE" not in f.evidence for f in findings)


@pytest.mark.asyncio
async def test_flags_missing_httponly():
    context = CheckContext(
        target_url="https://example.com",
        pages=[_page("sessionid=abc123; Path=/; Secure")],
    )
    findings = await CookieSecurityCheck().run(context)
    assert any("HttpOnly" in f.title for f in findings)


@pytest.mark.asyncio
async def test_well_configured_cookie_has_fewer_findings():
    context = CheckContext(
        target_url="https://example.com",
        pages=[_page("sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict")],
    )
    findings = await CookieSecurityCheck().run(context)
    assert findings == []
