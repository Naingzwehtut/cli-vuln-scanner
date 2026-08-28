import pytest

from scanner.checks.base import CheckContext
from scanner.checks.headers import SecurityHeadersCheck
from scanner.core.crawler import CrawledPage


def _page(headers: dict) -> CrawledPage:
    return CrawledPage(
        url="https://example.com/",
        status_code=200,
        content_type="text/html; charset=utf-8",
        headers=headers,
        html="<html></html>",
    )


@pytest.mark.asyncio
async def test_flags_missing_headers():
    context = CheckContext(target_url="https://example.com", pages=[_page({})])
    findings = await SecurityHeadersCheck().run(context)
    titles = {f.title for f in findings}
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("Strict-Transport-Security" in t or "Hsts" in t for t in titles)


@pytest.mark.asyncio
async def test_no_findings_when_all_headers_present():
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=63072000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    context = CheckContext(target_url="https://example.com", pages=[_page(headers)])
    findings = await SecurityHeadersCheck().run(context)
    assert findings == []


@pytest.mark.asyncio
async def test_skips_non_html_pages():
    page = _page({})
    page.content_type = "application/json"
    context = CheckContext(target_url="https://example.com", pages=[page])
    findings = await SecurityHeadersCheck().run(context)
    assert findings == []
