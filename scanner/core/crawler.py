"""Controlled, same-domain crawler with depth/page limits and SSRF-safe requests."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from scanner.core.http_client import SafeHttpClient, SSRFBlockedError
from scanner.core.target_validator import is_same_domain, validate_target

logger = logging.getLogger("scanner.crawler")


@dataclass
class CrawledPage:
    url: str
    status_code: int
    content_type: str
    headers: dict
    html: str
    forms: list[dict] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    pages: list[CrawledPage] = field(default_factory=list)
    visited_urls: set[str] = field(default_factory=set)
    skipped_urls: dict[str, str] = field(default_factory=dict)  # url -> reason


def _normalize_url(url: str) -> str:
    url, _fragment = urldefrag(url)
    if url.endswith("/") and urlparse(url).path != "/":
        url = url[:-1]
    return url


def _extract_links(base_url: str, soup: BeautifulSoup) -> list[str]:
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        links.append(_normalize_url(urljoin(base_url, href)))
    return links


def _extract_forms(soup: BeautifulSoup, base_url: str) -> list[dict]:
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action", ""))
        inputs = [
            {"type": inp.get("type", "text"), "name": inp.get("name", "")}
            for inp in form.find_all("input")
        ]
        forms.append(
            {
                "action": action,
                "method": form.get("method", "get").upper(),
                "inputs": inputs,
                "is_https": urlparse(action).scheme == "https",
                "has_password_field": any(i["type"] == "password" for i in inputs),
            }
        )
    return forms


async def crawl(
    client: SafeHttpClient,
    start_url: str,
    max_depth: int = 2,
    max_pages: int = 50,
    same_domain_only: bool = True,
) -> CrawlResult:
    """
    BFS crawl starting from start_url. Every candidate URL is re-validated
    via validate_target() before it's requested — crawling never bypasses
    the SSRF boundary, even for links discovered mid-scan.
    """
    result = CrawlResult()
    start_url = _normalize_url(start_url)
    queue: list[tuple[str, int]] = [(start_url, 0)]
    seen: set[str] = {start_url}

    while queue and len(result.pages) < max_pages:
        url, depth = queue.pop(0)

        if same_domain_only and not is_same_domain(start_url, url):
            result.skipped_urls[url] = "different domain"
            continue

        validation = validate_target(url)
        if not validation.is_valid:
            result.skipped_urls[url] = validation.reason or "failed validation"
            logger.warning("Skipping unsafe URL %s: %s", url, validation.reason)
            continue

        try:
            response = await client.request(url, method="GET")
        except SSRFBlockedError as exc:
            result.skipped_urls[url] = str(exc)
            continue
        except Exception as exc:  # noqa: BLE001 — crawler must not die on one bad page
            logger.warning("Failed to fetch %s: %s", url, exc)
            result.skipped_urls[url] = f"request failed: {exc}"
            continue

        result.visited_urls.add(url)
        content_type = response.headers.get("content-type", "")

        page = CrawledPage(
            url=response.url,
            status_code=response.status_code,
            content_type=content_type,
            headers=dict(response.headers),
            html=response.text if "text/html" in content_type else "",
        )

        if "text/html" in content_type and response.text:
            soup = BeautifulSoup(response.text, "html.parser")
            page.forms = _extract_forms(soup, url)
            if depth < max_depth:
                page.links = _extract_links(url, soup)
                for link in page.links:
                    if link not in seen and len(seen) < max_pages * 4:
                        seen.add(link)
                        queue.append((link, depth + 1))

        result.pages.append(page)

    return result
