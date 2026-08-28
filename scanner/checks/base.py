"""Common interface every security check implements."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from scanner.core.crawler import CrawledPage
from scanner.models.finding import Finding


@dataclass
class CheckContext:
    """Everything a check might need, gathered once per scan."""
    target_url: str
    pages: list[CrawledPage]
    resolved_ips: list[str] = field(default_factory=list)


class SecurityCheck(ABC):
    name: str
    description: str

    @abstractmethod
    async def run(self, context: CheckContext) -> list[Finding]:
        """Return a list of Findings (may be empty). Must never raise on bad input —
        catch and log instead, since one check failing shouldn't kill the scan."""
        raise NotImplementedError
