"""Command-line interface for the vulnerability scanner."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from scanner.core.scanner import run_scan
from scanner.core.target_validator import validate_target
from scanner.models.scan import ScanConfig, ScanProfile, ScanResult
from scanner.reports.csv_report import generate_csv_report
from scanner.reports.html_report import generate_html_report
from scanner.reports.json_report import generate_json_report
from scanner.storage.repository import get_scan, list_scans, save_scan
from scanner.utils.formatting import risk_label
from scanner.utils.logging import setup_logging

app = typer.Typer(
    name="scanner",
    help="Web Application Vulnerability Scanner (authorized security testing only).",
    add_completion=False,
)
console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold white on dark_red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
    "INFO": "dim",
}

BANNER = """[bold cyan]╔════════════════════════════════════════════╗
║       WEB VULNERABILITY SCANNER v0.1        ║
╚════════════════════════════════════════════╝[/bold cyan]
[dim]Authorized security testing only.[/dim]
"""


def _print_banner() -> None:
    console.print(BANNER)


def _print_findings_table(result: ScanResult) -> None:
    if not result.findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(title=f"Findings for {result.target_url}", show_lines=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Finding")
    table.add_column("URL", overflow="fold")
    table.add_column("Status", no_wrap=True)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for finding in sorted(
        result.findings,
        key=lambda f: severity_order.index(f.severity if isinstance(f.severity, str) else f.severity.value),
    ):
        severity = finding.severity if isinstance(finding.severity, str) else finding.severity.value
        status = finding.status if isinstance(finding.status, str) else finding.status.value
        style = SEVERITY_STYLES.get(severity, "")
        table.add_row(f"[{style}]{severity}[/{style}]", finding.title, finding.url, status)

    console.print(table)


def _print_summary(result: ScanResult) -> None:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = {s: 0 for s in severity_order}
    for f in result.findings:
        sev = f.severity if isinstance(f.severity, str) else f.severity.value
        counts[sev] += 1

    summary_lines = "\n".join(
        f"[{SEVERITY_STYLES[s]}]{s:<10}[/{SEVERITY_STYLES[s]}] {counts[s]}" for s in severity_order
    )
    status = result.status if isinstance(result.status, str) else result.status.value
    panel_text = (
        f"Target: {result.target_url}\n"
        f"Status: {status}\n"
        f"Risk Score: {result.risk_score}/100 ({risk_label(result.risk_score)})\n"
        f"Pages scanned: {result.pages_scanned}  |  Requests: {result.requests_made}\n\n"
        f"{summary_lines}"
    )
    console.print(Panel(panel_text, title="Scan Summary", border_style="cyan"))


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan (must be a site you own or are authorized to test)."),
    profile: ScanProfile = typer.Option(ScanProfile.STANDARD, "--profile", "-p", help="Scan profile."),
    depth: int = typer.Option(2, "--depth", "-d", help="Maximum crawl depth."),
    max_pages: int = typer.Option(50, "--max-pages", help="Maximum pages to crawl."),
    timeout: float = typer.Option(10.0, "--timeout", help="Per-request timeout in seconds."),
    rate_limit: float = typer.Option(5.0, "--rate-limit", help="Max requests per second."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save scan result as JSON to this path."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    """Run a security scan against TARGET. Only scan systems you own or are authorized to test."""
    setup_logging(verbose)
    _print_banner()

    console.print(
        Panel(
            "[yellow]This scanner is intended only for websites you own or have explicit "
            "permission to test.[/yellow]",
            border_style="yellow",
        )
    )

    validation = validate_target(target)
    if not validation.is_valid:
        console.print(f"[bold red]Target rejected:[/bold red] {validation.reason}")
        raise typer.Exit(code=1)

    config = ScanConfig(
        target_url=target,
        profile=profile,
        max_depth=depth,
        max_pages=max_pages,
        timeout_seconds=timeout,
        rate_limit_rps=rate_limit,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.fields[stats]}"),
        console=console,
    ) as progress:
        task_id = progress.add_task("Initializing...", total=None, stats="")

        def on_progress(result: ScanResult, stage: str) -> None:
            stats = f"Pages: {result.pages_scanned}  Requests: {result.requests_made}  Findings: {len(result.findings)}"
            progress.update(task_id, description=f"[cyan]{stage.capitalize()}...", stats=stats)

        result = asyncio.run(run_scan(config, on_progress=on_progress))
        progress.update(task_id, description="[green]Done", stats=f"Findings: {len(result.findings)}")

    if result.status == "FAILED" or (hasattr(result.status, "value") and result.status.value == "FAILED"):
        console.print(f"[bold red]Scan failed:[/bold red] {result.error}")
        raise typer.Exit(code=1)

    console.print()
    _print_summary(result)
    console.print()
    _print_findings_table(result)

    save_scan(result)
    console.print(f"\n[dim]Scan saved to history (id: {result.id}). Run 'scanner history' to view.[/dim]")

    if output:
        generate_json_report(result, output)
        console.print(f"[green]Results saved to {output}[/green]")


@app.command()
def crawl(
    target: str = typer.Argument(..., help="Target URL to crawl."),
    depth: int = typer.Option(2, "--depth", "-d"),
    max_pages: int = typer.Option(50, "--max-pages"),
) -> None:
    """Crawl TARGET and list discovered pages, without running security checks."""
    from scanner.core.crawler import crawl as crawl_fn
    from scanner.core.http_client import SafeHttpClient

    validation = validate_target(target)
    if not validation.is_valid:
        console.print(f"[bold red]Target rejected:[/bold red] {validation.reason}")
        raise typer.Exit(code=1)

    async def _run():
        client = SafeHttpClient()
        try:
            return await crawl_fn(client, target, max_depth=depth, max_pages=max_pages)
        finally:
            await client.close()

    result = asyncio.run(_run())
    table = Table(title=f"Crawl results for {target}")
    table.add_column("URL")
    table.add_column("Status")
    table.add_column("Content-Type")
    for page in result.pages:
        table.add_row(page.url, str(page.status_code), page.content_type or "-")
    console.print(table)
    if result.skipped_urls:
        console.print(f"[dim]{len(result.skipped_urls)} URL(s) skipped (out of scope or blocked).[/dim]")


@app.command()
def check(target: str = typer.Argument(..., help="Target URL for a quick headers-only check.")) -> None:
    """Run a quick, headers-only check against TARGET (equivalent to --profile quick)."""
    validation = validate_target(target)
    if not validation.is_valid:
        console.print(f"[bold red]Target rejected:[/bold red] {validation.reason}")
        raise typer.Exit(code=1)

    config = ScanConfig(target_url=target, profile=ScanProfile.QUICK, max_depth=0, max_pages=1)
    result = asyncio.run(run_scan(config))
    _print_summary(result)
    _print_findings_table(result)
    save_scan(result)


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID (see 'scanner history')."),
    fmt: str = typer.Option("html", "--format", "-f", help="Output format: html, json, or csv."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path."),
) -> None:
    """Generate a report file for a previously run scan."""
    result = get_scan(scan_id)
    if result is None:
        console.print(f"[bold red]No scan found with id {scan_id}[/bold red]")
        raise typer.Exit(code=1)

    default_dir = Path("reports")
    default_dir.mkdir(exist_ok=True)

    if fmt == "html":
        path = output or default_dir / f"{scan_id}.html"
        generate_html_report(result, path)
    elif fmt == "json":
        path = output or default_dir / f"{scan_id}.json"
        generate_json_report(result, path)
    elif fmt == "csv":
        path = output or default_dir / f"{scan_id}.csv"
        generate_csv_report(result, path)
    else:
        console.print(f"[bold red]Unknown format: {fmt}[/bold red] (use html, json, or csv)")
        raise typer.Exit(code=1)

    console.print(f"[green]Report written to {path}[/green]")


@app.command()
def history(limit: int = typer.Option(20, "--limit", "-n")) -> None:
    """Show previously run scans."""
    records = list_scans(limit)
    if not records:
        console.print("[dim]No scans found yet. Run 'scanner scan <url>' first.[/dim]")
        return

    table = Table(title="Previous Scans")
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Date")
    table.add_column("Status")
    table.add_column("Findings")
    table.add_column("Risk Score")

    for r in records:
        finding_count = len(r.findings)
        date_str = r.started_at.strftime("%Y-%m-%d %H:%M") if r.started_at else "-"
        table.add_row(r.id[:8], r.target_url, date_str, r.status, str(finding_count), f"{r.risk_score}/100")

    console.print(table)


@app.command()
def version() -> None:
    """Show scanner version."""
    console.print("Web Vulnerability Scanner v0.1.0")


if __name__ == "__main__":
    app()
