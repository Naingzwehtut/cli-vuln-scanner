"""HTML report export — a single self-contained, styled HTML file."""
from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path

from scanner.models.scan import ScanResult
from scanner.utils.formatting import risk_label

SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#dc2626",
    "MEDIUM": "#f59e0b",
    "LOW": "#3b82f6",
    "INFO": "#6b7280",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _finding_row(f) -> str:
    severity = f.severity if isinstance(f.severity, str) else f.severity.value
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    return f"""
    <div class="finding" style="border-left: 4px solid {color};">
      <div class="finding-header">
        <span class="badge" style="background:{color};">{escape(severity)}</span>
        <span class="finding-title">{escape(f.title)}</span>
      </div>
      <table class="finding-table">
        <tr><td>URL</td><td>{escape(f.url)}</td></tr>
        <tr><td>Confidence</td><td>{escape(f.confidence if isinstance(f.confidence, str) else f.confidence.value)}</td></tr>
        <tr><td>Status</td><td>{escape(f.status if isinstance(f.status, str) else f.status.value)}</td></tr>
        <tr><td>OWASP</td><td>{escape(f.owasp or '-')}</td></tr>
        <tr><td>CWE</td><td>{escape(f.cwe or '-')}</td></tr>
        <tr><td>Description</td><td>{escape(f.description)}</td></tr>
        <tr><td>Evidence</td><td><code>{escape(f.evidence)}</code></td></tr>
        <tr><td>Recommendation</td><td>{escape(f.recommendation)}</td></tr>
        <tr><td>Detection Method</td><td>{escape(f.detection_method)}</td></tr>
      </table>
    </div>
    """


def generate_html_report(result: ScanResult, output_path: Path) -> Path:
    counts = Counter(f.severity if isinstance(f.severity, str) else f.severity.value for f in result.findings)
    score = result.risk_score
    label = risk_label(score)

    severity_summary = "".join(
        f'<div class="stat"><div class="stat-value" style="color:{SEVERITY_COLORS[s]}">{counts.get(s, 0)}</div>'
        f'<div class="stat-label">{s}</div></div>'
        for s in SEVERITY_ORDER
    )

    findings_html = "".join(
        _finding_row(f)
        for f in sorted(
            result.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity if isinstance(f.severity, str) else f.severity.value),
        )
    ) or "<p>No findings.</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Scan Report - {escape(result.target_url)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; }}
  .summary {{ background:#1e293b; border-radius:8px; padding:1.5rem; margin-bottom:1.5rem; }}
  .risk-score {{ font-size:3rem; font-weight:bold; }}
  .risk-label {{ font-size:1rem; color:#94a3b8; }}
  .stats {{ display:flex; gap:1rem; margin-top:1rem; flex-wrap:wrap; }}
  .stat {{ background:#0f172a; padding:0.75rem 1.25rem; border-radius:6px; text-align:center; min-width:80px; }}
  .stat-value {{ font-size:1.5rem; font-weight:bold; }}
  .stat-label {{ font-size:0.75rem; color:#94a3b8; }}
  .finding {{ background:#1e293b; border-radius:6px; padding:1rem; margin-bottom:1rem; }}
  .finding-header {{ display:flex; align-items:center; gap:0.75rem; margin-bottom:0.75rem; }}
  .badge {{ color:white; font-size:0.7rem; font-weight:bold; padding:0.2rem 0.6rem; border-radius:4px; }}
  .finding-title {{ font-weight:600; }}
  .finding-table {{ width:100%; border-collapse:collapse; font-size:0.85rem; }}
  .finding-table td {{ padding:0.35rem 0.5rem; vertical-align:top; border-top:1px solid #334155; }}
  .finding-table td:first-child {{ width:150px; color:#94a3b8; }}
  code {{ background:#0f172a; padding:2px 4px; border-radius:3px; }}
  .notice {{ background:#422006; border:1px solid #92400e; border-radius:6px; padding:0.75rem 1rem; font-size:0.85rem; margin-bottom:1.5rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>Vulnerability Scan Report</h1>
  <div class="notice">Generated for authorized security testing of {escape(result.target_url)} only.</div>

  <div class="summary">
    <div class="risk-score">{score}/100</div>
    <div class="risk-label">Risk Level: {label}</div>
    <div class="stats">{severity_summary}</div>
    <p style="margin-top:1rem; color:#94a3b8; font-size:0.85rem;">
      Target: {escape(result.target_url)} &middot;
      Status: {escape(result.status if isinstance(result.status, str) else result.status.value)} &middot;
      Pages scanned: {result.pages_scanned} &middot;
      Requests made: {result.requests_made} &middot;
      Duration: {result.duration_seconds() or 'N/A'}s
    </p>
  </div>

  <h2>Findings ({len(result.findings)})</h2>
  {findings_html}
</div>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")
    return output_path
