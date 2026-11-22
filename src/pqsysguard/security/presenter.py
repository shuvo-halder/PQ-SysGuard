"""Security audit report visualizer for terminal, JSON, and HTML formats."""

from __future__ import annotations

import html
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pqsysguard.security.models import AuditSeverity, AuditStatus, SecurityReport


def get_grade_color(grade: str) -> str:
    """Return color associated with letter grade."""
    if grade in ("A", "B"):
        return "green"
    if grade == "C":
        return "yellow"
    return "red"


def display_terminal_report(report: SecurityReport, console: Console | None = None) -> None:
    """Render security audit results to Rich console with score and CIS controls."""
    out_console = console or Console()
    grade_color = get_grade_color(report.grade)

    # 1. Score Summary Banner
    out_console.print(
        Panel.fit(
            f"[bold {grade_color}]PQ-SysGuard Security Hardening Audit[/bold {grade_color}]\n"
            f"[bold]Security Score: [{grade_color}]{report.score} / 100[/{grade_color}] "
            f"(Grade: [{grade_color}]{report.grade}[/{grade_color}])[/bold]\n"
            f"[dim]Total Controls: {report.total_checks} | "
            f"[green]Passed: {report.passed_count}[/green] | "
            f"[yellow]Warnings: {report.warn_count}[/yellow] | "
            f"[red]Failed: {report.failed_count}[/red][/dim]\n"
            "[bold white]Mode: READ-ONLY AUDIT[/bold white] "
            "[dim](No system configuration changes applied)[/dim]",
            border_style=grade_color,
        )
    )

    # 2. CIS Control Overview Table
    table = Table(title="CIS Benchmark Audit Controls Summary", expand=True)
    table.add_column("Check ID", style="cyan", width=12)
    table.add_column("CIS Control", style="magenta", width=14)
    table.add_column("Title / Description", style="white")
    table.add_column("Status", justify="center", width=10)
    table.add_column("Severity", justify="center", width=10)

    for f in report.findings:
        cis_id = f.cis_control.id if f.cis_control else "N/A"
        if f.status == AuditStatus.PASS:
            status_str = "[bold green]PASS[/bold green]"
        elif f.status == AuditStatus.WARN:
            status_str = "[bold yellow]WARN[/bold yellow]"
        else:
            status_str = "[bold red]FAIL[/bold red]"

        sev_color = "red" if f.severity in (AuditSeverity.HIGH, AuditSeverity.CRITICAL) else (
            "yellow" if f.severity == AuditSeverity.MEDIUM else "cyan"
        )
        sev_str = f"[{sev_color}]{f.severity.value}[/{sev_color}]"

        table.add_row(
            f.check_id,
            cis_id,
            f.title,
            status_str,
            sev_str,
        )

    out_console.print(table)

    # 3. Actionable Remediation Details (for Non-PASS findings)
    issues = [f for f in report.findings if f.status != AuditStatus.PASS]
    if issues:
        out_console.print("\n[bold underline]Remediation Recommendations:[/bold underline]")
        for idx, issue in enumerate(issues, start=1):
            cis_tag = f"[{issue.cis_control.id}] " if issue.cis_control else ""
            status_color = "red" if issue.status == AuditStatus.FAIL else "yellow"
            detail_table = Table(box=None, expand=True, show_header=False)
            detail_table.add_column("Key", style="bold dim", width=16)
            detail_table.add_column("Val", style="white")

            detail_table.add_row("Status", f"[{status_color}]{issue.status.value}[/{status_color}]")
            detail_table.add_row("Evidence", f"[dim]{issue.evidence}[/dim]")
            detail_table.add_row("Remediation", f"[bold yellow]{issue.remediation}[/bold yellow]")

            out_console.print(
                Panel(
                    detail_table,
                    title=f"[{status_color}][#{idx}] {cis_tag}{issue.title}[/{status_color}]",
                    border_style=status_color,
                )
            )


def export_json_report(report: SecurityReport) -> str:
    """Serialize the complete security audit report to JSON format."""
    return json.dumps(report.model_dump(mode="json"), indent=2)


def export_html_report(report: SecurityReport) -> str:
    """Generate a clean, standalone, responsive HTML report without external dependencies."""
    grade_color = "#10b981" if report.grade in ("A", "B") else (
        "#f59e0b" if report.grade == "C" else "#ef4444"
    )

    rows_html: list[str] = []
    for f in report.findings:
        cis_id = html.escape(f.cis_control.id) if f.cis_control else "N/A"
        cis_title = html.escape(f.cis_control.title) if f.cis_control else ""

        badge_class = "badge-pass" if f.status == AuditStatus.PASS else (
            "badge-warn" if f.status == AuditStatus.WARN else "badge-fail"
        )
        sev_class = f"sev-{f.severity.value.lower()}"

        evidence_escaped = html.escape(f.evidence).replace("\n", "<br>")
        remediation_escaped = html.escape(f.remediation)

        rows_html.append(
            f"""
            <tr>
              <td><code>{html.escape(f.check_id)}</code></td>
              <td><span class="cis-tag" title="{cis_title}">{cis_id}</span></td>
              <td><strong>{html.escape(f.title)}</strong><br><small class="text-muted">{evidence_escaped}</small></td>
              <td><span class="badge {badge_class}">{f.status.value}</span></td>
              <td><span class="badge {sev_class}">{f.severity.value}</span></td>
              <td><code>{remediation_escaped}</code></td>
            </tr>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PQ-SysGuard Security Hardening Audit Report</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --border: #334155;
      --pass: #10b981;
      --warn: #f59e0b;
      --fail: #ef4444;
      --primary: #38bdf8;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 2rem;
      line-height: 1.5;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    .header-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }}
    .score-circle {{
      width: 110px;
      height: 110px;
      border-radius: 50%;
      border: 6px solid {grade_color};
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      font-weight: bold;
    }}
    .score-number {{ font-size: 2rem; color: {grade_color}; }}
    .score-grade {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }}
    .stats {{ display: flex; gap: 1.5rem; margin-top: 1rem; }}
    .stat-item {{ background: rgba(255,255,255,0.05); padding: 0.5rem 1rem; border-radius: 6px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid var(--border);
    }}
    th, td {{
      padding: 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{ background: rgba(255, 255, 255, 0.03); color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
    }}
    .badge-pass {{ background: rgba(16, 185, 129, 0.2); color: var(--pass); border: 1px solid var(--pass); }}
    .badge-warn {{ background: rgba(245, 158, 11, 0.2); color: var(--warn); border: 1px solid var(--warn); }}
    .badge-fail {{ background: rgba(239, 68, 68, 0.2); color: var(--fail); border: 1px solid var(--fail); }}
    .sev-critical {{ color: #f87171; }}
    .sev-high {{ color: #fb923c; }}
    .sev-medium {{ color: #fbbf24; }}
    .sev-low {{ color: #38bdf8; }}
    .sev-info {{ color: #94a3b8; }}
    .cis-tag {{ background: rgba(56, 189, 248, 0.15); color: var(--primary); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.75rem; font-family: monospace; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; color: #e2e8f0; }}
    .text-muted {{ color: var(--text-muted); }}
    footer {{ margin-top: 2rem; text-align: center; color: var(--text-muted); font-size: 0.85rem; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-card">
      <div>
        <h1 style="margin: 0 0 0.5rem 0;">PQ-SysGuard Security Audit</h1>
        <p class="text-muted" style="margin: 0;">CIS Benchmark Compliance & Hardening Verification | Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <div class="stats">
          <div class="stat-item"><strong>{report.total_checks}</strong> Controls</div>
          <div class="stat-item" style="color: var(--pass)"><strong>{report.passed_count}</strong> Passed</div>
          <div class="stat-item" style="color: var(--warn)"><strong>{report.warn_count}</strong> Warnings</div>
          <div class="stat-item" style="color: var(--fail)"><strong>{report.failed_count}</strong> Failed</div>
        </div>
      </div>
      <div class="score-circle">
        <span class="score-number">{report.score}</span>
        <span class="score-grade">Grade {report.grade}</span>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Check ID</th>
          <th>CIS Benchmark</th>
          <th>Control & Evidence</th>
          <th>Status</th>
          <th>Severity</th>
          <th>Recommended Fix</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>

    <footer>
      <p>PQ-SysGuard Security Module &bull; Strictly Read-Only Audit &bull; NIST Post-Quantum Zero-Trust Toolkit</p>
    </footer>
  </div>
</body>
</html>
"""
