"""Troubleshooting diagnostic engine orchestrating rules and diagnostic checks."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pqsysguard.troubleshoot.diagnostics import (
    check_cpu_culprits,
    check_disk_hogs,
    check_dns_connectivity,
    check_failed_units,
    check_memory_culprits,
    check_port_in_use,
)
from pqsysguard.troubleshoot.log_analyzer import analyze_system_logs
from pqsysguard.troubleshoot.models import Finding, FindingSeverity, LogRule, TroubleshootReport
from pqsysguard.utils.logger import get_logger

logger = get_logger("troubleshoot.engine")


def load_rules_from_yaml(yaml_path: Path | str) -> list[LogRule]:
    """Load and validate troubleshooting log rules from a YAML file."""
    path = Path(yaml_path)
    if not path.is_file():
        logger.debug("Troubleshoot rules file not found: %s", path)
        return []

    try:
        with open(path, encoding="utf-8") as f:
            content = yaml.safe_load(f)
            if not isinstance(content, dict) or "rules" not in content:
                logger.warning("Rules YAML does not contain a 'rules' list: %s", path)
                return []

            rules: list[LogRule] = []
            for item in content["rules"]:
                try:
                    rules.append(LogRule.model_validate(item))
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    logger.warning("Failed parsing rule %s: %s", item.get("id"), exc)
            return rules
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Error reading troubleshoot rules YAML %s: %s", path, exc)
        return []


class TroubleshootEngine:
    """Diagnostic orchestrator executing checks and evaluating log rules."""

    def __init__(self, rules_file: Path | str = "config/troubleshoot_rules.yaml") -> None:
        self.rules_file = Path(rules_file)
        self.rules = load_rules_from_yaml(self.rules_file)
        self._registry: dict[str, Callable[[], list[Finding]]] = {
            "logs": self._run_logs,
            "cpu": check_cpu_culprits,
            "memory": check_memory_culprits,
            "disk": check_disk_hogs,
            "systemd": check_failed_units,
            "connectivity": check_dns_connectivity,
            "ports": check_port_in_use,
        }

    def _run_logs(self) -> list[Finding]:
        """Execute log analysis against loaded rules."""
        return analyze_system_logs(self.rules)

    @property
    def available_checks(self) -> list[str]:
        """List of individual diagnostic check names."""
        return list(self._registry.keys())

    def run_check(self, check_name: str) -> TroubleshootReport:
        """Execute a single diagnostic check by name."""
        normalized = check_name.lower().strip()
        if normalized not in self._registry:
            avail = ", ".join(self.available_checks)
            raise ValueError(f"Unknown check '{check_name}'. Available: {avail}")

        report = TroubleshootReport(total_checks=1)
        check_fn = self._registry[normalized]
        try:
            findings = check_fn()
            report.findings.extend(findings)
            if not findings:
                report.passed_checks.append(normalized)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Check '%s' raised an unexpected error: %s", normalized, exc)
            report.findings.append(
                Finding(
                    check_name=normalized,
                    severity=FindingSeverity.WARNING,
                    title=f"Check '{normalized}' Encountered an Error",
                    evidence=str(exc),
                    probable_cause="Insufficient permissions or missing system utility.",
                    recommended_fix=(
                        "Run as privileged user (sudo) or verify utility availability."
                    ),
                )
            )

        return report

    def run_all(self) -> TroubleshootReport:
        """Execute all registered diagnostic checks and log analysis."""
        report = TroubleshootReport(total_checks=len(self._registry))
        for check_name, check_fn in self._registry.items():
            try:
                findings = check_fn()
                report.findings.extend(findings)
                if not findings:
                    report.passed_checks.append(check_name)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.error("Check '%s' failed during run_all: %s", check_name, exc)
                report.findings.append(
                    Finding(
                        check_name=check_name,
                        severity=FindingSeverity.WARNING,
                        title=f"Check '{check_name}' Encountered an Error",
                        evidence=str(exc),
                        probable_cause="Insufficient permissions or missing system utility.",
                        recommended_fix=(
                            "Run as privileged user (sudo) or verify utility availability."
                        ),
                    )
                )

        return report


def display_troubleshoot_report(report: TroubleshootReport, console: Console | None = None) -> None:
    """Render a comprehensive diagnostic report to the Rich terminal."""
    out_console = console or Console()

    header_color = "red" if report.has_critical else ("yellow" if report.has_warning else "green")
    out_console.print(
        Panel.fit(
            f"[bold {header_color}]PQ-SysGuard Automated Diagnostic Report[/bold {header_color}]\n"
            f"[dim]Total Checks: {report.total_checks} | "
            f"Passed: {len(report.passed_checks)} | "
            f"Findings: {len(report.findings)}[/dim]\n"
            "[bold white]Mode: READ-ONLY AUDIT[/bold white] "
            "[dim](Recommended remediation commands are NOT automatically executed)[/dim]",
            border_style=header_color,
        )
    )

    if not report.findings:
        out_console.print(
            Panel(
                "[bold green]✔ All diagnostic checks passed with zero issues.[/bold green]",
                border_style="green",
            )
        )
        return

    for idx, finding in enumerate(report.findings, start=1):
        color = (
            "red"
            if finding.severity == FindingSeverity.CRITICAL
            else ("yellow" if finding.severity == FindingSeverity.WARNING else "cyan")
        )
        table = Table(box=None, expand=True, show_header=False)
        table.add_column("Property", style="bold dim", width=18)
        table.add_column("Value", style="white")

        table.add_row("Severity", f"[{color}][bold]{finding.severity.value}[/bold][/{color}]")
        table.add_row("Subsystem", f"[cyan]{finding.check_name}[/cyan]")
        table.add_row("Evidence", f"[dim]{finding.evidence}[/dim]")
        table.add_row("Probable Cause", finding.probable_cause)
        table.add_row(
            "Recommended Fix",
            f"[bold yellow]{finding.recommended_fix}[/bold yellow]",
        )

        out_console.print(
            Panel(
                table,
                title=f"[{color}][Finding #{idx}] {finding.title}[/{color}]",
                border_style=color,
            )
        )

    out_console.print(
        "[dim]Note: Verify findings before applying any recommended commands. "
        "PQ-SysGuard never executes remediation scripts without explicit operator consent.[/dim]"
    )
