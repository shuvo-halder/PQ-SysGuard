"""System log analyzer for syslog, auth.log, and journalctl streams."""

from __future__ import annotations

import re
import shutil
import subprocess
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path

from pqsysguard.troubleshoot.models import Finding, LogRule
from pqsysguard.utils.logger import get_logger

logger = get_logger("troubleshoot.log_analyzer")

# Standard Linux log paths
DEFAULT_LOG_PATHS: dict[str, list[Path]] = {
    "syslog": [
        Path("/var/log/syslog"),
        Path("/var/log/messages"),
    ],
    "auth.log": [
        Path("/var/log/auth.log"),
        Path("/var/log/secure"),
    ],
}


def read_log_file(file_path: Path, max_lines: int = 1000) -> list[str]:
    """Safely read trailing lines of a log file, handling missing files and permissions."""
    if not file_path.is_file():
        logger.debug("Log file does not exist: %s", file_path)
        return []

    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            return lines[-max_lines:] if len(lines) > max_lines else lines
    except (PermissionError, OSError) as exc:
        logger.warning("Unable to read log file %s: %s", file_path, exc)
        return []


def query_journalctl(max_lines: int = 200, priority: str = "warning..emerg") -> list[str]:
    """Execute journalctl safely to retrieve recent system and service logs."""
    journalctl_bin = shutil.which("journalctl")
    if not journalctl_bin:
        logger.debug("journalctl binary not found on this system.")
        return []

    cmd = [
        journalctl_bin,
        "-n",
        str(max_lines),
        "--no-pager",
        "-p",
        priority,
    ]

    try:
        # Parameter-safe execution (Rule 8)
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.splitlines()
        return []
    except (subprocess.SubprocessError, OSError) as exc:
        logger.warning("Error querying journalctl: %s", exc)
        return []


def analyze_log_content(
    lines: Sequence[str],
    rules: Sequence[LogRule],
    check_name: str = "log_analysis",
) -> list[Finding]:
    """Scan a sequence of log lines against compiled LogRules and generate findings."""
    findings: list[Finding] = []
    matches_by_rule: dict[str, list[str]] = defaultdict(list)

    for rule in rules:
        try:
            regex = re.compile(rule.pattern, re.IGNORECASE)
        except re.error as exc:
            logger.error("Invalid regex in rule %s: %s", rule.id, exc)
            continue

        for line in lines:
            if regex.search(line):
                cleaned_line = line.strip()
                if cleaned_line:
                    matches_by_rule[rule.id].append(cleaned_line)

        matched_lines = matches_by_rule.get(rule.id, [])
        if matched_lines:
            count = len(matched_lines)
            sample_evidence = "\n".join(matched_lines[-5:])  # Show up to 5 most recent
            evidence_summary = f"Detected {count} occurrence(s). Recent excerpt:\n{sample_evidence}"

            findings.append(
                Finding(
                    check_name=check_name,
                    severity=rule.severity,
                    title=f"[{rule.id}] {rule.name}",
                    evidence=evidence_summary,
                    probable_cause=rule.probable_cause,
                    recommended_fix=rule.recommended_fix,
                )
            )

    return findings


def analyze_system_logs(
    rules: Sequence[LogRule],
    custom_sources: Mapping[str, Sequence[str]] | None = None,
    max_lines: int = 500,
) -> list[Finding]:
    """Analyze all standard system log files and journalctl against rules."""
    findings: list[Finding] = []

    # If custom in-memory sources are provided (e.g. for testing)
    if custom_sources:
        for source_name, lines in custom_sources.items():
            matching_rules = [r for r in rules if r.source.lower() == source_name.lower()]
            if matching_rules:
                findings.extend(
                    analyze_log_content(
                        lines, matching_rules, check_name=f"log_analysis.{source_name}"
                    )
                )
        return findings

    # 1. Syslog / Messages
    syslog_rules = [r for r in rules if r.source.lower() == "syslog"]
    if syslog_rules:
        syslog_lines: list[str] = []
        for path in DEFAULT_LOG_PATHS["syslog"]:
            if path.is_file():
                syslog_lines = read_log_file(path, max_lines=max_lines)
                break
        if syslog_lines:
            findings.extend(
                analyze_log_content(syslog_lines, syslog_rules, check_name="log_analysis.syslog")
            )

    # 2. Auth log / Secure
    auth_rules = [r for r in rules if r.source.lower() == "auth.log"]
    if auth_rules:
        auth_lines: list[str] = []
        for path in DEFAULT_LOG_PATHS["auth.log"]:
            if path.is_file():
                auth_lines = read_log_file(path, max_lines=max_lines)
                break
        if auth_lines:
            findings.extend(
                analyze_log_content(auth_lines, auth_rules, check_name="log_analysis.auth")
            )

    # 3. Journalctl
    journal_rules = [r for r in rules if r.source.lower() == "journalctl"]
    if journal_rules:
        journal_lines = query_journalctl(max_lines=max_lines)
        if journal_lines:
            findings.extend(
                analyze_log_content(
                    journal_lines, journal_rules, check_name="log_analysis.journalctl"
                )
            )

    return findings
