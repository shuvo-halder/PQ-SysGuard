"""Unit and integration tests for automated troubleshooting module."""

import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

from pqsysguard.cli import app
from pqsysguard.troubleshoot.diagnostics import (
    check_cpu_culprits,
    check_disk_hogs,
    check_dns_connectivity,
    check_failed_units,
    check_memory_culprits,
    check_port_in_use,
    scan_directory_space_hogs,
)
from pqsysguard.troubleshoot.engine import (
    TroubleshootEngine,
    display_troubleshoot_report,
    load_rules_from_yaml,
)
from pqsysguard.troubleshoot.log_analyzer import (
    analyze_log_content,
    analyze_system_logs,
    query_journalctl,
    read_log_file,
)
from pqsysguard.troubleshoot.models import (
    Finding,
    FindingSeverity,
    LogRule,
    TroubleshootReport,
)

SAMPLE_SYSLOG_OOM = """
Nov 20 10:14:01 srv01 CRON[1234]: (root) CMD (/usr/local/bin/backup.sh)
Nov 20 10:15:22 srv01 kernel: [ 4512.123] Out of memory: Kill process 9999 (java) score 850
Nov 20 10:15:22 srv01 kernel: [ 4512.124] Killed process 9999 (java) anon-rss:7200kB
"""

SAMPLE_AUTH_LOG = """
Nov 20 11:00:01 srv01 sshd[2222]: Failed password for root from 192.168.1.100 port 45678 ssh2
Nov 20 11:00:03 srv01 sshd[2225]: Failed password for root from 192.168.1.100 port 45680 ssh2
Nov 20 11:00:05 srv01 sshd[2228]: Failed password for invalid user admin from 10.0.0.1 ssh2
"""

SAMPLE_JOURNALCTL_CRASH = """
-- Logs begin at Wed 2026-11-18 10:00:00 UTC. --
Nov 20 12:00:10 srv01 systemd[1]: nginx.service: Main process exited, code=exited, status=1/FAILURE
Nov 20 12:00:10 srv01 systemd[1]: nginx.service: Failed with result 'exit-code'.
Nov 20 12:00:15 srv01 systemd[1]: nginx.service: Scheduled restart job, restart counter is at 5.
"""


# ---------------------------------------------------------------------------
# Rule Loading & Model Tests
# ---------------------------------------------------------------------------
def test_load_rules_valid(tmp_path: Path) -> None:
    """Test loading valid LogRules from YAML file."""
    yaml_file = tmp_path / "rules.yaml"
    content = """
rules:
  - id: "TEST-001"
    name: "Test Failure Rule"
    pattern: "test failure detected"
    severity: "CRITICAL"
    source: "syslog"
    probable_cause: "Test cause"
    recommended_fix: "Test fix command"
"""
    yaml_file.write_text(content, encoding="utf-8")
    rules = load_rules_from_yaml(yaml_file)
    assert len(rules) == 1
    assert rules[0].id == "TEST-001"
    assert rules[0].severity == FindingSeverity.CRITICAL


def test_load_rules_missing_or_invalid() -> None:
    """Test missing file and invalid format handling."""
    assert load_rules_from_yaml(Path("/nonexistent/rules.yaml")) == []


# ---------------------------------------------------------------------------
# Log Analyzer Tests
# ---------------------------------------------------------------------------
def test_read_log_file(tmp_path: Path) -> None:
    """Test reading lines from a log file safely."""
    log_file = tmp_path / "syslog.txt"
    log_file.write_text("line 1\nline 2\nline 3\n", encoding="utf-8")

    lines = read_log_file(log_file, max_lines=2)
    assert len(lines) == 2
    assert "line 3" in lines[1]

    # Non-existent file
    assert read_log_file(tmp_path / "not_found.log") == []


def test_analyze_log_content_oom_detection() -> None:
    """Test detecting OOM killer in syslog lines."""
    rule = LogRule(
        id="OOM-001",
        name="Out of Memory Killer",
        pattern=r"(?:Out of memory: Kill process|Killed process \d+)",
        severity=FindingSeverity.CRITICAL,
        source="syslog",
        probable_cause="Exhausted RAM",
        recommended_fix="Tune memory limits",
    )
    lines = SAMPLE_SYSLOG_OOM.strip().splitlines()
    findings = analyze_log_content(lines, [rule])

    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert "OOM-001" in findings[0].title
    assert "Detected 2 occurrence(s)" in findings[0].evidence


def test_analyze_system_logs_custom_sources() -> None:
    """Test analyzing multiple sources in-memory."""
    rules = [
        LogRule(
            id="AUTH-001",
            name="SSH Failure",
            pattern=r"Failed password for",
            severity=FindingSeverity.WARNING,
            source="auth.log",
            probable_cause="Brute force",
            recommended_fix="fail2ban",
        ),
        LogRule(
            id="SVC-001",
            name="Crash Loop",
            pattern=r"Failed with result",
            severity=FindingSeverity.WARNING,
            source="journalctl",
            probable_cause="Config error",
            recommended_fix="journalctl -u",
        ),
    ]

    custom_sources = {
        "auth.log": SAMPLE_AUTH_LOG.strip().splitlines(),
        "journalctl": SAMPLE_JOURNALCTL_CRASH.strip().splitlines(),
    }

    findings = analyze_system_logs(rules, custom_sources=custom_sources)
    assert len(findings) == 2
    rule_ids = [f.title for f in findings]
    assert any("AUTH-001" in title for title in rule_ids)
    assert any("SVC-001" in title for title in rule_ids)


@patch("shutil.which", return_value="/bin/journalctl")
@patch("subprocess.run")
def test_query_journalctl_success(mock_run: MagicMock, mock_which: MagicMock) -> None:
    """Test query_journalctl safe subprocess execution."""
    mock_run.return_value = subprocess.CompletedProcess(
        args=["journalctl"],
        returncode=0,
        stdout="line 1\nline 2\n",
        stderr="",
    )
    lines = query_journalctl(max_lines=10)
    assert len(lines) == 2
    assert lines[0] == "line 1"


# ---------------------------------------------------------------------------
# Diagnostics Checks Tests
# ---------------------------------------------------------------------------
@patch("psutil.cpu_percent", return_value=92.0)
@patch("psutil.process_iter")
def test_check_cpu_culprits_high(mock_proc_iter: MagicMock, mock_cpu: MagicMock) -> None:
    """Test CPU culprit detection when CPU is above threshold."""
    proc = MagicMock()
    proc.info = {"pid": 555, "name": "stress", "username": "root", "cpu_percent": 91.5}
    mock_proc_iter.return_value = [proc]

    findings = check_cpu_culprits(threshold=85.0)
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert "stress" in findings[0].evidence
    assert "kill -15 555" in findings[0].recommended_fix


@patch("psutil.cpu_percent", return_value=12.0)
@patch("psutil.process_iter", return_value=[])
def test_check_cpu_culprits_healthy(mock_proc_iter: MagicMock, mock_cpu: MagicMock) -> None:
    """Test CPU check returns empty when healthy."""
    assert check_cpu_culprits(threshold=85.0) == []


@patch("psutil.virtual_memory")
@patch("psutil.process_iter")
def test_check_memory_culprits_high(mock_proc_iter: MagicMock, mock_vm: MagicMock) -> None:
    """Test memory culprit detection when RAM is above threshold."""
    mock_vm.return_value = SimpleNamespace(percent=91.0, used=15000000000, total=16000000000)
    proc = MagicMock()
    proc.info = {
        "pid": 777,
        "name": "memleak",
        "username": "app",
        "memory_percent": 65.0,
        "memory_info": SimpleNamespace(rss=10000000000),
    }
    mock_proc_iter.return_value = [proc]

    findings = check_memory_culprits(threshold=85.0)
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert "memleak" in findings[0].evidence
    assert "kill -15 777" in findings[0].recommended_fix


@patch("psutil.disk_partitions")
@patch("psutil.disk_usage")
def test_check_disk_hogs_high(
    mock_usage: MagicMock, mock_partitions: MagicMock, tmp_path: Path
) -> None:
    """Test disk space hog detection when filesystem is full."""
    mock_partitions.return_value = [
        SimpleNamespace(device="/dev/sda1", mountpoint=str(tmp_path), fstype="ext4", opts="rw")
    ]
    mock_usage.return_value = SimpleNamespace(percent=94.0, used=94000000000, total=100000000000)

    findings = check_disk_hogs(threshold=85.0)
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert "94.0%" in findings[0].evidence


def test_scan_directory_space_hogs(tmp_path: Path) -> None:
    """Test directory size scanning helper."""
    f1 = tmp_path / "big_file.log"
    f1.write_bytes(b"0" * 1024 * 50)
    f2 = tmp_path / "small_file.log"
    f2.write_bytes(b"0" * 1024)

    hogs = scan_directory_space_hogs(tmp_path, max_depth=0, top_n=2)
    assert len(hogs) == 2
    assert hogs[0][0] == str(f1)
    assert hogs[0][1] == 1024 * 50


@patch("shutil.which", return_value="/bin/systemctl")
@patch("subprocess.run")
def test_check_failed_units_found(mock_run: MagicMock, mock_which: MagicMock) -> None:
    """Test detection of failed systemd units."""
    mock_run.return_value = subprocess.CompletedProcess(
        args=["systemctl"],
        returncode=0,
        stdout="nginx.service loaded failed failed A high performance web server\n",
        stderr="",
    )

    findings = check_failed_units()
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert "nginx.service" in findings[0].evidence


@patch("shutil.which", return_value=None)
def test_check_failed_units_missing_systemctl(mock_which: MagicMock) -> None:
    """Test graceful handling when systemctl is missing."""
    assert check_failed_units() == []


@patch("socket.gethostbyname", side_effect=socket.gaierror("Name or service not known"))
def test_check_dns_failure(mock_dns: MagicMock) -> None:
    """Test DNS failure detection."""
    findings = check_dns_connectivity(target_host="invalid.local.test")
    dns_findings = [f for f in findings if f.check_name == "dns_connectivity"]
    assert len(dns_findings) == 1
    assert dns_findings[0].severity == FindingSeverity.CRITICAL


@patch("socket.gethostbyname", return_value="8.8.8.8")
@patch("socket.create_connection", side_effect=OSError("Connection refused"))
def test_check_network_failure(mock_conn: MagicMock, mock_dns: MagicMock) -> None:
    """Test network outbound connectivity failure detection."""
    findings = check_dns_connectivity()
    net_findings = [f for f in findings if f.check_name == "network_connectivity"]
    assert len(net_findings) == 1
    assert net_findings[0].severity == FindingSeverity.CRITICAL


@patch("psutil.net_connections")
@patch("psutil.Process")
def test_check_port_in_use_active(mock_proc: MagicMock, mock_conns: MagicMock) -> None:
    """Test active port detection."""
    conn = SimpleNamespace(
        status="LISTEN",
        laddr=SimpleNamespace(ip="127.0.0.1", port=80),
        pid=1234,
    )
    mock_conns.return_value = [conn]
    proc_inst = MagicMock()
    proc_inst.name.return_value = "httpd"
    mock_proc.return_value = proc_inst

    findings = check_port_in_use(target_ports=[80])
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.INFO
    assert "Port 80" in findings[0].evidence


# ---------------------------------------------------------------------------
# Engine & Presenter Tests
# ---------------------------------------------------------------------------
def test_troubleshoot_engine_run_all() -> None:
    """Test executing all diagnostic checks via TroubleshootEngine."""
    engine = TroubleshootEngine(rules_file="config/troubleshoot_rules.yaml")
    report = engine.run_all()
    assert report.total_checks > 0
    assert isinstance(report.findings, list)


def test_troubleshoot_engine_run_check_valid() -> None:
    """Test running individual check via engine."""
    engine = TroubleshootEngine(rules_file="config/troubleshoot_rules.yaml")
    report = engine.run_check("cpu")
    assert report.total_checks == 1


def test_troubleshoot_engine_run_check_invalid() -> None:
    """Test running invalid check name raises ValueError."""
    engine = TroubleshootEngine(rules_file="config/troubleshoot_rules.yaml")
    with pytest.raises(ValueError, match="Unknown check"):
        engine.run_check("non_existent_check")


def test_display_troubleshoot_report() -> None:
    """Test rendering report to Rich console."""
    report = TroubleshootReport(
        total_checks=2,
        passed_checks=["connectivity"],
        findings=[
            Finding(
                check_name="cpu",
                severity=FindingSeverity.CRITICAL,
                title="Critical CPU Overload",
                evidence="PID 100 consuming 99% CPU",
                probable_cause="Runaway worker",
                recommended_fix="kill -15 100",
            )
        ],
    )
    mock_console = MagicMock(spec=Console)
    display_troubleshoot_report(report, console=mock_console)
    assert mock_console.print.called


# ---------------------------------------------------------------------------
# CLI Integration Tests
# ---------------------------------------------------------------------------
def test_cli_troubleshoot_run_all(runner: CliRunner) -> None:
    """Test pqsysguard troubleshoot run --all CLI command."""
    result = runner.invoke(app, ["troubleshoot", "run", "--all"])
    assert result.exit_code == 0
    assert "Automated Diagnostic Report" in result.stdout
    assert "READ-ONLY AUDIT" in result.stdout


def test_cli_troubleshoot_check_individual(runner: CliRunner) -> None:
    """Test pqsysguard troubleshoot check <name> CLI command."""
    result = runner.invoke(app, ["troubleshoot", "check", "cpu"])
    assert result.exit_code == 0
    assert "Automated Diagnostic Report" in result.stdout


def test_cli_troubleshoot_check_invalid(runner: CliRunner) -> None:
    """Test pqsysguard troubleshoot check with invalid name fails with code 1."""
    result = runner.invoke(app, ["troubleshoot", "check", "unknown_subsystem"])
    assert result.exit_code == 1
    assert "Unknown check" in result.stdout
