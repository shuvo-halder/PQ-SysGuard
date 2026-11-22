"""Unit and integration tests for security hardening audit module."""

import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from rich.console import Console
from typer.testing import CliRunner

from pqsysguard.cli import app
from pqsysguard.security.auditor import (
    audit_failed_logins,
    audit_firewall_status,
    audit_open_ports,
    audit_pending_security_updates,
    audit_ssh_config,
    audit_suid_binaries,
    audit_users_and_passwords,
    audit_world_writable_files,
    run_full_security_audit,
)
from pqsysguard.security.models import (
    AuditFinding,
    AuditSeverity,
    AuditStatus,
    CISControl,
    SecurityReport,
)
from pqsysguard.security.presenter import (
    display_terminal_report,
    export_html_report,
    export_json_report,
    get_grade_color,
)


# ---------------------------------------------------------------------------
# Open Ports Audit Tests
# ---------------------------------------------------------------------------
@patch("psutil.net_connections")
def test_audit_open_ports_dangerous_detected(mock_conns: MagicMock) -> None:
    """Test detection of dangerous legacy services listening on wildcard IP."""
    conn_telnet = SimpleNamespace(
        status="LISTEN",
        laddr=SimpleNamespace(ip="0.0.0.0", port=23),
        pid=123,
    )
    mock_conns.return_value = [conn_telnet]

    finding = audit_open_ports()
    assert finding.status == AuditStatus.FAIL
    assert finding.severity == AuditSeverity.CRITICAL
    assert "Port 23 (Telnet" in finding.evidence
    assert finding.cis_control is not None
    assert finding.cis_control.id == "CIS-3.1.1"


@patch("psutil.net_connections")
def test_audit_open_ports_public_safe(mock_conns: MagicMock) -> None:
    """Test standard public listener detection."""
    conn_http = SimpleNamespace(
        status="LISTEN",
        laddr=SimpleNamespace(ip="0.0.0.0", port=8080),
        pid=456,
    )
    mock_conns.return_value = [conn_http]

    finding = audit_open_ports()
    assert finding.status == AuditStatus.PASS
    assert "Port 8080" in finding.evidence


# ---------------------------------------------------------------------------
# SSH Config Audit Tests
# ---------------------------------------------------------------------------
def test_audit_ssh_config_unhardened(tmp_path: Path) -> None:
    """Test SSH audit with insecure configuration directives."""
    sshd_config = tmp_path / "sshd_config"
    content = """
PermitRootLogin yes
PasswordAuthentication yes
Protocol 1
PermitEmptyPasswords yes
X11Forwarding yes
"""
    sshd_config.write_text(content.strip(), encoding="utf-8")

    findings = audit_ssh_config(config_path=sshd_config)
    checks = {f.check_id: f for f in findings}

    assert checks["SSH-001"].status == AuditStatus.FAIL  # Root login
    assert checks["SSH-002"].status == AuditStatus.WARN  # Password auth
    assert checks["SSH-003"].status == AuditStatus.FAIL  # Protocol 1
    assert checks["SSH-004"].status == AuditStatus.FAIL  # Empty passwords
    assert checks["SSH-005"].status == AuditStatus.WARN  # X11


def test_audit_ssh_config_hardened(tmp_path: Path) -> None:
    """Test SSH audit with hardened configuration directives."""
    sshd_config = tmp_path / "sshd_config"
    content = """
PermitRootLogin no
PasswordAuthentication no
Protocol 2
PermitEmptyPasswords no
X11Forwarding no
"""
    sshd_config.write_text(content.strip(), encoding="utf-8")

    findings = audit_ssh_config(config_path=sshd_config)
    for f in findings:
        assert f.status == AuditStatus.PASS


def test_audit_ssh_config_missing(tmp_path: Path) -> None:
    """Test missing SSH config returns empty findings list."""
    assert audit_ssh_config(config_path=tmp_path / "nonexistent") == []


# ---------------------------------------------------------------------------
# Failed Logins Audit Tests
# ---------------------------------------------------------------------------
def test_audit_failed_logins_spike(tmp_path: Path) -> None:
    """Test detecting spike in failed logins and aggregating top attacker IPs."""
    auth_log = tmp_path / "auth.log"
    content = """
Nov 22 10:00:01 srv sshd[1]: Failed password for root from 198.51.100.1 port 4001 ssh2
Nov 22 10:00:02 srv sshd[2]: Failed password for root from 198.51.100.1 port 4002 ssh2
Nov 22 10:00:03 srv sshd[3]: Failed password for root from 198.51.100.1 port 4003 ssh2
Nov 22 10:00:04 srv sshd[4]: Failed password for admin from 198.51.100.1 port 4004 ssh2
Nov 22 10:00:05 srv sshd[5]: Failed password for admin from 198.51.100.1 port 4005 ssh2
Nov 22 10:00:06 srv sshd[6]: Failed password for user from 203.0.113.5 port 5001 ssh2
"""
    auth_log.write_text(content.strip(), encoding="utf-8")

    finding = audit_failed_logins(auth_log_path=auth_log, max_threshold=4)
    assert finding.status == AuditStatus.WARN
    assert "198.51.100.1" in finding.evidence
    assert finding.cis_control is not None
    assert finding.cis_control.id == "CIS-5.3.2"


def test_audit_failed_logins_normal(tmp_path: Path) -> None:
    """Test normal failed login volume returns PASS."""
    auth_log = tmp_path / "auth.log"
    auth_log.write_text("Nov 22 10:00:01 srv sshd[1]: Accepted publickey\n", encoding="utf-8")

    finding = audit_failed_logins(auth_log_path=auth_log, max_threshold=10)
    assert finding.status == AuditStatus.PASS


# ---------------------------------------------------------------------------
# World Writable & SUID Binaries Audit Tests
# ---------------------------------------------------------------------------
def test_audit_world_writable_files(tmp_path: Path) -> None:
    """Test detecting world-writable files in system directory."""
    test_dir = tmp_path / "etc"
    test_dir.mkdir()
    good_file = test_dir / "safe.conf"
    good_file.write_text("data", encoding="utf-8")
    good_file.chmod(0o644)

    bad_file = test_dir / "insecure.conf"
    bad_file.write_text("secrets", encoding="utf-8")
    # Grant world-writable (0o666)
    bad_file.chmod(bad_file.stat().st_mode | stat.S_IWOTH)

    finding = audit_world_writable_files(search_paths=[test_dir])
    assert finding.status == AuditStatus.FAIL
    assert finding.severity == AuditSeverity.CRITICAL
    assert "insecure.conf" in finding.evidence


def test_audit_suid_binaries_non_standard(tmp_path: Path) -> None:
    """Test flagging non-standard SUID executables."""
    test_bin_dir = tmp_path / "bin"
    test_bin_dir.mkdir()

    # Standard safe SUID binary
    sudo_bin = test_bin_dir / "sudo"
    sudo_bin.write_bytes(b"\x7fELF")
    sudo_bin.chmod(sudo_bin.stat().st_mode | stat.S_ISUID | stat.S_IXUSR)

    # Suspicious custom SUID binary
    custom_bin = test_bin_dir / "backdoor_shell"
    custom_bin.write_bytes(b"\x7fELF")
    custom_bin.chmod(custom_bin.stat().st_mode | stat.S_ISUID | stat.S_IXUSR)

    finding = audit_suid_binaries(search_paths=[test_bin_dir])
    assert finding.status == AuditStatus.WARN
    assert "backdoor_shell" in finding.evidence


# ---------------------------------------------------------------------------
# Users & Passwords Audit Tests
# ---------------------------------------------------------------------------
def test_audit_users_duplicate_uid0(tmp_path: Path) -> None:
    """Test detecting unauthorized account with UID 0."""
    passwd_file = tmp_path / "passwd"
    content = """
root:x:0:0:root:/root:/bin/bash
toor:x:0:0:toor:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
"""
    passwd_file.write_text(content.strip(), encoding="utf-8")

    findings = audit_users_and_passwords(passwd_path=passwd_file, shadow_path=tmp_path / "none")
    uid0_finding = next(f for f in findings if f.check_id == "USER-001")
    assert uid0_finding.status == AuditStatus.FAIL
    assert uid0_finding.severity == AuditSeverity.CRITICAL
    assert "toor" in uid0_finding.evidence


def test_audit_users_empty_passwords(tmp_path: Path) -> None:
    """Test detecting account with empty password in shadow file."""
    passwd_file = tmp_path / "passwd"
    passwd_file.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")

    shadow_file = tmp_path / "shadow"
    content = """
root:$6$encryptedhash:19000:0:99999:7:::
nopassuser::19000:0:99999:7:::
"""
    shadow_file.write_text(content.strip(), encoding="utf-8")

    findings = audit_users_and_passwords(passwd_path=passwd_file, shadow_path=shadow_file)
    empty_pwd_finding = next(f for f in findings if f.check_id == "USER-002")
    assert empty_pwd_finding.status == AuditStatus.FAIL
    assert empty_pwd_finding.severity == AuditSeverity.CRITICAL
    assert "nopassuser" in empty_pwd_finding.evidence


# ---------------------------------------------------------------------------
# Security Updates & Firewall Audit Tests
# ---------------------------------------------------------------------------
@patch("shutil.which", return_value="/usr/bin/apt-get")
@patch("subprocess.run")
def test_audit_pending_updates_apt(mock_run: MagicMock, mock_which: MagicMock) -> None:
    """Test pending updates detection via apt-get."""
    mock_run.return_value = subprocess.CompletedProcess(
        args=["apt-get"],
        returncode=0,
        stdout="5 upgraded, 0 newly installed, 0 to remove\n",
        stderr="",
    )

    finding = audit_pending_security_updates()
    assert finding.status == AuditStatus.WARN
    assert "5 Pending Software Package Update" in finding.title


@patch("shutil.which", side_effect=lambda bin_name: "/usr/sbin/ufw" if bin_name == "ufw" else None)
@patch("subprocess.run")
def test_audit_firewall_ufw_active(mock_run: MagicMock, mock_which: MagicMock) -> None:
    """Test active UFW firewall detection."""
    mock_run.return_value = subprocess.CompletedProcess(
        args=["ufw"],
        returncode=0,
        stdout="Status: active\nLogging: on (low)\n",
        stderr="",
    )

    finding = audit_firewall_status()
    assert finding.status == AuditStatus.PASS
    assert "UFW Host Firewall is Active" in finding.title


@patch("shutil.which", return_value=None)
def test_audit_firewall_none_active(mock_which: MagicMock) -> None:
    """Test failure when no host firewall is enabled."""
    finding = audit_firewall_status()
    assert finding.status == AuditStatus.FAIL
    assert finding.severity == AuditSeverity.CRITICAL
    assert finding.impact_penalty == 15


# ---------------------------------------------------------------------------
# Report & Presenter Tests
# ---------------------------------------------------------------------------
def test_security_report_scoring() -> None:
    """Test security score deduction and grade mapping."""
    report = SecurityReport()
    report.findings = [
        AuditFinding(
            check_id="T-1",
            title="Clean check",
            status=AuditStatus.PASS,
            severity=AuditSeverity.INFO,
            evidence="ok",
            remediation="none",
            impact_penalty=0,
        ),
        AuditFinding(
            check_id="T-2",
            title="Critical failure",
            status=AuditStatus.FAIL,
            severity=AuditSeverity.CRITICAL,
            evidence="critical issue",
            remediation="fix",
            impact_penalty=20,
        ),
    ]
    report.calculate_score()
    assert report.score == 80  # 100 - 20
    assert report.grade == "B"
    assert report.passed_count == 1
    assert report.failed_count == 1


def test_presenter_exports(tmp_path: Path) -> None:
    """Test JSON and HTML report generation."""
    report = SecurityReport()
    report.findings.append(
        AuditFinding(
            check_id="CIS-5.2.10",
            title="SSH Root Login Test",
            status=AuditStatus.PASS,
            severity=AuditSeverity.INFO,
            cis_control=CISControl(id="CIS-5.2.10", title="Disable SSH Root Login"),
            evidence="Root login disabled",
            remediation="Maintain config",
            impact_penalty=0,
        )
    )
    report.calculate_score()

    # JSON export
    json_out = export_json_report(report)
    parsed = json.loads(json_out)
    assert parsed["score"] == 100
    assert parsed["grade"] == "A"

    # HTML export
    html_out = export_html_report(report)
    assert "<!DOCTYPE html>" in html_out
    assert "CIS-5.2.10" in html_out
    assert "Grade A" in html_out

    # Grade color helper
    assert get_grade_color("A") == "green"
    assert get_grade_color("C") == "yellow"
    assert get_grade_color("F") == "red"

    # Console display
    mock_console = MagicMock(spec=Console)
    display_terminal_report(report, console=mock_console)
    assert mock_console.print.called


# ---------------------------------------------------------------------------
# CLI Integration Tests
# ---------------------------------------------------------------------------
def test_cli_security_audit_text(runner: CliRunner) -> None:
    """Test pqsysguard security audit text output."""
    result = runner.invoke(app, ["security", "audit"])
    assert result.exit_code == 0
    assert "PQ-SysGuard Security Hardening Audit" in result.stdout
    assert "CIS Benchmark Audit Controls Summary" in result.stdout


def test_cli_security_audit_json(runner: CliRunner) -> None:
    """Test pqsysguard security audit JSON output."""
    result = runner.invoke(app, ["security", "audit", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert "score" in data
    assert "grade" in data


def test_cli_security_audit_html(runner: CliRunner, tmp_path: Path) -> None:
    """Test pqsysguard security audit HTML file generation."""
    out_html = tmp_path / "audit.html"
    result = runner.invoke(
        app,
        ["security", "audit", "--format", "html", "--output", str(out_html)],
    )
    assert result.exit_code == 0
    assert out_html.is_file()
    assert "<!DOCTYPE html>" in out_html.read_text(encoding="utf-8")


def test_cli_security_audit_invalid_format(runner: CliRunner) -> None:
    """Test pqsysguard security audit with unsupported format."""
    result = runner.invoke(app, ["security", "audit", "--format", "pdf"])
    assert result.exit_code == 1
    assert "Unsupported format" in result.stdout
