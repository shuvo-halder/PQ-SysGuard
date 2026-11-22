"""Core security audit checks mapping system posture to CIS benchmarks."""

from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

import psutil

from pqsysguard.security.models import (
    AuditFinding,
    AuditSeverity,
    AuditStatus,
    CISControl,
    SecurityReport,
)
from pqsysguard.utils.logger import get_logger

logger = get_logger("security.auditor")

STANDARD_SUID_BASELINE = {
    "sudo",
    "su",
    "passwd",
    "mount",
    "umount",
    "chfn",
    "chsh",
    "newgrp",
    "gpasswd",
    "pkexec",
    "ping",
    "crontab",
    "ssh-keysign",
}


def audit_open_ports() -> AuditFinding:
    """Audit listening ports on public interfaces (0.0.0.0, ::) vs localhost."""
    cis = CISControl(
        id="CIS-3.1.1",
        title="Ensure unauthenticated legacy network services are not listening on public interfaces",
    )

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        logger.debug("Cannot inspect net connections: %s", exc)
        return AuditFinding(
            check_id="PORT-001",
            title="Open Listening Ports Audit",
            status=AuditStatus.WARN,
            severity=AuditSeverity.LOW,
            cis_control=cis,
            evidence="Insufficient privileges to query active network sockets (run with sudo).",
            remediation="Execute security audit with elevated root privileges: 'sudo pqsysguard security'.",
            impact_penalty=0,
        )

    wildcard_listeners: list[tuple[int, str, str]] = []
    dangerous_ports = {21: "FTP", 23: "Telnet", 513: "Rlogin", 514: "Rsh", 5900: "VNC"}
    detected_dangerous: list[str] = []

    for c in conns:
        if c.status == psutil.CONN_LISTEN and c.laddr:
            ip_addr = c.laddr.ip
            port = c.laddr.port
            # Check if listening on public/wildcard addresses
            if ip_addr in ("0.0.0.0", "::", ""):
                pname = "unknown"
                if c.pid:
                    try:
                        pname = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                wildcard_listeners.append((port, ip_addr, pname))
                if port in dangerous_ports:
                    detected_dangerous.append(f"Port {port} ({dangerous_ports[port]} / {pname})")

    if detected_dangerous:
        return AuditFinding(
            check_id="PORT-001",
            title="Dangerous Insecure Services Listening on Public Interfaces",
            status=AuditStatus.FAIL,
            severity=AuditSeverity.CRITICAL,
            cis_control=cis,
            evidence="Insecure legacy services detected:\n" + "\n".join(f"• {s}" for s in detected_dangerous),
            remediation="Disable legacy unencrypted services: 'systemctl disable --now <service>'.",
            impact_penalty=20,
        )

    if wildcard_listeners:
        evidence = (
            f"Found {len(wildcard_listeners)} public listening port(s):\n"
            + "\n".join(f"• Port {p} bound by {name}" for p, ip, name in wildcard_listeners[:5])
        )
        return AuditFinding(
            check_id="PORT-001",
            title="Public Listening Network Sockets Detected",
            status=AuditStatus.PASS,
            severity=AuditSeverity.INFO,
            cis_control=cis,
            evidence=evidence,
            remediation="Bind internal services to 127.0.0.1 or protect with firewall rules.",
            impact_penalty=0,
        )

    return AuditFinding(
        check_id="PORT-001",
        title="Open Listening Ports Audit",
        status=AuditStatus.PASS,
        severity=AuditSeverity.INFO,
        cis_control=cis,
        evidence="No unexpected listening services bound to wildcard interfaces.",
        remediation="Continue periodic port audits.",
        impact_penalty=0,
    )


def audit_ssh_config(config_path: Path | None = None) -> list[AuditFinding]:
    """Audit OpenSSH daemon configuration against CIS benchmark controls."""
    findings: list[AuditFinding] = []
    target_path = config_path or Path("/etc/ssh/sshd_config")

    if not target_path.is_file():
        # OpenSSH not installed or running in non-standard location
        return findings

    config_text = ""
    try:
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            config_text = f.read()
    except (PermissionError, OSError) as exc:
        findings.append(
            AuditFinding(
                check_id="SSH-000",
                title="SSH Configuration File Read Permission",
                status=AuditStatus.WARN,
                severity=AuditSeverity.MEDIUM,
                evidence=f"Cannot read {target_path}: {exc}",
                remediation="Run security audit as root to inspect /etc/ssh/sshd_config.",
                impact_penalty=5,
            )
        )
        return findings

    # Parse effective active key-value directives (ignoring comments)
    directives: dict[str, str] = {}
    for line in config_text.splitlines():
        cleaned = line.strip()
        if cleaned and not cleaned.startswith("#") and " " in cleaned:
            k, v = cleaned.split(None, 1)
            # SSH directives are case-insensitive
            directives[k.lower()] = v.strip()

    # 1. PermitRootLogin (CIS-5.2.10)
    cis_root = CISControl(id="CIS-5.2.10", title="Ensure SSH PermitRootLogin is disabled")
    root_login = directives.get("permitrootlogin", "yes").lower()  # Default in older sshd is 'yes'
    if root_login in ("yes", "without-password"):
        findings.append(
            AuditFinding(
                check_id="SSH-001",
                title="SSH PermitRootLogin is Enabled",
                status=AuditStatus.FAIL,
                severity=AuditSeverity.HIGH,
                cis_control=cis_root,
                evidence=f"PermitRootLogin is currently configured as '{root_login}'.",
                remediation="Set 'PermitRootLogin no' or 'prohibit-password' in /etc/ssh/sshd_config and reload sshd.",
                impact_penalty=10,
            )
        )
    else:
        findings.append(
            AuditFinding(
                check_id="SSH-001",
                title="SSH PermitRootLogin is Hardened",
                status=AuditStatus.PASS,
                severity=AuditSeverity.INFO,
                cis_control=cis_root,
                evidence=f"PermitRootLogin is securely set to '{root_login}'.",
                remediation="Maintain existing configuration.",
                impact_penalty=0,
            )
        )

    # 2. PasswordAuthentication (CIS-5.2.11)
    cis_pass = CISControl(id="CIS-5.2.11", title="Ensure SSH PasswordAuthentication is disabled")
    pwd_auth = directives.get("passwordauthentication", "yes").lower()
    if pwd_auth == "yes":
        findings.append(
            AuditFinding(
                check_id="SSH-002",
                title="SSH Password Authentication is Enabled",
                status=AuditStatus.WARN,
                severity=AuditSeverity.MEDIUM,
                cis_control=cis_pass,
                evidence="PasswordAuthentication is enabled ('yes'), exposing SSH to brute-force credential stuffing.",
                remediation="Enforce SSH public key authentication: set 'PasswordAuthentication no' in /etc/ssh/sshd_config.",
                impact_penalty=8,
            )
        )
    else:
        findings.append(
            AuditFinding(
                check_id="SSH-002",
                title="SSH Password Authentication is Disabled",
                status=AuditStatus.PASS,
                severity=AuditSeverity.INFO,
                cis_control=cis_pass,
                evidence="PasswordAuthentication is set to 'no' (key-based login enforced).",
                remediation="Maintain key-based authentication.",
                impact_penalty=0,
            )
        )

    # 3. Protocol 2 Enforced (CIS-5.2.3)
    cis_proto = CISControl(id="CIS-5.2.3", title="Ensure SSH Protocol 2 is used exclusively")
    proto = directives.get("protocol", "2")
    if proto != "2":
        findings.append(
            AuditFinding(
                check_id="SSH-003",
                title="Insecure SSH Protocol Version",
                status=AuditStatus.FAIL,
                severity=AuditSeverity.CRITICAL,
                cis_control=cis_proto,
                evidence=f"SSH protocol is set to '{proto}' (vulnerable to cryptanalytic flaws).",
                remediation="Set 'Protocol 2' in /etc/ssh/sshd_config.",
                impact_penalty=15,
            )
        )

    # 4. PermitEmptyPasswords (CIS-5.2.9)
    cis_empty = CISControl(id="CIS-5.2.9", title="Ensure SSH PermitEmptyPasswords is disabled")
    empty_pwd = directives.get("permitemptypasswords", "no").lower()
    if empty_pwd == "yes":
        findings.append(
            AuditFinding(
                check_id="SSH-004",
                title="SSH Allows Empty Passwords",
                status=AuditStatus.FAIL,
                severity=AuditSeverity.CRITICAL,
                cis_control=cis_empty,
                evidence="PermitEmptyPasswords is set to 'yes'.",
                remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
                impact_penalty=15,
            )
        )

    # 5. X11Forwarding (CIS-5.2.6)
    cis_x11 = CISControl(id="CIS-5.2.6", title="Ensure SSH X11Forwarding is disabled")
    x11 = directives.get("x11forwarding", "no").lower()
    if x11 == "yes":
        findings.append(
            AuditFinding(
                check_id="SSH-005",
                title="SSH X11 Forwarding is Enabled",
                status=AuditStatus.WARN,
                severity=AuditSeverity.LOW,
                cis_control=cis_x11,
                evidence="X11Forwarding is enabled ('yes'), potentially exposing remote displays to keystroke snooping.",
                remediation="Disable X11 forwarding: 'X11Forwarding no' in /etc/ssh/sshd_config.",
                impact_penalty=3,
            )
        )

    return findings


def audit_failed_logins(
    auth_log_path: Path | None = None,
    max_threshold: int = 10,
) -> AuditFinding:
    """Analyze authentication logs for repeated failed logins and top attacker IP addresses."""
    cis = CISControl(id="CIS-5.3.2", title="Ensure system tracks and alerts on repeated failed logins")

    # Locate auth log
    possible_paths = [
        auth_log_path,
        Path("/var/log/auth.log"),
        Path("/var/log/secure"),
    ]
    target_log: Path | None = None
    for p in possible_paths:
        if p and p.is_file():
            target_log = p
            break

    if not target_log:
        return AuditFinding(
            check_id="AUTH-LOG-001",
            title="Failed Login Attempts & Brute-Force Tracker",
            status=AuditStatus.PASS,
            severity=AuditSeverity.INFO,
            cis_control=cis,
            evidence="No system authentication log found or accessible on this host.",
            remediation="Ensure systemd-journald or rsyslog is configured for auth logging.",
            impact_penalty=0,
        )

    lines: list[str] = []
    try:
        with open(target_log, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-2000:]  # Read up to 2000 most recent lines
    except (PermissionError, OSError) as exc:
        return AuditFinding(
            check_id="AUTH-LOG-001",
            title="Failed Login Tracker",
            status=AuditStatus.WARN,
            severity=AuditSeverity.LOW,
            cis_control=cis,
            evidence=f"Cannot read authentication log {target_log}: {exc}",
            remediation="Run security audit with root permissions to inspect /var/log/auth.log.",
            impact_penalty=0,
        )

    ip_pattern = re.compile(r"Failed password.*from\s+([0-9a-fA-F\.\:]+)")
    attacker_ips: Counter[str] = Counter()

    for line in lines:
        match = ip_pattern.search(line)
        if match:
            attacker_ips[match.group(1)] += 1

    total_failures = sum(attacker_ips.values())
    if total_failures > max_threshold or any(cnt >= 5 for cnt in attacker_ips.values()):
        top_offenders = attacker_ips.most_common(5)
        evidence_lines = [f"Total failed login attempts: {total_failures}. Top source IPs:"]
        for ip, count in top_offenders:
            evidence_lines.append(f"• IP {ip}: {count} failed attempt(s)")

        return AuditFinding(
            check_id="AUTH-LOG-001",
            title=f"Repeated SSH Failed Login Spike Detected ({total_failures} attempts)",
            status=AuditStatus.WARN,
            severity=AuditSeverity.HIGH,
            cis_control=cis,
            evidence="\n".join(evidence_lines),
            remediation="Deploy fail2ban ('systemctl enable --now fail2ban') or block offending IPs via firewall.",
            impact_penalty=10,
        )

    return AuditFinding(
        check_id="AUTH-LOG-001",
        title="Failed Login Attempts Normal",
        status=AuditStatus.PASS,
        severity=AuditSeverity.INFO,
        cis_control=cis,
        evidence=f"No abnormal failed login spikes detected ({total_failures} total failures).",
        remediation="Continue log monitoring.",
        impact_penalty=0,
    )


def audit_world_writable_files(search_paths: list[Path] | None = None) -> AuditFinding:
    """Scan critical system directories for world-writable files."""
    cis = CISControl(id="CIS-6.1.10", title="Ensure no world-writable files exist in system paths")
    paths_to_check = search_paths or [
        Path("/etc"),
        Path("/bin"),
        Path("/sbin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
    ]

    world_writable: list[str] = []

    for base_dir in paths_to_check:
        if not base_dir.is_dir():
            continue
        try:
            for root, _dirs, files in os.walk(base_dir):
                for fname in files:
                    full_path = os.path.join(root, fname)
                    try:
                        st = os.lstat(full_path)
                        # Exclude symlinks
                        if stat.S_ISLNK(st.st_mode):
                            continue
                        if st.st_mode & 0o002 != 0:
                            world_writable.append(full_path)
                            if len(world_writable) >= 10:
                                break
                    except (PermissionError, OSError):
                        continue
                if len(world_writable) >= 10:
                    break
        except (PermissionError, OSError):
            continue

    if world_writable:
        evidence = f"Found {len(world_writable)} world-writable file(s):\n" + "\n".join(
            f"• {f}" for f in world_writable[:5]
        )
        return AuditFinding(
            check_id="PERM-001",
            title="World-Writable Files in System Paths Detected",
            status=AuditStatus.FAIL,
            severity=AuditSeverity.CRITICAL,
            cis_control=cis,
            evidence=evidence,
            remediation="Remove world-writable permissions: 'chmod o-w <file>'.",
            impact_penalty=15,
        )

    return AuditFinding(
        check_id="PERM-001",
        title="No World-Writable Files in System Paths",
        status=AuditStatus.PASS,
        severity=AuditSeverity.INFO,
        cis_control=cis,
        evidence="All scanned system directories have properly restricted permissions.",
        remediation="Maintain existing filesystem permissions.",
        impact_penalty=0,
    )


def audit_suid_binaries(search_paths: list[Path] | None = None) -> AuditFinding:
    """Identify SUID/SGID binaries and flag non-standard or unauthorized executables."""
    cis = CISControl(id="CIS-6.1.13", title="Ensure unauthorized SUID/SGID binaries are removed")
    paths_to_check = search_paths or [
        Path("/bin"),
        Path("/sbin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
    ]

    detected_suid: list[tuple[str, str]] = []
    suspicious_suid: list[str] = []

    for base_dir in paths_to_check:
        if not base_dir.is_dir():
            continue
        try:
            for entry in os.scandir(base_dir):
                try:
                    if entry.is_file(follow_symlinks=False):
                        st = entry.stat(follow_symlinks=False)
                        mode = st.st_mode
                        is_suid = bool(mode & 0o4000)
                        is_sgid = bool(mode & 0o2000)
                        if is_suid or is_sgid:
                            tag = "SUID" if is_suid else "SGID"
                            detected_suid.append((entry.path, tag))
                            bname = Path(entry.name).stem.lower()
                            if bname not in STANDARD_SUID_BASELINE:
                                suspicious_suid.append(f"{entry.path} ({tag})")
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            continue

    if suspicious_suid:
        evidence = (
            f"Detected {len(suspicious_suid)} non-standard SUID/SGID binary/binaries:\n"
            + "\n".join(f"• {b}" for b in suspicious_suid[:5])
        )
        return AuditFinding(
            check_id="SUID-001",
            title="Non-Standard SUID/SGID Executables Identified",
            status=AuditStatus.WARN,
            severity=AuditSeverity.MEDIUM,
            cis_control=cis,
            evidence=evidence,
            remediation="Review necessity of SUID permissions: 'chmod u-s <binary>' or verify package checksums.",
            impact_penalty=8,
        )

    return AuditFinding(
        check_id="SUID-001",
        title="SUID/SGID Binaries Conforming to Baseline",
        status=AuditStatus.PASS,
        severity=AuditSeverity.INFO,
        cis_control=cis,
        evidence=f"All {len(detected_suid)} detected SUID binaries match the standard system baseline.",
        remediation="Continue auditing SUID binaries periodically.",
        impact_penalty=0,
    )


def audit_users_and_passwords(
    passwd_path: Path | None = None,
    shadow_path: Path | None = None,
) -> list[AuditFinding]:
    """Audit accounts for empty password hashes and unauthorized UID 0 users."""
    findings: list[AuditFinding] = []
    p_path = passwd_path or Path("/etc/passwd")
    s_path = shadow_path or Path("/etc/shadow")

    # 1. UID 0 Audit (CIS-6.2.5)
    cis_uid0 = CISControl(id="CIS-6.2.5", title="Ensure root is the only UID 0 account")
    if p_path.is_file():
        try:
            with open(p_path, "r", encoding="utf-8", errors="replace") as f:
                uid0_users: list[str] = []
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 3:
                        uname = parts[0]
                        uid = parts[2]
                        if uid == "0" and uname != "root":
                            uid0_users.append(uname)

                if uid0_users:
                    findings.append(
                        AuditFinding(
                            check_id="USER-001",
                            title="Unauthorized Non-Root Account with UID 0 Detected",
                            status=AuditStatus.FAIL,
                            severity=AuditSeverity.CRITICAL,
                            cis_control=cis_uid0,
                            evidence=f"Account(s) with UID 0: {', '.join(uid0_users)}.",
                            remediation="Delete or re-assign non-root UID 0 accounts: 'usermod -u <new-uid> <user>'.",
                            impact_penalty=20,
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            check_id="USER-001",
                            title="Root is the Only UID 0 Account",
                            status=AuditStatus.PASS,
                            severity=AuditSeverity.INFO,
                            cis_control=cis_uid0,
                            evidence="Only the 'root' user possesses UID 0.",
                            remediation="Maintain existing account separation.",
                            impact_penalty=0,
                        )
                    )
        except (PermissionError, OSError) as exc:
            logger.warning("Error reading %s: %s", p_path, exc)

    # 2. Empty Password Hashes Audit (CIS-6.2.1)
    cis_empty_pwd = CISControl(id="CIS-6.2.1", title="Ensure password fields are not empty")
    if s_path.is_file():
        try:
            with open(s_path, "r", encoding="utf-8", errors="replace") as f:
                empty_pwd_users: list[str] = []
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        uname = parts[0]
                        pwd_hash = parts[1]
                        if pwd_hash == "":
                            empty_pwd_users.append(uname)

                if empty_pwd_users:
                    findings.append(
                        AuditFinding(
                            check_id="USER-002",
                            title="Accounts with Empty Passwords Detected",
                            status=AuditStatus.FAIL,
                            severity=AuditSeverity.CRITICAL,
                            cis_control=cis_empty_pwd,
                            evidence=f"User(s) with empty password: {', '.join(empty_pwd_users)}.",
                            remediation="Lock account or set strong password: 'passwd -l <user>'.",
                            impact_penalty=20,
                        )
                    )
                else:
                    findings.append(
                        AuditFinding(
                            check_id="USER-002",
                            title="No Accounts with Empty Passwords",
                            status=AuditStatus.PASS,
                            severity=AuditSeverity.INFO,
                            cis_control=cis_empty_pwd,
                            evidence="All accounts in shadow file have passwords or are locked.",
                            remediation="Maintain account security.",
                            impact_penalty=0,
                        )
                    )
        except (PermissionError, OSError):
            findings.append(
                AuditFinding(
                    check_id="USER-002",
                    title="Shadow File Permission Denied",
                    status=AuditStatus.WARN,
                    severity=AuditSeverity.LOW,
                    cis_control=cis_empty_pwd,
                    evidence=f"Permission denied reading {s_path} (requires root privileges).",
                    remediation="Execute security audit with elevated root privileges: 'sudo pqsysguard security'.",
                    impact_penalty=0,
                )
            )

    return findings


def audit_pending_security_updates() -> AuditFinding:
    """Query package manager for unapplied security patches and updates."""
    cis = CISControl(id="CIS-1.9", title="Ensure system software updates are installed")

    # Check for APT (Debian/Ubuntu)
    apt_bin = shutil.which("apt-get")
    if apt_bin:
        try:
            res = subprocess.run(  # noqa: S603
                [apt_bin, "-s", "upgrade"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            # Find lines like "X upgraded, Y newly installed"
            match = re.search(r"(\d+)\s+upgraded", res.stdout)
            if match and int(match.group(1)) > 0:
                count = int(match.group(1))
                return AuditFinding(
                    check_id="UPDATE-001",
                    title=f"{count} Pending Software Package Update(s)",
                    status=AuditStatus.WARN,
                    severity=AuditSeverity.MEDIUM,
                    cis_control=cis,
                    evidence=f"Package manager reports {count} upgradeable package(s).",
                    remediation="Apply system updates: 'sudo apt-get update && sudo apt-get dist-upgrade'.",
                    impact_penalty=5,
                )
        except (subprocess.SubprocessError, OSError):
            pass

    # Check for DNF (Fedora/RHEL/CentOS)
    dnf_bin = shutil.which("dnf")
    if dnf_bin:
        try:
            res = subprocess.run(  # noqa: S603
                [dnf_bin, "check-update", "--security"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            if res.returncode == 100:  # DNF returns 100 when updates are available
                return AuditFinding(
                    check_id="UPDATE-001",
                    title="Pending Security Updates Available (DNF)",
                    status=AuditStatus.WARN,
                    severity=AuditSeverity.MEDIUM,
                    cis_control=cis,
                    evidence="DNF reports pending security errata/updates.",
                    remediation="Apply security updates: 'sudo dnf update --security'.",
                    impact_penalty=5,
                )
        except (subprocess.SubprocessError, OSError):
            pass

    return AuditFinding(
        check_id="UPDATE-001",
        title="Package Updates Up-to-Date",
        status=AuditStatus.PASS,
        severity=AuditSeverity.INFO,
        cis_control=cis,
        evidence="No outstanding security updates detected.",
        remediation="Continue weekly update cadence.",
        impact_penalty=0,
    )


def audit_firewall_status() -> AuditFinding:
    """Verify that an active host-based firewall (UFW, firewalld, nftables) is running."""
    cis = CISControl(id="CIS-3.5.1", title="Ensure a host-based firewall is active and enabled")

    # 1. Check UFW
    ufw_bin = shutil.which("ufw")
    if ufw_bin:
        try:
            res = subprocess.run(  # noqa: S603
                [ufw_bin, "status"],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            if "Status: active" in res.stdout:
                return AuditFinding(
                    check_id="FW-001",
                    title="UFW Host Firewall is Active",
                    status=AuditStatus.PASS,
                    severity=AuditSeverity.INFO,
                    cis_control=cis,
                    evidence="UFW firewall daemon status is 'active'.",
                    remediation="Maintain existing firewall rules.",
                    impact_penalty=0,
                )
        except (subprocess.SubprocessError, OSError):
            pass

    # 2. Check firewalld
    fw_cmd_bin = shutil.which("firewall-cmd")
    if fw_cmd_bin:
        try:
            res = subprocess.run(  # noqa: S603
                [fw_cmd_bin, "--state"],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            if "running" in res.stdout:
                return AuditFinding(
                    check_id="FW-001",
                    title="Firewalld Daemon is Active",
                    status=AuditStatus.PASS,
                    severity=AuditSeverity.INFO,
                    cis_control=cis,
                    evidence="firewall-cmd reports state is 'running'.",
                    remediation="Maintain existing firewall rules.",
                    impact_penalty=0,
                )
        except (subprocess.SubprocessError, OSError):
            pass

    # 3. Check nftables / iptables
    nft_bin = shutil.which("nft")
    if nft_bin:
        try:
            res = subprocess.run(  # noqa: S603
                [nft_bin, "list", "tables"],
                capture_output=True,
                text=True,
                timeout=3.0,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return AuditFinding(
                    check_id="FW-001",
                    title="Nftables Packet Filter is Active",
                    status=AuditStatus.PASS,
                    severity=AuditSeverity.INFO,
                    cis_control=cis,
                    evidence="nftables tables detected.",
                    remediation="Maintain existing nftables ruleset.",
                    impact_penalty=0,
                )
        except (subprocess.SubprocessError, OSError):
            pass

    # No active firewall detected
    return AuditFinding(
        check_id="FW-001",
        title="No Active Host-Based Firewall Detected",
        status=AuditStatus.FAIL,
        severity=AuditSeverity.CRITICAL,
        cis_control=cis,
        evidence="Neither UFW, firewalld, nor nftables is running or enabled.",
        remediation="Enable and configure UFW ('sudo ufw enable') or firewalld ('sudo systemctl enable --now firewalld').",
        impact_penalty=15,
    )


def run_full_security_audit(
    ssh_config_path: Path | None = None,
    passwd_path: Path | None = None,
    shadow_path: Path | None = None,
    auth_log_path: Path | None = None,
) -> SecurityReport:
    """Execute all security hardening audit checks and generate composite report."""
    report = SecurityReport()

    # 1. Open Ports
    report.findings.append(audit_open_ports())

    # 2. SSH Configuration
    report.findings.extend(audit_ssh_config(config_path=ssh_config_path))

    # 3. Failed Logins
    report.findings.append(audit_failed_logins(auth_log_path=auth_log_path))

    # 4. World Writable Files
    report.findings.append(audit_world_writable_files())

    # 5. SUID / SGID Binaries
    report.findings.append(audit_suid_binaries())

    # 6. Accounts & Passwords
    report.findings.extend(
        audit_users_and_passwords(passwd_path=passwd_path, shadow_path=shadow_path)
    )

    # 7. Software Updates
    report.findings.append(audit_pending_security_updates())

    # 8. Firewall Status
    report.findings.append(audit_firewall_status())

    # Calculate overall security score (0-100) and grade (A-F)
    report.calculate_score()
    return report
