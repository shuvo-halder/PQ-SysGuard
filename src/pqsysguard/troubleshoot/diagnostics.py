"""Automated diagnostic checks for CPU, memory, disk hogs, systemd units, DNS, and ports."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path

import psutil

from pqsysguard.monitor.presenter import format_bytes
from pqsysguard.troubleshoot.models import Finding, FindingSeverity
from pqsysguard.utils.logger import get_logger

logger = get_logger("troubleshoot.diagnostics")


def check_cpu_culprits(threshold: float = 85.0) -> list[Finding]:
    """Identify processes consuming excessive CPU when system load is high."""
    findings: list[Finding] = []
    total_cpu = psutil.cpu_percent(interval=None)

    # Collect process list
    high_cpu_procs: list[tuple[int, str, str, float]] = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent"]):
        try:
            info = p.info
            cpu_val = info["cpu_percent"] or 0.0
            if cpu_val > 50.0:
                high_cpu_procs.append(
                    (
                        info["pid"],
                        info["name"] or "unknown",
                        info["username"] or "unknown",
                        cpu_val,
                    )
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    high_cpu_procs.sort(key=lambda x: x[3], reverse=True)

    if total_cpu >= threshold or high_cpu_procs:
        evidence_lines = [f"Total System CPU Utilization: {total_cpu:.1f}%"]
        for pid, name, user, proc_cpu in high_cpu_procs[:3]:
            evidence_lines.append(
                f"• PID {pid} ({name}, user: {user}) consuming {proc_cpu:.1f}% CPU"
            )

        if high_cpu_procs:
            top_pid = high_cpu_procs[0][0]
            rec_fix = (
                f"Inspect: 'top -p {top_pid}', renice: 'renice +10 -p {top_pid}', "
                f"or terminate: 'kill -15 {top_pid}'."
            )
        else:
            rec_fix = "Inspect active processes with 'top' or 'htop' to identify high consumers."

        findings.append(
            Finding(
                check_name="cpu_culprit",
                severity=FindingSeverity.CRITICAL if total_cpu >= 90.0 else FindingSeverity.WARNING,
                title="High CPU Utilization & Culprit Process Detected",
                evidence="\n".join(evidence_lines),
                probable_cause=(
                    "Runaway compute task, infinite loop, or high concurrency thread spinlock."
                ),
                recommended_fix=rec_fix,
            )
        )

    return findings


def check_memory_culprits(threshold: float = 85.0) -> list[Finding]:
    """Identify processes consuming excessive memory when RAM utilization is critical."""
    findings: list[Finding] = []
    vm = psutil.virtual_memory()

    high_mem_procs: list[tuple[int, str, str, float, int]] = []
    for p in psutil.process_iter(["pid", "name", "username", "memory_percent", "memory_info"]):
        try:
            info = p.info
            mem_pct = info["memory_percent"] or 0.0
            mem_info = info["memory_info"]
            rss = mem_info.rss if mem_info else 0
            if mem_pct > 20.0 or rss > 1024 * 1024 * 1024:  # > 20% or > 1 GiB
                high_mem_procs.append(
                    (
                        info["pid"],
                        info["name"] or "unknown",
                        info["username"] or "unknown",
                        mem_pct,
                        rss,
                    )
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    high_mem_procs.sort(key=lambda x: x[4], reverse=True)

    if vm.percent >= threshold or high_mem_procs:
        evidence_lines = [
            f"RAM Usage: {vm.percent:.1f}% ({format_bytes(vm.used)} / {format_bytes(vm.total)})"
        ]
        for pid, name, user, proc_mem, rss in high_mem_procs[:3]:
            evidence_lines.append(
                f"• PID {pid} ({name}, user: {user}) holding {proc_mem:.1f}% RAM "
                f"({format_bytes(rss)} RSS)"
            )

        if high_mem_procs:
            top_pid = high_mem_procs[0][0]
            rec_fix = (
                f"Analyze map: 'cat /proc/{top_pid}/smaps_rollup' or restart: "
                f"'systemctl restart <unit>' or 'kill -15 {top_pid}'."
            )
        else:
            rec_fix = "Inspect memory consumers with 'top -o %MEM' or restart responsible daemon."

        findings.append(
            Finding(
                check_name="memory_culprit",
                severity=(
                    FindingSeverity.CRITICAL if vm.percent >= 90.0 else FindingSeverity.WARNING
                ),
                title="High RAM Utilization & Heavy Memory Consumer Identified",
                evidence="\n".join(evidence_lines),
                probable_cause=(
                    "Memory leak, excessive in-memory cache, or undersized RAM for workload."
                ),
                recommended_fix=rec_fix,
            )
        )

    return findings


def scan_directory_space_hogs(
    root_dir: Path, max_depth: int = 1, top_n: int = 3
) -> list[tuple[str, int]]:
    """Safe, non-recursive direct scan of directory sizes without invoking shell commands."""
    results: list[tuple[str, int]] = []
    if not root_dir.is_dir():
        return results

    try:
        with os.scandir(root_dir) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        size = entry.stat().st_size
                        results.append((entry.path, size))
                    elif entry.is_dir(follow_symlinks=False) and max_depth > 0:
                        dir_size = 0
                        with os.scandir(entry.path) as sub_it:
                            for sub_entry in sub_it:
                                try:
                                    if sub_entry.is_file(follow_symlinks=False):
                                        dir_size += sub_entry.stat().st_size
                                except (PermissionError, OSError):
                                    continue
                        results.append((entry.path, dir_size))
                except (PermissionError, OSError):
                    continue
    except (PermissionError, OSError):
        return results

    results.sort(key=lambda x: x[1], reverse=True)
    return results[:top_n]


def check_disk_hogs(threshold: float = 85.0) -> list[Finding]:
    """Scan mounted filesystems for high usage and identify top space-consuming paths."""
    findings: list[Finding] = []
    partitions = psutil.disk_partitions(all=False)

    for part in partitions:
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue

        if usage.percent >= threshold:
            space_used = format_bytes(usage.used)
            space_total = format_bytes(usage.total)
            evidence_lines = [
                f"Mount point '{part.mountpoint}' on {part.device} is {usage.percent:.1f}% full "
                f"({space_used} used / {space_total} total)."
            ]

            # Look for large items in common problem paths on this partition
            probe_paths = [Path(part.mountpoint) / "var" / "log", Path(part.mountpoint) / "tmp"]
            for probe_path in probe_paths:
                if probe_path.is_dir():
                    hogs = scan_directory_space_hogs(probe_path, max_depth=1, top_n=2)
                    for item_path, item_size in hogs:
                        if item_size > 10 * 1024 * 1024:  # > 10 MB
                            evidence_lines.append(
                                f"• Large item: {item_path} ({format_bytes(item_size)})"
                            )

            findings.append(
                Finding(
                    check_name="disk_hogs",
                    severity=(
                        FindingSeverity.CRITICAL
                        if usage.percent >= 90.0
                        else FindingSeverity.WARNING
                    ),
                    title=f"Filesystem Partition Space Warning on {part.mountpoint}",
                    evidence="\n".join(evidence_lines),
                    probable_cause=(
                        "Unrotated application logs, crash dumps, package cache, or DB growth."
                    ),
                    recommended_fix=(
                        f"Inspect: 'find {part.mountpoint} -xdev -size +500M' and clean "
                        "logs: 'journalctl --vacuum-size=500M'."
                    ),
                )
            )

    return findings


def check_failed_units() -> list[Finding]:
    """Query systemd for currently failed service units using parameterized subprocess."""
    systemctl_bin = shutil.which("systemctl")
    if not systemctl_bin:
        return []

    cmd = [
        systemctl_bin,
        "--failed",
        "--no-legend",
        "--no-pager",
    ]

    try:
        # Parameter-safe execution (Rule 8)
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=4.0,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return []

        evidence = "Failed systemd units detected:\n" + "\n".join(f"• {line}" for line in lines)
        failed_unit_name = lines[0].split()[0] if lines[0].split() else "service"

        return [
            Finding(
                check_name="failed_units",
                severity=FindingSeverity.CRITICAL,
                title=f"{len(lines)} Failed Systemd Unit(s) Detected",
                evidence=evidence,
                probable_cause=(
                    "Service crash, missing dependency, syntax error in unit, or resource bug."
                ),
                recommended_fix=(
                    f"Inspect status: 'systemctl status {failed_unit_name}' and recent logs: "
                    f"'journalctl -xeu {failed_unit_name}'."
                ),
            )
        ]
    except (subprocess.SubprocessError, OSError) as exc:
        logger.warning("Error checking failed systemd units: %s", exc)
        return []


def check_dns_connectivity(
    target_host: str = "dns.google",
    probe_ip: str = "8.8.8.8",
    probe_port: int = 53,
    timeout: float = 3.0,
) -> list[Finding]:
    """Test DNS name resolution and direct outbound network socket connectivity."""
    findings: list[Finding] = []

    # 1. DNS Resolution test
    try:
        resolved_ip = socket.gethostbyname(target_host)
        logger.debug("DNS resolved %s -> %s", target_host, resolved_ip)
    except socket.gaierror as exc:
        findings.append(
            Finding(
                check_name="dns_connectivity",
                severity=FindingSeverity.CRITICAL,
                title=f"DNS Name Resolution Failure for '{target_host}'",
                evidence=f"socket.gethostbyname('{target_host}') failed with: {exc}",
                probable_cause=(
                    "Local DNS resolver is down, nameservers unreachable, or UDP/TCP 53 blocked."
                ),
                recommended_fix=(
                    "Verify '/etc/resolv.conf' and test: 'dig @8.8.8.8 google.com' or restart "
                    "resolver: 'systemctl restart systemd-resolved'."
                ),
            )
        )

    # 2. Direct TCP network connectivity test
    try:
        with socket.create_connection((probe_ip, probe_port), timeout=timeout):
            logger.debug("TCP connection to %s:%d succeeded", probe_ip, probe_port)
    except (OSError, TimeoutError) as exc:
        findings.append(
            Finding(
                check_name="network_connectivity",
                severity=FindingSeverity.CRITICAL,
                title=f"Outbound Network Connectivity Failure to {probe_ip}:{probe_port}",
                evidence=f"TCP connection to {probe_ip}:{probe_port} failed: {exc}",
                probable_cause=(
                    "Default gateway unreachable, network interface down, or egress firewall block."
                ),
                recommended_fix=(
                    "Check 'ip link' and route: 'ip route show'. Check firewall: "
                    "'iptables -L -n -v' or 'nft list ruleset'."
                ),
            )
        )

    return findings


def check_port_in_use(target_ports: list[int] | None = None) -> list[Finding]:
    """Inspect active network listening sockets to identify port bindings and conflicts."""
    findings: list[Finding] = []
    ports_to_inspect = target_ports or [22, 80, 443, 8080, 5432, 3306]

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        logger.debug("psutil.net_connections permission denied or unsupported: %s", exc)
        return []

    active_listeners: dict[int, tuple[str, int | None, str]] = {}
    for conn in connections:
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            port = conn.laddr.port
            if port in ports_to_inspect:
                ip_addr = conn.laddr.ip
                pid = conn.pid
                pname = "unknown"
                if pid:
                    try:
                        pname = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                active_listeners[port] = (ip_addr, pid, pname)

    if active_listeners:
        evidence_lines = ["Active listening services detected on monitored ports:"]
        for port, (ip_addr, pid, pname) in sorted(active_listeners.items()):
            evidence_lines.append(f"• Port {port} ({ip_addr}): bound by PID {pid} ({pname})")

        first_pid = next(iter(active_listeners.values()))[1]
        findings.append(
            Finding(
                check_name="port_in_use",
                severity=FindingSeverity.INFO,
                title=f"Active Listening Sockets on {len(active_listeners)} Monitored Port(s)",
                evidence="\n".join(evidence_lines),
                probable_cause=(
                    "Expected daemon is active or previous instance did not cleanly release socket."
                ),
                recommended_fix=(
                    "Verify with 'ss -tulpn' or stop service: "
                    f"'systemctl stop <service>' or 'kill -15 {first_pid}'."
                ),
            )
        )

    return findings
