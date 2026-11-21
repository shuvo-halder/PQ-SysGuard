"""System health telemetry collector using psutil and systemd queries."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Sequence

import psutil

from pqsysguard.monitor.models import (
    CPUMetrics,
    DiskPartitionMetrics,
    MemoryMetrics,
    NetworkInterfaceMetrics,
    ProcessMetrics,
    ServiceMetrics,
    SystemSnapshot,
)
from pqsysguard.utils.logger import get_logger

logger = get_logger("monitor.collector")


def collect_cpu() -> CPUMetrics:
    """Collect CPU utilization, core counts, and load averages."""
    # psutil.cpu_percent with interval=None returns instantaneous value since last call
    usage = psutil.cpu_percent(interval=None)
    per_cpu = psutil.cpu_percent(interval=None, percpu=True)
    logical_cores = psutil.cpu_count(logical=True) or 1
    physical_cores = psutil.cpu_count(logical=False) or logical_cores

    # Load average (1m, 5m, 15m) - POSIX only, fallback on Windows
    load_avg: tuple[float, float, float] = (0.0, 0.0, 0.0)
    psutil_getloadavg = getattr(psutil, "getloadavg", None)
    if callable(psutil_getloadavg):
        try:
            raw_load = psutil_getloadavg()
            load_avg = (float(raw_load[0]), float(raw_load[1]), float(raw_load[2]))
        except (AttributeError, OSError):
            pass
    elif hasattr(os, "getloadavg"):
        try:
            load_avg = os.getloadavg()
        except (AttributeError, OSError):
            pass

    return CPUMetrics(
        usage_percent=usage,
        physical_cores=physical_cores,
        logical_cores=logical_cores,
        load_avg=load_avg,
        per_cpu_percent=per_cpu,
    )


def collect_memory() -> MemoryMetrics:
    """Collect virtual memory and swap utilization."""
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return MemoryMetrics(
        total_bytes=vm.total,
        used_bytes=vm.used,
        free_bytes=vm.free,
        available_bytes=vm.available,
        percent=vm.percent,
        swap_total_bytes=swap.total,
        swap_used_bytes=swap.used,
        swap_free_bytes=swap.free,
        swap_percent=swap.percent,
    )


def collect_disks() -> list[DiskPartitionMetrics]:
    """Collect filesystem disk capacity and inode allocation per mount point."""
    partitions = psutil.disk_partitions(all=False)
    results: list[DiskPartitionMetrics] = []
    seen_mounts: set[str] = set()

    for part in partitions:
        if part.mountpoint in seen_mounts:
            continue
        seen_mounts.add(part.mountpoint)

        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError) as exc:
            logger.debug("Failed reading disk usage for %s: %s", part.mountpoint, exc)
            continue

        # Inode metrics via os.statvfs (Linux / Unix)
        inodes_total: int | None = None
        inodes_used: int | None = None
        inodes_free: int | None = None
        inodes_percent: float | None = None

        if hasattr(os, "statvfs"):
            try:
                st = os.statvfs(part.mountpoint)
                inodes_total = st.f_files
                inodes_free = st.f_ffree
                if inodes_total > 0:
                    inodes_used = inodes_total - inodes_free
                    inodes_percent = round((inodes_used / inodes_total) * 100.0, 2)
            except (OSError, PermissionError) as exc:
                logger.debug("statvfs error for %s: %s", part.mountpoint, exc)

        results.append(
            DiskPartitionMetrics(
                device=part.device,
                mount_point=part.mountpoint,
                fstype=part.fstype,
                total_bytes=usage.total,
                used_bytes=usage.used,
                free_bytes=usage.free,
                percent=usage.percent,
                inodes_total=inodes_total,
                inodes_used=inodes_used,
                inodes_free=inodes_free,
                inodes_percent=inodes_percent,
            )
        )

    return results


def collect_network() -> list[NetworkInterfaceMetrics]:
    """Collect per-interface network throughput and packet error counters."""
    net_io = psutil.net_io_counters(pernic=True)
    results: list[NetworkInterfaceMetrics] = []

    for iface_name, stats in net_io.items():
        results.append(
            NetworkInterfaceMetrics(
                interface=iface_name,
                bytes_sent=stats.bytes_sent,
                bytes_recv=stats.bytes_recv,
                packets_sent=stats.packets_sent,
                packets_recv=stats.packets_recv,
                errin=stats.errin,
                errout=stats.errout,
                dropin=stats.dropin,
                dropout=stats.dropout,
            )
        )

    return results


def collect_top_processes(limit: int = 5) -> list[ProcessMetrics]:
    """Identify top processes sorted by CPU and memory consumption."""
    procs: list[ProcessMetrics] = []

    for proc in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent", "status", "num_threads"]
    ):
        try:
            info = proc.info
            procs.append(
                ProcessMetrics(
                    pid=info["pid"],
                    name=info["name"] or "unknown",
                    username=info["username"] or "unknown",
                    cpu_percent=info["cpu_percent"] or 0.0,
                    memory_percent=round(info["memory_percent"] or 0.0, 2),
                    status=info["status"] or "unknown",
                    num_threads=info["num_threads"] or 1,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort primarily by CPU % descending, then Memory % descending
    procs.sort(key=lambda p: (p.cpu_percent, p.memory_percent), reverse=True)
    return procs[:limit]


def collect_uptime() -> float:
    """Calculate system uptime in seconds."""
    boot_time = psutil.boot_time()
    return max(0.0, time.time() - boot_time)


def query_systemd_service(service_name: str) -> ServiceMetrics:
    """Query a single systemd service status via parameter-safe subprocess execution."""
    systemctl_path = shutil.which("systemctl")
    if not systemctl_path:
        return ServiceMetrics(
            name=service_name,
            load_state="unknown",
            active_state="unknown",
            sub_state="systemctl_not_found",
            is_active=False,
        )

    # Safe subprocess execution: non-negotiable rule 8
    try:
        cmd = [
            systemctl_path,
            "show",
            service_name,
            "--no-page",
            "--property=LoadState,ActiveState,SubState",
        ]
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )

        props: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()

        load_state = props.get("LoadState", "unknown")
        active_state = props.get("ActiveState", "unknown")
        sub_state = props.get("SubState", "unknown")
        is_active = active_state == "active"

        return ServiceMetrics(
            name=service_name,
            load_state=load_state,
            active_state=active_state,
            sub_state=sub_state,
            is_active=is_active,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.warning("Error querying service %s: %s", service_name, exc)
        return ServiceMetrics(
            name=service_name,
            load_state="unknown",
            active_state="error",
            sub_state=str(exc),
            is_active=False,
        )


def collect_services(services: Sequence[str]) -> list[ServiceMetrics]:
    """Collect service status for specified list of services."""
    return [query_systemd_service(svc) for svc in services]


def collect_snapshot(monitored_services: Sequence[str] | None = None) -> SystemSnapshot:
    """Take a full system telemetry snapshot."""
    services_to_check = monitored_services or ["ssh", "sshd", "systemd-journald", "cron"]

    return SystemSnapshot(
        uptime_seconds=collect_uptime(),
        cpu=collect_cpu(),
        memory=collect_memory(),
        disks=collect_disks(),
        network=collect_network(),
        top_processes=collect_top_processes(),
        services=collect_services(services_to_check),
    )
