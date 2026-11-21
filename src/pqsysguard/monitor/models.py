"""Data models for system health telemetry and monitoring."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AlertSeverity(StrEnum):
    """Alert severity levels."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Alert(BaseModel):
    """System health threshold violation or incident."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    subsystem: str
    metric: str
    current_value: float | str
    threshold_value: float | str
    severity: AlertSeverity
    message: str


class CPUMetrics(BaseModel):
    """CPU telemetry data."""

    usage_percent: float
    physical_cores: int
    logical_cores: int
    load_avg: tuple[float, float, float]
    per_cpu_percent: list[float] = Field(default_factory=list)


class MemoryMetrics(BaseModel):
    """RAM and Swap utilization data."""

    total_bytes: int
    used_bytes: int
    free_bytes: int
    available_bytes: int
    percent: float
    swap_total_bytes: int
    swap_used_bytes: int
    swap_free_bytes: int
    swap_percent: float


class DiskPartitionMetrics(BaseModel):
    """Filesystem mount point utilization and inode status."""

    device: str
    mount_point: str
    fstype: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent: float
    inodes_total: int | None = None
    inodes_used: int | None = None
    inodes_free: int | None = None
    inodes_percent: float | None = None


class NetworkInterfaceMetrics(BaseModel):
    """Network I/O counter data."""

    interface: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errin: int
    errout: int
    dropin: int
    dropout: int


class ProcessMetrics(BaseModel):
    """Process resource utilization entry."""

    pid: int
    name: str
    username: str
    cpu_percent: float
    memory_percent: float
    status: str
    num_threads: int


class ServiceMetrics(BaseModel):
    """Systemd service status entry."""

    name: str
    load_state: str
    active_state: str
    sub_state: str
    is_active: bool


class SystemSnapshot(BaseModel):
    """Point-in-time complete system health snapshot."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    uptime_seconds: float
    cpu: CPUMetrics
    memory: MemoryMetrics
    disks: list[DiskPartitionMetrics]
    network: list[NetworkInterfaceMetrics]
    top_processes: list[ProcessMetrics]
    services: list[ServiceMetrics]
    alerts: list[Alert] = Field(default_factory=list)

    def to_summary_dict(self) -> dict[str, Any]:
        """Convert snapshot to summary dictionary suitable for tabular serialization."""
        max_disk_pct = max((d.percent for d in self.disks), default=0.0)
        max_inode_pct = max(
            (d.inodes_percent for d in self.disks if d.inodes_percent is not None), default=0.0
        )
        total_net_sent = sum(n.bytes_sent for n in self.network)
        total_net_recv = sum(n.bytes_recv for n in self.network)

        return {
            "timestamp": self.timestamp.isoformat(),
            "uptime_seconds": round(self.uptime_seconds, 1),
            "cpu_percent": self.cpu.usage_percent,
            "load_1m": self.cpu.load_avg[0],
            "load_5m": self.cpu.load_avg[1],
            "load_15m": self.cpu.load_avg[2],
            "memory_percent": self.memory.percent,
            "swap_percent": self.memory.swap_percent,
            "max_disk_percent": max_disk_pct,
            "max_inode_percent": max_inode_pct,
            "net_bytes_sent": total_net_sent,
            "net_bytes_recv": total_net_recv,
            "active_alerts_count": len(self.alerts),
        }
