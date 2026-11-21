"""Health monitoring module for PQ-SysGuard.

Provides real-time system telemetry, threshold monitoring, alerting hooks,
and time-series SQLite persistence.
"""

from pqsysguard.monitor.alerts import (
    AlertHook,
    EmailAlertHookStub,
    LogFileAlertHook,
    StdoutAlertHook,
    TelegramAlertHookStub,
    dispatch_alerts,
    evaluate_thresholds,
)
from pqsysguard.monitor.collector import (
    collect_cpu,
    collect_disks,
    collect_memory,
    collect_network,
    collect_services,
    collect_snapshot,
    collect_top_processes,
    collect_uptime,
)
from pqsysguard.monitor.models import (
    Alert,
    AlertSeverity,
    CPUMetrics,
    DiskPartitionMetrics,
    MemoryMetrics,
    NetworkInterfaceMetrics,
    ProcessMetrics,
    ServiceMetrics,
    SystemSnapshot,
)
from pqsysguard.monitor.presenter import display_snapshot, render_snapshot_view
from pqsysguard.monitor.storage import export_history, get_history, init_db, save_snapshot

__all__ = [
    "Alert",
    "AlertHook",
    "AlertSeverity",
    "CPUMetrics",
    "DiskPartitionMetrics",
    "EmailAlertHookStub",
    "LogFileAlertHook",
    "MemoryMetrics",
    "NetworkInterfaceMetrics",
    "ProcessMetrics",
    "ServiceMetrics",
    "StdoutAlertHook",
    "SystemSnapshot",
    "TelegramAlertHookStub",
    "collect_cpu",
    "collect_disks",
    "collect_memory",
    "collect_network",
    "collect_services",
    "collect_snapshot",
    "collect_top_processes",
    "collect_uptime",
    "dispatch_alerts",
    "display_snapshot",
    "evaluate_thresholds",
    "export_history",
    "get_history",
    "init_db",
    "render_snapshot_view",
    "save_snapshot",
]
