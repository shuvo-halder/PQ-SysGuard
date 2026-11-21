"""Threshold evaluation and alerting hooks for system monitoring."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Sequence

from rich.console import Console

from pqsysguard.config import MonitorConfig
from pqsysguard.monitor.models import Alert, AlertSeverity, SystemSnapshot
from pqsysguard.utils.logger import get_logger

logger = get_logger("monitor.alerts")


class AlertHook(ABC):
    """Abstract base class for alert delivery hooks."""

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver a single alert."""
        raise NotImplementedError


class StdoutAlertHook(AlertHook):
    """Terminal standard output alert hook using Rich formatting."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console(stderr=True)

    def send(self, alert: Alert) -> None:
        color = "red" if alert.severity == AlertSeverity.CRITICAL else "yellow"
        self.console.print(
            f"[{color}][ALERT - {alert.severity.value}][/{color}] "
            f"[[bold cyan]{alert.subsystem}[/bold cyan]] {alert.message} "
            f"([dim]Value: {alert.current_value} | Threshold: {alert.threshold_value}[/dim])"
        )


class LogFileAlertHook(AlertHook):
    """Structured audit log alert hook."""

    def __init__(self, custom_logger: logging.Logger | None = None) -> None:
        self.log = custom_logger or logger

    def send(self, alert: Alert) -> None:
        log_level = (
            logging.CRITICAL if alert.severity == AlertSeverity.CRITICAL else logging.WARNING
        )
        self.log.log(
            log_level,
            "Monitoring alert triggered: %s",
            alert.message,
            extra={
                "subsystem": alert.subsystem,
                "metric": alert.metric,
                "current_value": alert.current_value,
                "threshold_value": alert.threshold_value,
                "severity": alert.severity.value,
            },
        )


class EmailAlertHookStub(AlertHook):
    """Future email/SMTP notification hook stub."""

    def __init__(self, recipient: str = "admin@localhost") -> None:
        self.recipient = recipient

    def send(self, alert: Alert) -> None:
        logger.info(
            "[STUB] Email alert would be sent to %s: [%s] %s",
            self.recipient,
            alert.severity.value,
            alert.message,
        )


class TelegramAlertHookStub(AlertHook):
    """Future Telegram bot notification hook stub."""

    def __init__(self, chat_id: str = "@sysguard_alerts") -> None:
        self.chat_id = chat_id

    def send(self, alert: Alert) -> None:
        logger.info(
            "[STUB] Telegram alert would be posted to %s: [%s] %s",
            self.chat_id,
            alert.severity.value,
            alert.message,
        )


def evaluate_thresholds(snapshot: SystemSnapshot, config: MonitorConfig) -> list[Alert]:
    """Check snapshot metrics against configured warning and critical thresholds."""
    alerts: list[Alert] = []

    # 1. CPU Utilization
    cpu_val = snapshot.cpu.usage_percent
    if cpu_val >= config.cpu_critical_percent:
        alerts.append(
            Alert(
                subsystem="CPU",
                metric="usage_percent",
                current_value=cpu_val,
                threshold_value=config.cpu_critical_percent,
                severity=AlertSeverity.CRITICAL,
                message=f"CPU usage critically high ({cpu_val:.1f}%)",
            )
        )
    elif cpu_val >= config.cpu_warning_percent:
        alerts.append(
            Alert(
                subsystem="CPU",
                metric="usage_percent",
                current_value=cpu_val,
                threshold_value=config.cpu_warning_percent,
                severity=AlertSeverity.WARNING,
                message=f"CPU usage warning ({cpu_val:.1f}%)",
            )
        )

    # 2. RAM Utilization
    mem_val = snapshot.memory.percent
    if mem_val >= config.memory_critical_percent:
        alerts.append(
            Alert(
                subsystem="Memory",
                metric="percent",
                current_value=mem_val,
                threshold_value=config.memory_critical_percent,
                severity=AlertSeverity.CRITICAL,
                message=f"RAM usage critically high ({mem_val:.1f}%)",
            )
        )
    elif mem_val >= config.memory_warning_percent:
        alerts.append(
            Alert(
                subsystem="Memory",
                metric="percent",
                current_value=mem_val,
                threshold_value=config.memory_warning_percent,
                severity=AlertSeverity.WARNING,
                message=f"RAM usage warning ({mem_val:.1f}%)",
            )
        )

    # 3. Swap Utilization
    swap_val = snapshot.memory.swap_percent
    if snapshot.memory.swap_total_bytes > 0:
        if swap_val >= config.swap_critical_percent:
            alerts.append(
                Alert(
                    subsystem="Memory",
                    metric="swap_percent",
                    current_value=swap_val,
                    threshold_value=config.swap_critical_percent,
                    severity=AlertSeverity.CRITICAL,
                    message=f"Swap usage critically high ({swap_val:.1f}%)",
                )
            )
        elif swap_val >= config.swap_warning_percent:
            alerts.append(
                Alert(
                    subsystem="Memory",
                    metric="swap_percent",
                    current_value=swap_val,
                    threshold_value=config.swap_warning_percent,
                    severity=AlertSeverity.WARNING,
                    message=f"Swap usage warning ({swap_val:.1f}%)",
                )
            )

    # 4. Disks & Inodes
    for disk in snapshot.disks:
        if disk.percent >= config.disk_critical_percent:
            alerts.append(
                Alert(
                    subsystem="Disk",
                    metric=f"{disk.mount_point}.percent",
                    current_value=disk.percent,
                    threshold_value=config.disk_critical_percent,
                    severity=AlertSeverity.CRITICAL,
                    message=f"Disk space critical on {disk.mount_point} ({disk.percent:.1f}%)",
                )
            )
        elif disk.percent >= config.disk_warning_percent:
            alerts.append(
                Alert(
                    subsystem="Disk",
                    metric=f"{disk.mount_point}.percent",
                    current_value=disk.percent,
                    threshold_value=config.disk_warning_percent,
                    severity=AlertSeverity.WARNING,
                    message=f"Disk space warning on {disk.mount_point} ({disk.percent:.1f}%)",
                )
            )

        # Inode alerts
        if disk.inodes_percent is not None:
            if disk.inodes_percent >= config.inode_critical_percent:
                alerts.append(
                    Alert(
                        subsystem="Disk",
                        metric=f"{disk.mount_point}.inodes_percent",
                        current_value=disk.inodes_percent,
                        threshold_value=config.inode_critical_percent,
                        severity=AlertSeverity.CRITICAL,
                        message=(
                            f"Disk inodes critical on {disk.mount_point} "
                            f"({disk.inodes_percent:.1f}%)"
                        ),
                    )
                )
            elif disk.inodes_percent >= config.inode_warning_percent:
                alerts.append(
                    Alert(
                        subsystem="Disk",
                        metric=f"{disk.mount_point}.inodes_percent",
                        current_value=disk.inodes_percent,
                        threshold_value=config.inode_warning_percent,
                        severity=AlertSeverity.WARNING,
                        message=(
                            f"Disk inodes warning on {disk.mount_point} "
                            f"({disk.inodes_percent:.1f}%)"
                        ),
                    )
                )

    # 5. Services status
    for svc in snapshot.services:
        if svc.active_state in ("failed", "error"):
            alerts.append(
                Alert(
                    subsystem="Services",
                    metric=f"{svc.name}.status",
                    current_value=svc.active_state,
                    threshold_value="active",
                    severity=AlertSeverity.CRITICAL,
                    message=f"Monitored service {svc.name} is {svc.active_state} ({svc.sub_state})",
                )
            )

    return alerts


def dispatch_alerts(alerts: Sequence[Alert], hooks: Sequence[AlertHook]) -> None:
    """Dispatch alerts across all configured hooks."""
    for alert in alerts:
        for hook in hooks:
            try:
                hook.send(alert)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.error("Failed dispatching alert via %s: %s", hook.__class__.__name__, exc)
