"""Unit and integration tests for system health monitoring module."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from rich.console import Console
from typer.testing import CliRunner

from pqsysguard.cli import app
from pqsysguard.config import MonitorConfig
from pqsysguard.monitor.alerts import (
    Alert,
    AlertSeverity,
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
    collect_top_processes,
    collect_uptime,
    query_systemd_service,
)
from pqsysguard.monitor.models import (
    CPUMetrics,
    DiskPartitionMetrics,
    MemoryMetrics,
    NetworkInterfaceMetrics,
    ProcessMetrics,
    ServiceMetrics,
    SystemSnapshot,
)
from pqsysguard.monitor.presenter import (
    display_snapshot,
    format_bytes,
    format_uptime,
    get_color_for_percent,
    render_snapshot_view,
)
from pqsysguard.monitor.storage import export_history, get_history, init_db, save_snapshot


# ---------------------------------------------------------------------------
# Collector Tests
# ---------------------------------------------------------------------------
@patch("psutil.getloadavg", return_value=(1.5, 0.8, 0.5))
@patch("psutil.cpu_count", side_effect=lambda logical: 8 if logical else 4)
@patch(
    "psutil.cpu_percent",
    side_effect=lambda interval, percpu=False: [10.0, 20.0] if percpu else 15.0,
)
def test_collect_cpu(mock_cpu_pct: MagicMock, mock_count: MagicMock, mock_load: MagicMock) -> None:
    """Test CPU metrics collection with mocked psutil."""
    cpu = collect_cpu()
    assert cpu.usage_percent == 15.0
    assert cpu.physical_cores == 4
    assert cpu.logical_cores == 8
    assert cpu.load_avg == (1.5, 0.8, 0.5)
    assert cpu.per_cpu_percent == [10.0, 20.0]


@patch("psutil.swap_memory")
@patch("psutil.virtual_memory")
def test_collect_memory(mock_vm: MagicMock, mock_swap: MagicMock) -> None:
    """Test memory and swap collection."""
    mock_vm.return_value = SimpleNamespace(
        total=16000000000, used=8000000000, free=4000000000, available=8000000000, percent=50.0
    )
    mock_swap.return_value = SimpleNamespace(
        total=4000000000, used=1000000000, free=3000000000, percent=25.0
    )

    mem = collect_memory()
    assert mem.total_bytes == 16000000000
    assert mem.used_bytes == 8000000000
    assert mem.percent == 50.0
    assert mem.swap_total_bytes == 4000000000
    assert mem.swap_percent == 25.0


@patch("psutil.disk_usage")
@patch("psutil.disk_partitions")
def test_collect_disks(mock_partitions: MagicMock, mock_usage: MagicMock) -> None:
    """Test filesystem disk partitions and inode handling."""
    mock_partitions.return_value = [
        SimpleNamespace(device="/dev/sda1", mountpoint="/", fstype="ext4", opts="rw")
    ]
    mock_usage.return_value = SimpleNamespace(
        total=100000000000, used=40000000000, free=60000000000, percent=40.0
    )

    disks = collect_disks()
    assert len(disks) == 1
    assert disks[0].mount_point == "/"
    assert disks[0].percent == 40.0
    assert disks[0].total_bytes == 100000000000


@patch("psutil.net_io_counters")
def test_collect_network(mock_net: MagicMock) -> None:
    """Test network counters collection."""
    net_obj = SimpleNamespace(
        bytes_sent=1024,
        bytes_recv=2048,
        packets_sent=10,
        packets_recv=20,
        errin=0,
        errout=0,
        dropin=0,
        dropout=0,
    )
    mock_net.return_value = {"eth0": net_obj}

    nets = collect_network()
    assert len(nets) == 1
    assert nets[0].interface == "eth0"
    assert nets[0].bytes_sent == 1024
    assert nets[0].bytes_recv == 2048


@patch("psutil.process_iter")
def test_collect_top_processes(mock_proc_iter: MagicMock) -> None:
    """Test top process identification sorted by CPU/Memory."""
    proc1 = MagicMock()
    proc1.info = {
        "pid": 101,
        "name": "python",
        "username": "root",
        "cpu_percent": 12.0,
        "memory_percent": 3.5,
        "status": "running",
        "num_threads": 4,
    }
    proc2 = MagicMock()
    proc2.info = {
        "pid": 102,
        "name": "nginx",
        "username": "www-data",
        "cpu_percent": 45.0,
        "memory_percent": 1.2,
        "status": "sleeping",
        "num_threads": 2,
    }
    mock_proc_iter.return_value = [proc1, proc2]

    procs = collect_top_processes(limit=2)
    assert len(procs) == 2
    # Nginx had 45.0% CPU, so it should rank first
    assert procs[0].pid == 102
    assert procs[0].name == "nginx"


@patch("time.time", return_value=1700000500.0)
@patch("psutil.boot_time", return_value=1700000000.0)
def test_collect_uptime(mock_boot: MagicMock, mock_time: MagicMock) -> None:
    """Test uptime computation."""
    uptime = collect_uptime()
    assert uptime == 500.0


@patch("shutil.which", return_value="/bin/systemctl")
@patch("subprocess.run")
def test_query_systemd_service_active(mock_run: MagicMock, mock_which: MagicMock) -> None:
    """Test active systemd service query."""
    mock_run.return_value = subprocess.CompletedProcess(
        args=["systemctl", "show", "ssh"],
        returncode=0,
        stdout="LoadState=loaded\nActiveState=active\nSubState=running\n",
        stderr="",
    )
    svc = query_systemd_service("ssh")
    assert svc.name == "ssh"
    assert svc.is_active is True
    assert svc.active_state == "active"
    assert svc.load_state == "loaded"


@patch("shutil.which", return_value=None)
def test_query_systemd_service_missing_systemctl(mock_which: MagicMock) -> None:
    """Test graceful handling when systemctl is missing (e.g., non-Linux hosts)."""
    svc = query_systemd_service("ssh")
    assert svc.name == "ssh"
    assert svc.is_active is False
    assert svc.sub_state == "systemctl_not_found"


# ---------------------------------------------------------------------------
# Threshold Evaluation & Alerts Tests
# ---------------------------------------------------------------------------
def _build_dummy_snapshot(
    cpu_pct: float = 10.0,
    mem_pct: float = 20.0,
    swap_pct: float = 5.0,
    disk_pct: float = 30.0,
    inode_pct: float = 10.0,
    svc_active: bool = True,
) -> SystemSnapshot:
    """Helper to build arbitrary system snapshots for threshold testing."""
    return SystemSnapshot(
        uptime_seconds=3600.0,
        cpu=CPUMetrics(
            usage_percent=cpu_pct,
            physical_cores=4,
            logical_cores=8,
            load_avg=(0.5, 0.4, 0.3),
        ),
        memory=MemoryMetrics(
            total_bytes=1000,
            used_bytes=int(mem_pct * 10),
            free_bytes=1000 - int(mem_pct * 10),
            available_bytes=800,
            percent=mem_pct,
            swap_total_bytes=1000,
            swap_used_bytes=int(swap_pct * 10),
            swap_free_bytes=1000 - int(swap_pct * 10),
            swap_percent=swap_pct,
        ),
        disks=[
            DiskPartitionMetrics(
                device="/dev/sda1",
                mount_point="/",
                fstype="ext4",
                total_bytes=1000,
                used_bytes=int(disk_pct * 10),
                free_bytes=1000 - int(disk_pct * 10),
                percent=disk_pct,
                inodes_total=1000,
                inodes_used=int(inode_pct * 10),
                inodes_free=1000 - int(inode_pct * 10),
                inodes_percent=inode_pct,
            )
        ],
        network=[
            NetworkInterfaceMetrics(
                interface="eth0",
                bytes_sent=100,
                bytes_recv=200,
                packets_sent=1,
                packets_recv=2,
                errin=0,
                errout=0,
                dropin=0,
                dropout=0,
            )
        ],
        top_processes=[
            ProcessMetrics(
                pid=1,
                name="systemd",
                username="root",
                cpu_percent=0.1,
                memory_percent=0.1,
                status="sleeping",
                num_threads=1,
            )
        ],
        services=[
            ServiceMetrics(
                name="sshd",
                load_state="loaded",
                active_state="active" if svc_active else "failed",
                sub_state="running" if svc_active else "dead",
                is_active=svc_active,
            )
        ],
    )


def test_evaluate_thresholds_healthy() -> None:
    """Test that a healthy snapshot generates zero alerts."""
    snapshot = _build_dummy_snapshot()
    config = MonitorConfig()
    alerts = evaluate_thresholds(snapshot, config)
    assert len(alerts) == 0


def test_evaluate_thresholds_critical_violations() -> None:
    """Test that metric breaches trigger corresponding critical and warning alerts."""
    snapshot = _build_dummy_snapshot(
        cpu_pct=95.0,  # Critical >= 90
        mem_pct=85.0,  # Warning >= 80
        swap_pct=85.0,  # Critical >= 80
        disk_pct=92.0,  # Critical >= 90
        inode_pct=85.0,  # Warning >= 80
        svc_active=False,  # Critical service failure
    )
    config = MonitorConfig()
    alerts = evaluate_thresholds(snapshot, config)

    # Validate individual alert expectations
    cpu_alerts = [a for a in alerts if a.subsystem == "CPU"]
    assert len(cpu_alerts) == 1
    assert cpu_alerts[0].severity == AlertSeverity.CRITICAL

    mem_alerts = [a for a in alerts if a.subsystem == "Memory"]
    assert len(mem_alerts) == 2  # RAM (Warning) and Swap (Critical)
    severities = {a.severity for a in mem_alerts}
    assert AlertSeverity.WARNING in severities
    assert AlertSeverity.CRITICAL in severities

    disk_alerts = [a for a in alerts if a.subsystem == "Disk"]
    assert len(disk_alerts) == 2  # Space (Critical) and Inode (Warning)
    disk_severities = {a.severity for a in disk_alerts}
    assert AlertSeverity.CRITICAL in disk_severities
    assert AlertSeverity.WARNING in disk_severities

    svc_alerts = [a for a in alerts if a.subsystem == "Services"]
    assert len(svc_alerts) == 1
    assert svc_alerts[0].severity == AlertSeverity.CRITICAL


def test_alerting_hooks_delivery() -> None:
    """Test alert delivery across stdout, logfile, and stub hooks."""
    alert = Alert(
        subsystem="CPU",
        metric="usage_percent",
        current_value=95.0,
        threshold_value=90.0,
        severity=AlertSeverity.CRITICAL,
        message="CPU critical breach",
    )

    mock_console = MagicMock(spec=Console)
    stdout_hook = StdoutAlertHook(console=mock_console)
    stdout_hook.send(alert)
    assert mock_console.print.called

    mock_logger = MagicMock()
    log_hook = LogFileAlertHook(custom_logger=mock_logger)
    log_hook.send(alert)
    assert mock_logger.log.called

    email_stub = EmailAlertHookStub()
    email_stub.send(alert)

    telegram_stub = TelegramAlertHookStub()
    telegram_stub.send(alert)

    # Dispatch list
    dispatch_alerts([alert], [stdout_hook, log_hook])


# ---------------------------------------------------------------------------
# Storage & Export Tests
# ---------------------------------------------------------------------------
def test_storage_sqlite_crud(tmp_path: Path) -> None:
    """Test initializing DB, saving snapshots, querying history, and exporting data."""
    db_file = tmp_path / "test_monitor.db"
    init_db(db_file)

    snapshot = _build_dummy_snapshot()
    snapshot.alerts = [
        Alert(
            subsystem="CPU",
            metric="usage_percent",
            current_value=95.0,
            threshold_value=90.0,
            severity=AlertSeverity.CRITICAL,
            message="Test alert",
        )
    ]

    snapshot_id = save_snapshot(snapshot, db_file)
    assert snapshot_id > 0

    history = get_history(db_file, limit=10)
    assert len(history) == 1
    assert history[0]["cpu_percent"] == 10.0

    # Test JSON export
    json_export = export_history(db_file, export_format="json")
    exported_objs = json.loads(json_export)
    assert len(exported_objs) == 1
    assert exported_objs[0]["id"] == snapshot_id

    # Test CSV export
    csv_export = export_history(db_file, export_format="csv")
    assert "cpu_percent" in csv_export
    assert "10.0" in csv_export


# ---------------------------------------------------------------------------
# Presenter Tests
# ---------------------------------------------------------------------------
def test_presenter_helpers() -> None:
    """Test format_bytes, format_uptime, and color selection."""
    assert format_bytes(500) == "500.0 B"
    assert "KiB" in format_bytes(2048)
    assert "GiB" in format_bytes(1073741824 * 2)

    assert "1h" in format_uptime(3665)
    assert "45s" in format_uptime(45)

    assert get_color_for_percent(10.0, 75.0, 90.0) == "bold green"
    assert get_color_for_percent(80.0, 75.0, 90.0) == "bold yellow"
    assert get_color_for_percent(95.0, 75.0, 90.0) == "bold red"


def test_presenter_render_view() -> None:
    """Test rendering the snapshot view to Rich console without errors."""
    snapshot = _build_dummy_snapshot()
    config = MonitorConfig()
    view = render_snapshot_view(snapshot, config)
    assert view is not None

    mock_console = MagicMock(spec=Console)
    display_snapshot(snapshot, config, console=mock_console)
    assert mock_console.print.called


# ---------------------------------------------------------------------------
# CLI Commands Integration Tests
# ---------------------------------------------------------------------------
def test_cli_monitor_snapshot(runner: CliRunner) -> None:
    """Test pqsysguard monitor snapshot CLI command."""
    result = runner.invoke(app, ["--config", "config/default.yaml", "monitor", "snapshot"])
    assert result.exit_code == 0
    assert "System & Resource Overview" in result.stdout
    assert "Storage & Inode Allocation" in result.stdout
    assert "Top Active Processes" in result.stdout


def test_cli_monitor_export(runner: CliRunner, tmp_path: Path) -> None:
    """Test pqsysguard monitor export CLI command."""
    # First save a snapshot
    runner.invoke(app, ["monitor", "snapshot"])

    # Export as JSON to stdout
    result = runner.invoke(app, ["monitor", "export", "--format", "json", "--limit", "5"])
    assert result.exit_code == 0
    assert "cpu_percent" in result.stdout

    # Export as CSV to file
    out_csv = tmp_path / "metrics.csv"
    res_csv = runner.invoke(
        app,
        ["monitor", "export", "--format", "csv", "--output", str(out_csv)],
    )
    assert res_csv.exit_code == 0
    assert out_csv.is_file()
    assert "cpu_percent" in out_csv.read_text(encoding="utf-8")


def test_cli_monitor_export_invalid_format(runner: CliRunner) -> None:
    """Test pqsysguard monitor export with invalid format."""
    result = runner.invoke(app, ["monitor", "export", "--format", "yaml"])
    assert result.exit_code != 0
    assert "Unsupported format" in result.stdout
