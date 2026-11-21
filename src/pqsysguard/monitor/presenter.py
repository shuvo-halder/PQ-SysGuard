"""Rich terminal presenter for monitoring snapshots and live watch mode."""

from __future__ import annotations

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table

from pqsysguard.config import MonitorConfig
from pqsysguard.monitor.models import AlertSeverity, SystemSnapshot


def format_bytes(num_bytes: int | float) -> str:
    """Format bytes into human-readable units (B, KiB, MiB, GiB, TiB)."""
    val = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(val) < 1024.0:
            return f"{val:3.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} PiB"


def format_uptime(seconds: float) -> str:
    """Format uptime seconds into a human-readable string."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    parts: list[str] = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m {secs}s")
    return " ".join(parts)


def get_color_for_percent(value: float, warning_th: float, critical_th: float) -> str:
    """Determine Rich color code based on threshold tiers."""
    if value >= critical_th:
        return "bold red"
    if value >= warning_th:
        return "bold yellow"
    return "bold green"


def build_system_overview_table(snapshot: SystemSnapshot, config: MonitorConfig) -> Table:
    """Construct Rich table for CPU, Memory, Swap, and Uptime."""
    table = Table(title="System & Resource Overview", expand=True)
    table.add_column("Subsystem", style="cyan", no_wrap=True)
    table.add_column("Utilization", style="white")
    table.add_column("Capacity / Allocation", style="magenta")
    table.add_column("Health Status", justify="center")

    # CPU
    cpu_pct = snapshot.cpu.usage_percent
    cpu_color = get_color_for_percent(
        cpu_pct, config.cpu_warning_percent, config.cpu_critical_percent
    )
    load = snapshot.cpu.load_avg
    load_str = f"Load avg: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}"
    cores_str = f"{snapshot.cpu.logical_cores} logical ({snapshot.cpu.physical_cores} physical)"
    table.add_row(
        "CPU",
        f"[{cpu_color}]{cpu_pct:5.1f}%[/{cpu_color}]",
        f"{cores_str} | {load_str}",
        f"[{cpu_color}]●[/{cpu_color}]",
    )

    # Memory
    mem = snapshot.memory
    mem_color = get_color_for_percent(
        mem.percent, config.memory_warning_percent, config.memory_critical_percent
    )
    used_str = format_bytes(mem.used_bytes)
    total_str = format_bytes(mem.total_bytes)
    avail_str = format_bytes(mem.available_bytes)
    mem_detail = f"{used_str} / {total_str} (avail: {avail_str})"
    table.add_row(
        "Memory (RAM)",
        f"[{mem_color}]{mem.percent:5.1f}%[/{mem_color}]",
        mem_detail,
        f"[{mem_color}]●[/{mem_color}]",
    )

    # Swap
    swap_color = get_color_for_percent(
        mem.swap_percent, config.swap_warning_percent, config.swap_critical_percent
    )
    swap_detail = f"{format_bytes(mem.swap_used_bytes)} / {format_bytes(mem.swap_total_bytes)}"
    table.add_row(
        "Swap",
        f"[{swap_color}]{mem.swap_percent:5.1f}%[/{swap_color}]",
        swap_detail,
        f"[{swap_color}]●[/{swap_color}]",
    )

    # Uptime
    table.add_row(
        "Uptime",
        format_uptime(snapshot.uptime_seconds),
        f"Sampled at: {snapshot.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "[green]●[/green]",
    )

    return table


def build_disks_table(snapshot: SystemSnapshot, config: MonitorConfig) -> Table:
    """Construct Rich table for mounted filesystem partitions and inodes."""
    table = Table(title="Storage & Inode Allocation", expand=True)
    table.add_column("Mount Point", style="cyan")
    table.add_column("Device", style="dim")
    table.add_column("FS", style="white")
    table.add_column("Disk Space", justify="right")
    table.add_column("Disk %", justify="right")
    table.add_column("Inodes", justify="right")
    table.add_column("Inode %", justify="right")

    for disk in snapshot.disks:
        disk_color = get_color_for_percent(
            disk.percent, config.disk_warning_percent, config.disk_critical_percent
        )
        space_str = f"{format_bytes(disk.used_bytes)} / {format_bytes(disk.total_bytes)}"

        if disk.inodes_total and disk.inodes_used is not None:
            inode_color = get_color_for_percent(
                disk.inodes_percent or 0.0,
                config.inode_warning_percent,
                config.inode_critical_percent,
            )
            inode_str = f"{disk.inodes_used:,} / {disk.inodes_total:,}"
            inode_pct_str = f"[{inode_color}]{disk.inodes_percent:5.1f}%[/{inode_color}]"
        else:
            inode_str = "N/A"
            inode_pct_str = "[dim]N/A[/dim]"

        table.add_row(
            disk.mount_point,
            disk.device,
            disk.fstype,
            space_str,
            f"[{disk_color}]{disk.percent:5.1f}%[/{disk_color}]",
            inode_str,
            inode_pct_str,
        )

    return table


def build_processes_table(snapshot: SystemSnapshot) -> Table:
    """Construct Rich table for top consuming processes."""
    table = Table(title="Top Active Processes", expand=True)
    table.add_column("PID", style="cyan", justify="right")
    table.add_column("Command / Name", style="white")
    table.add_column("User", style="magenta")
    table.add_column("CPU %", justify="right")
    table.add_column("RAM %", justify="right")
    table.add_column("Threads", justify="right")
    table.add_column("State", justify="center")

    for p in snapshot.top_processes:
        table.add_row(
            str(p.pid),
            p.name,
            p.username,
            f"{p.cpu_percent:5.1f}%",
            f"{p.memory_percent:5.1f}%",
            str(p.num_threads),
            p.status,
        )

    return table


def build_services_table(snapshot: SystemSnapshot) -> Table:
    """Construct Rich table for systemd monitored services."""
    table = Table(title="Systemd Monitored Services", expand=True)
    table.add_column("Service Unit", style="cyan")
    table.add_column("Load State", style="dim")
    table.add_column("Active State", style="white")
    table.add_column("Sub State", style="dim")
    table.add_column("Status", justify="center")

    for svc in snapshot.services:
        if svc.is_active:
            status_badge = "[bold green]ACTIVE[/bold green]"
        elif svc.active_state in ("failed", "error"):
            status_badge = "[bold red]FAILED[/bold red]"
        else:
            status_badge = f"[yellow]{svc.active_state.upper()}[/yellow]"

        table.add_row(
            svc.name,
            svc.load_state,
            svc.active_state,
            svc.sub_state,
            status_badge,
        )

    return table


def build_alerts_panel(snapshot: SystemSnapshot) -> Panel | None:
    """Construct alert summary panel if any alerts triggered."""
    if not snapshot.alerts:
        return None

    lines: list[str] = []
    for a in snapshot.alerts:
        tag_color = "red" if a.severity == AlertSeverity.CRITICAL else "yellow"
        lines.append(
            f"[{tag_color}][{a.severity.value}][/{tag_color}] "
            f"[bold]{a.subsystem}:[/bold] {a.message}"
        )

    return Panel(
        "\n".join(lines),
        title=f"[bold red]Active Incidents ({len(snapshot.alerts)})[/bold red]",
        border_style="red",
    )


def render_snapshot_view(snapshot: SystemSnapshot, config: MonitorConfig) -> RenderableType:
    """Render a comprehensive composite view of the system snapshot."""
    renderables: list[RenderableType] = []

    alerts_panel = build_alerts_panel(snapshot)
    if alerts_panel:
        renderables.append(alerts_panel)

    renderables.append(build_system_overview_table(snapshot, config))
    renderables.append(build_disks_table(snapshot, config))
    renderables.append(build_processes_table(snapshot))
    renderables.append(build_services_table(snapshot))

    return Group(*renderables)


def display_snapshot(
    snapshot: SystemSnapshot, config: MonitorConfig, console: Console | None = None
) -> None:
    """Print the complete snapshot to the Rich console."""
    out_console = console or Console()
    view = render_snapshot_view(snapshot, config)
    out_console.print(view)
