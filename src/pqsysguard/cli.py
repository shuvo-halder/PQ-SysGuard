"""Command-line interface for PQ-SysGuard.

Provides commands for system monitoring, troubleshooting, security audits,
and post-quantum file encryption using Typer and Rich.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from pqsysguard import __version__
from pqsysguard.config import AppConfig, load_config
from pqsysguard.monitor import (
    LogFileAlertHook,
    StdoutAlertHook,
    collect_snapshot,
    dispatch_alerts,
    display_snapshot,
    evaluate_thresholds,
    export_history,
    render_snapshot_view,
    save_snapshot,
)
from pqsysguard.utils.logger import get_logger, setup_logging

console = Console()
logger = get_logger("cli")

app = typer.Typer(
    name="pqsysguard",
    help="PQ-SysGuard: Linux system-administration toolkit with post-quantum security hardening.",
    add_completion=False,
)

# Sub-command groups
monitor_app = typer.Typer(help="Server health monitoring (CPU, RAM, disk, network, processes).")
troubleshoot_app = typer.Typer(help="Automated system diagnosis and log triage.")
security_app = typer.Typer(help="Security hardening audit and compliance verification.")
vault_app = typer.Typer(help="Post-quantum cryptographic file vault (ML-KEM-768 + ML-DSA-65).")

app.add_typer(monitor_app, name="monitor")
app.add_typer(troubleshoot_app, name="troubleshoot")
app.add_typer(security_app, name="security")
app.add_typer(vault_app, name="vault")


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(
            f"[bold cyan]PQ-SysGuard[/bold cyan] version [bold green]{__version__}[/bold green]"
        )
        raise typer.Exit()


@app.callback()
def main_callback(
    ctx: typer.Context,
    config_file: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to YAML configuration file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    log_level: Annotated[
        str | None,
        typer.Option(
            "--log-level",
            help="Logging verbosity level (DEBUG, INFO, WARNING, ERROR).",
        ),
    ] = None,
    log_format: Annotated[
        str | None,
        typer.Option(
            "--log-format",
            help="Log output format (json or text).",
        ),
    ] = None,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Initialize configuration and structured logging."""
    loaded_config = load_config(config_file)
    ctx.obj = loaded_config
    effective_level = log_level or loaded_config.general.log_level
    effective_format = log_format or loaded_config.general.log_format
    setup_logging(level=effective_level, log_format=effective_format)


def _get_app_config(ctx: typer.Context) -> AppConfig:
    """Retrieve AppConfig from context or load default."""
    if isinstance(ctx.obj, AppConfig):
        return ctx.obj
    return load_config()


# ---------------------------------------------------------------------------
# Monitor Subcommands
# ---------------------------------------------------------------------------
@monitor_app.callback(invoke_without_command=True)
def monitor_default(ctx: typer.Context) -> None:
    """Server health monitoring (CPU, RAM, disk, network, processes, services)."""
    if ctx.invoked_subcommand is None:
        monitor_snapshot(ctx)


@monitor_app.command("snapshot")
def monitor_snapshot(ctx: typer.Context) -> None:
    """Collect a single health snapshot, evaluate thresholds, and persist to SQLite."""
    app_config = _get_app_config(ctx)
    mon_config = app_config.monitor

    # 1. Collect telemetry
    snapshot = collect_snapshot(monitored_services=mon_config.monitored_services)

    # 2. Evaluate thresholds
    alerts = evaluate_thresholds(snapshot, mon_config)
    snapshot.alerts = alerts

    # 3. Deliver alerts via hooks
    hooks = [StdoutAlertHook(console=console), LogFileAlertHook(custom_logger=logger)]
    dispatch_alerts(alerts, hooks)

    # 4. Save to SQLite database
    db_path = app_config.database.path
    snapshot_id = save_snapshot(snapshot, db_path)
    logger.debug("Saved telemetry snapshot #%d to %s", snapshot_id, db_path)

    # 5. Display Rich output
    display_snapshot(snapshot, mon_config, console=console)


@monitor_app.command("watch")
def monitor_watch(
    ctx: typer.Context,
    interval: Annotated[
        int,
        typer.Option(
            "--interval",
            "-i",
            help="Refresh interval in seconds.",
            min=1,
        ),
    ] = 5,
) -> None:
    """Live interactive terminal dashboard refreshing every interval seconds."""
    app_config = _get_app_config(ctx)
    mon_config = app_config.monitor
    db_path = app_config.database.path
    hooks = [LogFileAlertHook(custom_logger=logger)]

    console.print(
        f"[dim]Starting PQ-SysGuard Monitor Watch mode (interval: {interval}s). "
        "Press Ctrl+C to exit.[/dim]"
    )

    try:
        # Initial snapshot
        initial_snapshot = collect_snapshot(monitored_services=mon_config.monitored_services)
        initial_snapshot.alerts = evaluate_thresholds(initial_snapshot, mon_config)
        save_snapshot(initial_snapshot, db_path)

        with Live(
            render_snapshot_view(initial_snapshot, mon_config),
            console=console,
            refresh_per_second=2,
            screen=False,
        ) as live:
            while True:
                time.sleep(interval)
                snap = collect_snapshot(monitored_services=mon_config.monitored_services)
                snap.alerts = evaluate_thresholds(snap, mon_config)
                dispatch_alerts(snap.alerts, hooks)
                save_snapshot(snap, db_path)
                live.update(render_snapshot_view(snap, mon_config))
    except KeyboardInterrupt:
        console.print("\n[yellow]Watch mode stopped by operator.[/yellow]")


@monitor_app.command("export")
def monitor_export(
    ctx: typer.Context,
    export_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Export format: json or csv.",
        ),
    ] = "json",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Path to file to write export output.",
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            "-n",
            help="Maximum snapshot records to retrieve.",
            min=1,
        ),
    ] = 100,
) -> None:
    """Export historical telemetry snapshots from SQLite as JSON or CSV."""
    if export_format.lower() not in ("json", "csv"):
        console.print(
            f"[bold red]Error:[/bold red] Unsupported format '{export_format}'. "
            "Supported formats: json, csv."
        )
        raise typer.Exit(code=1)

    app_config = _get_app_config(ctx)
    db_path = app_config.database.path

    exported_data = export_history(db_path, export_format=export_format.lower(), limit=limit)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(exported_data, encoding="utf-8")
        console.print(
            f"[green]Successfully exported {limit} snapshot records to [bold]{output}[/bold] "
            f"({export_format.upper()}).[/green]"
        )
    else:
        # Output directly to stdout
        print(exported_data)


# ---------------------------------------------------------------------------
# Troubleshoot Subcommands (Placeholder)
# ---------------------------------------------------------------------------
@troubleshoot_app.callback(invoke_without_command=True)
def troubleshoot_default(ctx: typer.Context) -> None:
    """Analyze system logs and identify failing services or resource bottlenecks."""
    if ctx.invoked_subcommand is None:
        console.print(
            Panel.fit(
                "[bold yellow]PQ-SysGuard Troubleshooter[/bold yellow]\n"
                "[dim]Scanning system logs and service statuses...[/dim]",
                border_style="yellow",
            )
        )
        table = Table(title="Automated Diagnosis (Placeholder)")
        table.add_column("Check", style="yellow")
        table.add_column("Result", style="green")
        table.add_column("Recommendation", style="white")

        table.add_row("Failed Units (systemd)", "PASSED", "No active failed units found")
        table.add_row("OOM Killer Events", "PASSED", "No Out-Of-Memory events in journal")
        table.add_row("Disk Inodes", "PASSED", "All mounted filesystems have > 50% free inodes")
        console.print(table)
        console.print("[dim]Diagnostic rules engine will be implemented in Phase 3.[/dim]")


# ---------------------------------------------------------------------------
# Security Subcommands (Placeholder)
# ---------------------------------------------------------------------------
@security_app.callback(invoke_without_command=True)
def security_default(
    ctx: typer.Context,
    apply: Annotated[
        bool,
        typer.Option(
            "--apply",
            help="Apply remediation steps. Read-only audit by default.",
        ),
    ] = False,
) -> None:
    """Run security hardening checks. Read-only by default; --apply required for fixes."""
    if ctx.invoked_subcommand is None:
        mode_label = (
            "[bold red]APPLY (Remediation Mode)[/bold red]"
            if apply
            else "[bold green]READ-ONLY AUDIT[/bold green]"
        )
        console.print(
            Panel.fit(
                f"[bold magenta]PQ-SysGuard Security Audit[/bold magenta]\nMode: {mode_label}",
                border_style="magenta",
            )
        )
        table = Table(title="Hardening Audit Results (Placeholder)")
        table.add_column("Control", style="cyan")
        table.add_column("Compliance", style="yellow")
        table.add_column("Finding", style="white")

        table.add_row(
            "SSH Root Login", "WARNING", "PermitRootLogin is enabled in /etc/ssh/sshd_config"
        )
        table.add_row(
            "Shadow File Permissions", "PASS", "/etc/shadow permissions are 0640 or tighter"
        )
        table.add_row(
            "Open Ports", "PASS", "No unauthorized listening services on public interfaces"
        )
        console.print(table)
        if not apply:
            console.print(
                "[dim]Audit complete. Use --apply to enforce automated remediations.[/dim]"
            )
        else:
            console.print(
                "[yellow]Remediation flag detected: Automated fixes execute in Phase 4.[/yellow]"
            )


# ---------------------------------------------------------------------------
# Vault Subcommands (Placeholder)
# ---------------------------------------------------------------------------
@vault_app.command("keygen")
def vault_keygen(
    out_dir: Annotated[
        Path,
        typer.Option("--out-dir", "-o", help="Directory to save generated keypairs."),
    ] = Path("keys"),
) -> None:
    """Generate post-quantum ML-KEM-768 and ML-DSA-65 key pairs."""
    console.print(
        Panel.fit(
            f"[bold blue]Post-Quantum Key Generation[/bold blue]\n"
            f"Target directory: [yellow]{out_dir}[/yellow]\n"
            "Algorithms: [cyan]ML-KEM-768[/cyan] + [cyan]ML-DSA-65[/cyan]",
            border_style="blue",
        )
    )
    console.print("[dim]Vault implementation active in Phase 5.[/dim]")


@vault_app.command("encrypt")
def vault_encrypt(
    file_path: Annotated[Path, typer.Argument(help="Target file to encrypt.")],
    recipient_key: Annotated[
        Path, typer.Option("--recipient-key", "-r", help="Recipient ML-KEM public key.")
    ],
    signing_key: Annotated[
        Path, typer.Option("--signing-key", "-s", help="Sender ML-DSA private key.")
    ],
    output_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file path.")
    ] = None,
) -> None:
    """Encrypt a file with hybrid AES-256-GCM + ML-KEM-768 and sign with ML-DSA-65."""
    target_out = output_path or file_path.with_suffix(file_path.suffix + ".pqe")
    console.print(
        Panel.fit(
            f"[bold blue]Post-Quantum Hybrid Encryption[/bold blue]\n"
            f"Input: [yellow]{file_path}[/yellow] -> Output: [yellow]{target_out}[/yellow]\n"
            f"Recipient: {recipient_key}\n"
            f"Signer: {signing_key}",
            border_style="blue",
        )
    )
    console.print("[dim]Vault implementation active in Phase 5.[/dim]")


@vault_app.command("decrypt")
def vault_decrypt(
    file_path: Annotated[Path, typer.Argument(help="Encrypted file (.pqe) to decrypt.")],
    private_key: Annotated[Path, typer.Option("--key", "-k", help="Recipient ML-KEM private key.")],
    sender_key: Annotated[
        Path, typer.Option("--sender-key", "-s", help="Sender ML-DSA public key.")
    ],
    output_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Decrypted output file path.")
    ] = None,
) -> None:
    """Decrypt and verify signature of a post-quantum encrypted package."""
    console.print(
        Panel.fit(
            f"[bold blue]Post-Quantum Decryption & Verification[/bold blue]\n"
            f"File: [yellow]{file_path}[/yellow]\n"
            f"Key: {private_key}\n"
            f"Sender Verification Key: {sender_key}",
            border_style="blue",
        )
    )
    console.print("[dim]Vault implementation active in Phase 5.[/dim]")


def main() -> None:
    """Entry point for CLI execution."""
    app()


if __name__ == "__main__":
    main()
