"""Command-line interface for PQ-SysGuard.

Provides commands for system monitoring, troubleshooting, security audits,
and post-quantum file encryption using Typer and Rich.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from pqsysguard import __version__
from pqsysguard.config import AppConfig, load_config
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
        console.print(f"[bold cyan]PQ-SysGuard[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main_callback(
    config_file: Annotated[
        Optional[Path],
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
        Optional[str],
        typer.Option(
            "--log-level",
            help="Logging verbosity level (DEBUG, INFO, WARNING, ERROR).",
        ),
    ] = None,
    log_format: Annotated[
        Optional[str],
        typer.Option(
            "--log-format",
            help="Log output format (json or text).",
        ),
    ] = None,
    version: Annotated[
        Optional[bool],
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
    effective_level = log_level or loaded_config.general.log_level
    effective_format = log_format or loaded_config.general.log_format
    setup_logging(level=effective_level, log_format=effective_format)


# ---------------------------------------------------------------------------
# Monitor Subcommands (Placeholder)
# ---------------------------------------------------------------------------
@monitor_app.callback(invoke_without_command=True)
def monitor_default(ctx: typer.Context) -> None:
    """Run an instant health check overview across CPU, Memory, Disk, and Network."""
    if ctx.invoked_subcommand is None:
        console.print(
            Panel.fit(
                "[bold cyan]PQ-SysGuard Monitor[/bold cyan]\n"
                "[dim]Collecting real-time server health metrics...[/dim]",
                border_style="cyan",
            )
        )
        table = Table(title="System Health Overview (Placeholder)")
        table.add_column("Subsystem", style="cyan", no_wrap=True)
        table.add_column("Status", style="green")
        table.add_column("Details", style="magenta")

        table.add_row("CPU", "OK", "Usage: 12.5% across 8 cores")
        table.add_row("Memory", "OK", "Used: 4.2 GB / 16.0 GB (26.2%)")
        table.add_row("Disk", "OK", "Root: 45.1 GB / 250 GB (18.0%)")
        table.add_row("Network", "OK", "RX: 1.2 MB/s | TX: 0.4 MB/s")
        console.print(table)
        console.print("[dim]Use subcommands or watch mode in Phase 2.[/dim]")


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
        mode_label = "[bold red]APPLY (Remediation Mode)[/bold red]" if apply else "[bold green]READ-ONLY AUDIT[/bold green]"
        console.print(
            Panel.fit(
                f"[bold magenta]PQ-SysGuard Security Audit[/bold magenta]\n"
                f"Mode: {mode_label}",
                border_style="magenta",
            )
        )
        table = Table(title="Hardening Audit Results (Placeholder)")
        table.add_column("Control", style="cyan")
        table.add_column("Compliance", style="yellow")
        table.add_column("Finding", style="white")

        table.add_row("SSH Root Login", "WARNING", "PermitRootLogin is enabled in /etc/ssh/sshd_config")
        table.add_row("Shadow File Permissions", "PASS", "/etc/shadow permissions are 0640 or tighter")
        table.add_row("Open Ports", "PASS", "No unauthorized listening services on public interfaces")
        console.print(table)
        if not apply:
            console.print("[dim]Audit complete. Use --apply to enforce automated remediations.[/dim]")
        else:
            console.print("[yellow]Remediation flag detected: Automated fixes will execute here in Phase 4.[/yellow]")


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
            f"Algorithms: [cyan]ML-KEM-768 (Encapsulation)[/cyan] + [cyan]ML-DSA-65 (Signatures)[/cyan]",
            border_style="blue",
        )
    )
    console.print("[dim]Vault implementation active in Phase 5.[/dim]")


@vault_app.command("encrypt")
def vault_encrypt(
    file_path: Annotated[Path, typer.Argument(help="Target file to encrypt.")],
    recipient_key: Annotated[Path, typer.Option("--recipient-key", "-r", help="Recipient ML-KEM public key.")],
    signing_key: Annotated[Path, typer.Option("--signing-key", "-s", help="Sender ML-DSA private key.")],
    output_path: Annotated[Optional[Path], typer.Option("--out", "-o", help="Output file path.")] = None,
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
    sender_key: Annotated[Path, typer.Option("--sender-key", "-s", help="Sender ML-DSA public key.")],
    output_path: Annotated[Optional[Path], typer.Option("--out", "-o", help="Decrypted output file path.")] = None,
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
