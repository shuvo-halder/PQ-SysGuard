"""Unit and integration tests for the Typer CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from pqsysguard import __version__
from pqsysguard.cli import app


def test_cli_version(runner: CliRunner) -> None:
    """Test CLI version option."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli_help(runner: CliRunner) -> None:
    """Test CLI root help output."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "PQ-SysGuard" in result.stdout
    assert "monitor" in result.stdout
    assert "troubleshoot" in result.stdout
    assert "security" in result.stdout
    assert "vault" in result.stdout


def test_cli_monitor(runner: CliRunner) -> None:
    """Test CLI monitor default command runs snapshot."""
    result = runner.invoke(app, ["monitor"])
    assert result.exit_code == 0
    assert "System & Resource Overview" in result.stdout
    assert "CPU" in result.stdout


def test_cli_troubleshoot(runner: CliRunner) -> None:
    """Test CLI troubleshoot placeholder command."""
    result = runner.invoke(app, ["troubleshoot"])
    assert result.exit_code == 0
    assert "Automated Diagnosis" in result.stdout
    assert "Failed Units" in result.stdout


def test_cli_security_readonly(runner: CliRunner) -> None:
    """Test CLI security command in default read-only mode."""
    result = runner.invoke(app, ["security"])
    assert result.exit_code == 0
    assert "READ-ONLY AUDIT" in result.stdout
    assert "Audit complete" in result.stdout


def test_cli_security_apply(runner: CliRunner) -> None:
    """Test CLI security command with explicit --apply flag."""
    result = runner.invoke(app, ["security", "--apply"])
    assert result.exit_code == 0
    assert "APPLY (Remediation Mode)" in result.stdout
    assert "Remediation flag detected" in result.stdout


def test_cli_vault_keygen(runner: CliRunner, tmp_path: Path) -> None:
    """Test CLI vault keygen placeholder command."""
    key_dir = tmp_path / "keys"
    result = runner.invoke(app, ["vault", "keygen", "--out-dir", str(key_dir)])
    assert result.exit_code == 0
    assert "ML-KEM-768" in result.stdout
    assert "ML-DSA-65" in result.stdout


def test_cli_vault_encrypt(runner: CliRunner, tmp_path: Path) -> None:
    """Test CLI vault encrypt placeholder command."""
    test_file = tmp_path / "secret.txt"
    test_file.write_text("sensitivedata", encoding="utf-8")
    recipient_key = tmp_path / "recip.pub"
    recipient_key.write_text("pubkey", encoding="utf-8")
    signing_key = tmp_path / "sign.priv"
    signing_key.write_text("privkey", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "vault",
            "encrypt",
            str(test_file),
            "--recipient-key",
            str(recipient_key),
            "--signing-key",
            str(signing_key),
        ],
    )
    assert result.exit_code == 0
    assert "Post-Quantum Hybrid Encryption" in result.stdout


def test_cli_vault_decrypt(runner: CliRunner, tmp_path: Path) -> None:
    """Test CLI vault decrypt placeholder command."""
    test_file = tmp_path / "secret.txt.pqe"
    test_file.write_text("encryptedcontent", encoding="utf-8")
    key = tmp_path / "priv.key"
    key.write_text("privkey", encoding="utf-8")
    sender_key = tmp_path / "sender.pub"
    sender_key.write_text("pubkey", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "vault",
            "decrypt",
            str(test_file),
            "--key",
            str(key),
            "--sender-key",
            str(sender_key),
        ],
    )
    assert result.exit_code == 0
    assert "Post-Quantum Decryption" in result.stdout
