"""Global pytest fixtures and test configuration for PQ-SysGuard."""

import os
from collections.abc import Generator
from pathlib import Path

import pytest
from typer.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    """Fixture providing a Typer CLI runner for command testing."""
    return CliRunner()


@pytest.fixture
def temp_config_yaml(tmp_path: Path) -> Path:
    """Fixture creating a temporary valid YAML config file."""
    config_file = tmp_path / "custom_config.yaml"
    content = """
general:
  app_name: "test-sysguard"
  environment: "testing"
  log_level: "DEBUG"
  log_format: "text"

database:
  path: "test.db"

monitor:
  interval_seconds: 2
  cpu_warning_percent: 75.0
  cpu_critical_percent: 90.0
  memory_warning_percent: 80.0
  memory_critical_percent: 90.0
  disk_warning_percent: 85.0
  disk_critical_percent: 95.0

troubleshoot:
  journal_log_lines: 50
  failed_units_check: false

security:
  ssh_config_path: "/custom/sshd_config"
  check_root_login: false
  check_password_auth: false
  check_open_ports: true
  check_file_permissions: false
  sensitive_files:
    - "/custom/secret"

vault:
  default_chunk_size: 65536
  kem_algorithm: "ML-KEM-768"
  sig_algorithm: "ML-DSA-65"
  argon2_time_cost: 2
  argon2_memory_cost: 16384
  argon2_parallelism: 2
"""
    config_file.write_text(content.strip(), encoding="utf-8")
    return config_file


@pytest.fixture
def clean_env() -> Generator[None, None, None]:
    """Ensure PQSYSGUARD_ environment variables do not leak across tests."""
    backup = {k: v for k, v in os.environ.items() if k.startswith("PQSYSGUARD_")}
    for k in backup:
        del os.environ[k]
    try:
        yield
    finally:
        for k in list(os.environ.keys()):
            if k.startswith("PQSYSGUARD_"):
                del os.environ[k]
        for k, v in backup.items():
            os.environ[k] = v
