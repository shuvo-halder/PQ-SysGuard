"""Unit tests for configuration loading and validation."""

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from pqsysguard.config import AppConfig, load_config


def test_default_config() -> None:
    """Test that default configuration adheres to expected defaults."""
    config = AppConfig()
    assert config.general.app_name == "pqsysguard"
    assert config.general.log_level == "INFO"
    assert config.general.log_format == "json"
    assert config.monitor.interval_seconds == 5
    assert config.monitor.cpu_warning_percent == 75.0
    assert config.monitor.cpu_critical_percent == 90.0
    assert config.security.check_root_login is True
    assert config.vault.default_chunk_size == 1048576
    assert config.vault.kem_algorithm == "ML-KEM-768"
    assert config.vault.sig_algorithm == "ML-DSA-65"


def test_load_from_yaml(temp_config_yaml: Path) -> None:
    """Test loading configuration from a YAML file."""
    config = load_config(temp_config_yaml)
    assert config.general.app_name == "test-sysguard"
    assert config.general.environment == "testing"
    assert config.general.log_level == "DEBUG"
    assert config.general.log_format == "text"
    assert config.database.path == "test.db"
    assert config.monitor.interval_seconds == 2
    assert config.monitor.cpu_warning_percent == 75.0
    assert config.troubleshoot.journal_log_lines == 50
    assert config.troubleshoot.failed_units_check is False
    assert config.security.ssh_config_path == "/custom/sshd_config"
    assert config.security.sensitive_files == ["/custom/secret"]
    assert config.vault.default_chunk_size == 65536
    assert config.vault.argon2_memory_cost == 16384


def test_env_overrides(clean_env: None, temp_config_yaml: Path) -> None:
    """Test environment variable overrides over YAML values."""
    os.environ["PQSYSGUARD_GENERAL__LOG_LEVEL"] = "ERROR"
    os.environ["PQSYSGUARD_MONITOR__INTERVAL_SECONDS"] = "42"
    os.environ["PQSYSGUARD_TROUBLESHOOT__FAILED_UNITS_CHECK"] = "true"
    os.environ["PQSYSGUARD_MONITOR__CPU_WARNING_PERCENT"] = "92.5"

    config = load_config(temp_config_yaml)
    assert config.general.log_level == "ERROR"
    assert config.monitor.interval_seconds == 42
    assert config.troubleshoot.failed_units_check is True
    assert config.monitor.cpu_warning_percent == 92.5


def test_invalid_validation() -> None:
    """Test that invalid config values raise ValidationError."""
    with pytest.raises(ValidationError):
        AppConfig(monitor={"interval_seconds": 0})  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        AppConfig(monitor={"cpu_warning_percent": 150.0})  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        AppConfig(vault={"default_chunk_size": 128})  # type: ignore[arg-type]


def test_nonexistent_config_falls_back() -> None:
    """Test that a non-existent path falls back to default config without error."""
    config = load_config(Path("/non/existent/path/sysguard.yaml"))
    assert config.general.app_name == "pqsysguard"
    assert config.monitor.interval_seconds == 5
