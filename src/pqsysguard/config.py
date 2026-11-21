"""Configuration loading and validation for PQ-SysGuard.

Supports YAML configuration files with hierarchical structure,
falling back to sensible defaults and allowing environment variable overrides.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import yaml

from pydantic import BaseModel, Field


class GeneralConfig(BaseModel):
    """General application settings."""

    app_name: str = "pqsysguard"
    environment: str = "production"
    log_level: str = "INFO"
    log_format: str = "json"


class DatabaseConfig(BaseModel):
    """Local SQLite audit & metrics database configuration."""

    path: str = "pqsysguard.db"


class MonitorConfig(BaseModel):
    """Health monitoring parameters."""

    interval_seconds: int = Field(default=5, ge=1)
    cpu_threshold_percent: float = Field(default=85.0, ge=0.0, le=100.0)
    memory_threshold_percent: float = Field(default=85.0, ge=0.0, le=100.0)
    disk_threshold_percent: float = Field(default=90.0, ge=0.0, le=100.0)


class TroubleshootConfig(BaseModel):
    """Automated troubleshooting diagnostic parameters."""

    journal_log_lines: int = Field(default=100, ge=10)
    failed_units_check: bool = True


class SecurityConfig(BaseModel):
    """Security hardening audit parameters."""

    ssh_config_path: str = "/etc/ssh/sshd_config"
    check_root_login: bool = True
    check_password_auth: bool = True
    check_open_ports: bool = True
    check_file_permissions: bool = True
    sensitive_files: list[str] = Field(
        default_factory=lambda: [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
        ]
    )


class VaultConfig(BaseModel):
    """Post-quantum file vault cryptographic parameters."""

    default_chunk_size: int = Field(default=1048576, ge=4096)  # 1 MB default
    kem_algorithm: str = "ML-KEM-768"
    sig_algorithm: str = "ML-DSA-65"
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost: int = Field(default=65536, ge=1024)  # in KiB (64 MB)
    argon2_parallelism: int = Field(default=4, ge=1)


class AppConfig(BaseModel):
    """Root configuration model for PQ-SysGuard."""

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    troubleshoot: TroubleshootConfig = Field(default_factory=TroubleshootConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)


def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge source dictionary into target dictionary."""
    for key, value in source.items():
        if isinstance(value, dict) and key in target and isinstance(target[key], dict):
            target[key] = _deep_merge(target[key], value)
        else:
            target[key] = value
    return target


def _apply_env_overrides(config_dict: dict[str, Any]) -> dict[str, Any]:
    """Override configuration with environment variables.

    Format: PQSYSGUARD_<SECTION>__<KEY> or PQSYSGUARD_<KEY>
    Example: PQSYSGUARD_GENERAL__LOG_LEVEL=DEBUG -> config["general"]["log_level"] = "DEBUG"
    """
    prefix = "PQSYSGUARD_"
    for env_var, value in os.environ.items():
        if not env_var.startswith(prefix):
            continue

        raw_key = env_var[len(prefix) :].lower()

        # Handle parsed types (int, float, bool)
        parsed_val: Any = value
        if value.lower() in ("true", "yes", "1"):
            parsed_val = True
        elif value.lower() in ("false", "no", "0"):
            parsed_val = False
        else:
            try:
                parsed_val = int(value)
            except ValueError:
                try:
                    parsed_val = float(value)
                except ValueError:
                    parsed_val = value

        if "__" in raw_key:
            section, key = raw_key.split("__", 1)
            if section not in config_dict:
                config_dict[section] = {}
            if isinstance(config_dict[section], dict):
                config_dict[section][key] = parsed_val
        else:
            # Single key override at root level if exists
            config_dict[raw_key] = parsed_val

    return config_dict


def find_default_config_path() -> Path | None:
    """Locate the default configuration file across standard locations."""
    # 1. Environment variable
    env_path = os.environ.get("PQSYSGUARD_CONFIG")
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    # 2. Local repository / working directory
    local_path = Path("config/default.yaml")
    if local_path.is_file():
        return local_path

    # 3. User config directory
    user_path = Path.home() / ".config" / "pqsysguard" / "config.yaml"
    if user_path.is_file():
        return user_path

    # 4. System config directory
    system_path = Path("/etc/pqsysguard/config.yaml")
    if system_path.is_file():
        return system_path

    return None


def load_config(config_path: str | Path | None = None) -> AppConfig:
    """Load, merge, and validate configuration from YAML and environment variables.

    Args:
        config_path: Path to configuration YAML file. If None, standard locations are probed.

    Returns:
        Validated AppConfig instance.
    """
    path_to_load = Path(config_path) if config_path else find_default_config_path()

    loaded_dict: dict[str, Any] = {}
    if path_to_load and path_to_load.is_file():
        with open(path_to_load, "r", encoding="utf-8") as f:
            yaml_content = yaml.safe_load(f)
            if isinstance(yaml_content, dict):
                loaded_dict = yaml_content

    # Apply environment variable overrides
    loaded_dict = _apply_env_overrides(loaded_dict)

    return AppConfig.model_validate(loaded_dict)
