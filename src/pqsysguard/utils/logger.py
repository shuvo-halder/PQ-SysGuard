"""Structured logging implementation for PQ-SysGuard.

Provides JSON-formatted logging for automated ingestion and auditability,
as well as a human-friendly console formatter when requested.
"""

from datetime import datetime, timezone
import json
import logging
import sys
from typing import Any

# Sensitive keys that must NEVER appear in log records
SENSITIVE_FIELD_NAMES = {
    "password",
    "passphrase",
    "secret",
    "private_key",
    "key",
    "token",
    "auth",
    "file_key",
    "plaintext",
    "salt",
}


class JsonFormatter(logging.Formatter):
    """Custom formatter outputting single-line JSON records."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }

        # Include exception tracebacks if present
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        # Include extra attributes passed to the logger, sanitizing sensitive keys
        standard_attrs = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
        }

        extras: dict[str, Any] = {}
        for key, val in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                lower_key = key.lower()
                if any(sens in lower_key for sens in SENSITIVE_FIELD_NAMES):
                    extras[key] = "[REDACTED]"
                else:
                    try:
                        # Ensure value is JSON serializable
                        json.dumps(val)
                        extras[key] = val
                    except (TypeError, OverflowError):
                        extras[key] = str(val)

        if extras:
            log_payload["extra"] = extras

        return json.dumps(log_payload)


def setup_logging(
    level: str = "INFO",
    log_format: str = "json",
    stream: Any = sys.stdout,
) -> None:
    """Configure the root logger for PQ-SysGuard.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Log format ('json' or 'text').
        stream: Output stream (default: stdout).
    """
    root_logger = logging.getLogger()
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to prevent duplicate lines
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(stream)
    handler.setLevel(numeric_level)

    if log_format.lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        text_formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(text_formatter)

    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a logger configured under the pqsysguard namespace."""
    if not name.startswith("pqsysguard"):
        return logging.getLogger(f"pqsysguard.{name}")
    return logging.getLogger(name)
