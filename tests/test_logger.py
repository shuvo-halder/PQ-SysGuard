"""Unit tests for structured logging and sensitive data redaction."""

import io
import json
import logging
import pytest

from pqsysguard.utils.logger import JsonFormatter, get_logger, setup_logging


def test_json_formatter_basic() -> None:
    """Test basic JSON log formatting."""
    record = logging.LogRecord(
        name="pqsysguard.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test message with %s",
        args=("parameter",),
        exc_info=None,
    )
    formatter = JsonFormatter()
    output = formatter.format(record)

    data = json.loads(output)
    assert data["level"] == "INFO"
    assert data["logger"] == "pqsysguard.test"
    assert data["message"] == "Test message with parameter"
    assert data["module"] == "test"
    assert data["line"] == 10
    assert "timestamp" in data


def test_sensitive_field_redaction() -> None:
    """Security rule test: Sensitive keys in extra attributes must be redacted."""
    record = logging.LogRecord(
        name="pqsysguard.vault",
        level=logging.WARNING,
        pathname="vault.py",
        lineno=42,
        msg="Key operation triggered",
        args=(),
        exc_info=None,
    )
    # Attach sensitive attributes
    record.api_token = "secret-token-xyz"  # type: ignore[attr-defined]
    record.private_key = "super_secret_bytes"  # type: ignore[attr-defined]
    record.safe_metric = "disk_usage_ok"  # type: ignore[attr-defined]

    formatter = JsonFormatter()
    output = formatter.format(record)
    data = json.loads(output)

    assert "extra" in data
    assert data["extra"]["api_token"] == "[REDACTED]"
    assert data["extra"]["private_key"] == "[REDACTED]"
    assert data["extra"]["safe_metric"] == "disk_usage_ok"


def test_setup_logging_json() -> None:
    """Test setup_logging configures stream with JSON output."""
    stream = io.StringIO()
    setup_logging(level="DEBUG", log_format="json", stream=stream)

    logger = get_logger("audit")
    logger.info("Operation completed successfully", extra={"user_id": 1001})

    output = stream.getvalue().strip()
    data = json.loads(output)
    assert data["level"] == "INFO"
    assert data["message"] == "Operation completed successfully"
    assert data["extra"]["user_id"] == 1001


def test_setup_logging_text() -> None:
    """Test setup_logging configures stream with plain text output."""
    stream = io.StringIO()
    setup_logging(level="INFO", log_format="text", stream=stream)

    logger = get_logger("audit")
    logger.info("Hello text logging")

    output = stream.getvalue().strip()
    assert "[INFO]" in output
    assert "Hello text logging" in output


def test_get_logger_prefix() -> None:
    """Test get_logger auto-prefixes unqualified names."""
    l1 = get_logger("monitor")
    assert l1.name == "pqsysguard.monitor"

    l2 = get_logger("pqsysguard.security")
    assert l2.name == "pqsysguard.security"
