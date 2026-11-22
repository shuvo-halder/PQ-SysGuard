"""Data models for automated troubleshooting diagnosis and findings."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class FindingSeverity(StrEnum):
    """Severity classification for troubleshooting findings."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    """An identified issue with evidence, root cause analysis, and remediation advice."""

    check_name: str
    severity: FindingSeverity
    title: str
    evidence: str
    probable_cause: str
    recommended_fix: str  # Guidance command or config; never auto-executed by default


class LogRule(BaseModel):
    """YAML-defined pattern matching rule for system log analysis."""

    id: str
    name: str
    pattern: str
    severity: FindingSeverity
    source: str = "syslog"  # "syslog", "auth.log", "journalctl", or custom path
    probable_cause: str
    recommended_fix: str


class TroubleshootReport(BaseModel):
    """Consolidated summary report of all diagnostic checks."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_checks: int = 0
    passed_checks: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        """Check if any finding is CRITICAL."""
        return any(f.severity == FindingSeverity.CRITICAL for f in self.findings)

    @property
    def has_warning(self) -> bool:
        """Check if any finding is WARNING."""
        return any(f.severity == FindingSeverity.WARNING for f in self.findings)
