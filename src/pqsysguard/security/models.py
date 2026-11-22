"""Data models for system security hardening audits and CIS benchmark compliance."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditSeverity(StrEnum):
    """Audit finding severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuditStatus(StrEnum):
    """Compliance evaluation status."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class CISControl(BaseModel):
    """CIS benchmark reference metadata."""

    id: str  # e.g., "CIS-5.2.10"
    title: str
    benchmark_version: str = "Linux Benchmark v2.0"


class AuditFinding(BaseModel):
    """Security audit check finding."""

    check_id: str
    title: str
    status: AuditStatus
    severity: AuditSeverity
    cis_control: CISControl | None = None
    evidence: str
    remediation: str
    impact_penalty: int = 0  # Score deduction on failure


class SecurityReport(BaseModel):
    """Consolidated security audit report with scoring and compliance mapping."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    score: int = 100  # 0 to 100
    grade: str = "A"  # A, B, C, D, F
    total_checks: int = 0
    passed_count: int = 0
    failed_count: int = 0
    warn_count: int = 0
    findings: list[AuditFinding] = Field(default_factory=list)

    def calculate_score(self) -> None:
        """Compute aggregate score and letter grade from findings."""
        base_score = 100
        for f in self.findings:
            if f.status in (AuditStatus.FAIL, AuditStatus.WARN):
                base_score -= f.impact_penalty

        self.score = max(0, min(100, base_score))
        if self.score >= 90:
            self.grade = "A"
        elif self.score >= 75:
            self.grade = "B"
        elif self.score >= 60:
            self.grade = "C"
        elif self.score >= 40:
            self.grade = "D"
        else:
            self.grade = "F"

        self.total_checks = len(self.findings)
        self.passed_count = sum(1 for f in self.findings if f.status == AuditStatus.PASS)
        self.failed_count = sum(1 for f in self.findings if f.status == AuditStatus.FAIL)
        self.warn_count = sum(1 for f in self.findings if f.status == AuditStatus.WARN)

    def to_summary_dict(self) -> dict[str, Any]:
        """Return summary dictionary for logging and serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "score": self.score,
            "grade": self.grade,
            "total_checks": self.total_checks,
            "passed": self.passed_count,
            "failed": self.failed_count,
            "warnings": self.warn_count,
        }
