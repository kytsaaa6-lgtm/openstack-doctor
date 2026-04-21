"""Common data models for diagnostic results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    OK = "ok"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.OK: 0,
    Severity.INFO: 1,
    Severity.WARN: 2,
    Severity.ERROR: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class Finding:
    """A single diagnostic finding."""

    check: str
    severity: Severity
    title: str
    detail: str = ""
    resource: str | None = None
    suggestion: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "resource": self.resource,
            "suggestion": self.suggestion,
            "evidence": self.evidence,
        }


@dataclass
class CheckResult:
    """Result of a single check module."""

    name: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.OK
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "worst_severity": self.worst_severity.value,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class DiagnosisReport:
    """Aggregate report of all checks."""

    cloud: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    results: list[CheckResult] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def worst_severity(self) -> Severity:
        if not self.results:
            return Severity.OK
        return max(
            (r.worst_severity for r in self.results),
            key=lambda s: SEVERITY_ORDER[s],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cloud": self.cloud,
            "worst_severity": self.worst_severity.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "context": self.context,
            "results": [r.to_dict() for r in self.results],
        }
