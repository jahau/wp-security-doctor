"""Core data model: severities, statuses and structured findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How much harm the issue could cause if it is real."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Status(str, Enum):
    """Outcome of a single check.

    PASS     the check ran and found nothing wrong
    WARN     something needs human review (heuristic or hardening gap)
    FAIL     a confirmed problem (verified mismatch or an observed insecure setting)
    SKIPPED  the check did not run (unsupported platform, missing tool, opt-in)
    UNKNOWN  the check ran but could not reach a conclusion
    """

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return _STATUS_RANK[self]


# Lower rank sorts first in reports.
_STATUS_RANK = {
    Status.FAIL: 0,
    Status.WARN: 1,
    Status.UNKNOWN: 2,
    Status.SKIPPED: 3,
    Status.PASS: 4,
}


class Basis(str, Enum):
    """What a finding is based on, so readers can weigh it."""

    VERIFIED = "verified"  # compared against an authoritative reference (checksums)
    OBSERVED = "observed"  # directly read from disk (config value, permission bits)
    HEURISTIC = "heuristic"  # pattern or location based; may be a false positive
    NONE = "none"  # nothing was evaluated (SKIPPED)


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: Severity
    status: Status
    basis: Basis
    explanation: str
    locations: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def sort_key(self) -> tuple[int, int, str]:
        return (self.status.rank, -self.severity.rank, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "status": self.status.value,
            "basis": self.basis.value,
            "locations": list(self.locations),
            "evidence": list(self.evidence),
            "explanation": self.explanation,
            "remediation": self.remediation,
            "references": list(self.references),
        }


# Maximum number of individual paths/evidence lines listed per finding.
MAX_LISTED = 50


def capped(items: list[str], limit: int = MAX_LISTED) -> list[str]:
    """Return a sorted list truncated to ``limit`` entries with a trailer line."""
    ordered = sorted(set(items))
    if len(ordered) <= limit:
        return ordered
    return [*ordered[:limit], f"... and {len(ordered) - limit} more"]


@dataclass(frozen=True)
class Rule:
    """Static metadata for a rule; produces findings with consistent wording."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    explanation: str
    remediation: str
    references: tuple[str, ...] = ()
    pass_title: str = ""  # neutral wording used when the check passes

    def finding(
        self,
        status: Status,
        basis: Basis,
        *,
        severity: Severity | None = None,
        title: str | None = None,
        explanation: str | None = None,
        locations: list[str] | None = None,
        evidence: list[str] | None = None,
        remediation: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=title or self.title,
            category=self.category,
            severity=severity or self.severity,
            status=status,
            basis=basis,
            explanation=explanation or self.explanation,
            locations=capped(locations or []),
            evidence=list(evidence or []),
            remediation=self.remediation if remediation is None else remediation,
            references=list(self.references),
        )

    def passed(
        self,
        evidence: list[str] | None = None,
        locations: list[str] | None = None,
        basis: Basis = Basis.OBSERVED,
        explanation: str | None = None,
    ) -> Finding:
        return self.finding(
            Status.PASS,
            basis,
            severity=Severity.INFO,
            evidence=evidence,
            locations=locations,
            remediation="",
            explanation=explanation,
            title=self.pass_title or None,
        )

    def skipped(self, reason: str, remediation: str = "") -> Finding:
        return self.finding(
            Status.SKIPPED, Basis.NONE, severity=Severity.INFO, evidence=[reason], remediation=remediation
        )
