"""Finding data model.

A finding is the contract between the rules and every consumer (text, JSON,
SARIF, the release gate). Field names are stable and match the specification
exactly: ``rule_id``, ``severity``, ``confidence``, ``file``, ``line``,
``code_location``, ``description``, ``root_cause``, ``impact``, ``remediation``.
"""

from __future__ import annotations

import enum
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Final


class Severity(str, enum.Enum):
    """Finding severity, ordered from most to least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        """Higher rank means more urgent."""
        return SEVERITY_ORDER[self]


#: Sort order used for reporting and for ``fail_on`` comparisons.
SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}

#: SARIF requires these exact level strings.
SARIF_LEVEL: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFORMATIONAL: "note",
}


class Confidence(str, enum.Enum):
    """How sure the rule is that a true positive exists."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True, order=False)
class Finding:
    """One security finding.

    ``code_location`` is a short, already-redacted excerpt of the offending
    source line, kept in the finding so reports do not need to re-read the file.
    """

    rule_id: str
    severity: Severity
    confidence: Confidence
    file: str
    line: int
    column: int
    code_location: str
    description: str
    root_cause: str
    impact: str
    remediation: str
    language: str
    references: tuple[str, ...] = ()
    secret_kind: str | None = None
    fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "code_location": self.code_location,
            "description": self.description,
            "root_cause": self.root_cause,
            "impact": self.impact,
            "remediation": self.remediation,
            "language": self.language,
        }
        if self.references:
            payload["references"] = list(self.references)
        if self.secret_kind:
            # The fingerprint correlates the same credential across files; the
            # value itself is never stored.
            payload["secret_kind"] = self.secret_kind
            payload["secret_fingerprint"] = self.fingerprint
        return payload

    @property
    def sort_key(self) -> tuple[int, int, str, int, int]:
        """Deterministic ordering: severity, confidence, file, line, column."""
        return (
            -self.severity.rank,
            -_CONFIDENCE_ORDER[self.confidence],
            self.file,
            self.line,
            self.column,
        )


_CONFIDENCE_ORDER: Final[dict[Confidence, int]] = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}


@dataclass(slots=True)
class ScanResult:
    """Aggregated outcome of scanning one or more roots."""

    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    files_skipped: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    duration_seconds: float = 0.0
    rule_count: int = 0

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def counts_by_severity(self) -> dict[str, int]:
        """Return ``{severity: count}`` including zero entries."""
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def filtered(
        self, *, minimum: Severity | None = None, ignore: frozenset[str] = frozenset()
    ) -> ScanResult:
        """Return a copy limited to *minimum* severity, excluding ignored rules.

        Args:
            minimum: Severity | None: Lowest severity to keep; ``None`` keeps everything.
            ignore: frozenset[str]: Rule ids to drop from the copy.
        """
        clone = ScanResult(
            root=self.root,
            files_scanned=self.files_scanned,
            bytes_scanned=self.bytes_scanned,
            files_skipped=list(self.files_skipped),
            errors=list(self.errors),
            duration_seconds=self.duration_seconds,
            rule_count=self.rule_count,
        )
        for finding in self.findings:
            if finding.rule_id in ignore:
                continue
            if minimum is not None and finding.severity.rank < minimum.rank:
                continue
            clone.findings.append(finding)
        clone.findings.sort(key=lambda item: item.sort_key)
        return clone

    def highest_severity(self) -> Severity | None:
        """Return the most severe finding, or ``None`` when clean."""
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)

    def failing(self, fail_on: frozenset[Severity]) -> bool:
        """Return ``True`` when a finding reaches any threshold in *fail_on*.

        *fail_on* names a **lowest acceptable severity**, not an exact match:
        ``--fail-on high`` must still fail on a critical finding. Matching only
        the named severity would let a critical issue pass whenever the operator
        lowered the threshold, which is precisely when it matters most.

        Args:
            fail_on: frozenset[Severity]: Lowest acceptable severities; empty means never fail.
        """
        if not fail_on:
            return False
        lowest = min(severity.rank for severity in fail_on)
        return any(finding.severity.rank >= lowest for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the whole scan."""
        return {
            "tool": "opencode-security-audit",
            "root": self.root,
            "summary": {
                "files_scanned": self.files_scanned,
                "bytes_scanned": self.bytes_scanned,
                "findings": len(self.findings),
                "by_severity": self.counts_by_severity(),
                "files_skipped": len(self.files_skipped),
                "errors": len(self.errors),
                "duration_seconds": round(self.duration_seconds, 4),
                "rules_evaluated": self.rule_count,
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "files_skipped": self.files_skipped,
            "errors": self.errors,
        }
