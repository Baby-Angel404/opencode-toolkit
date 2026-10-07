"""The release gate.

A gate file records every mandatory check. The rule enforced here is blunt on
purpose:

    PASS is the only status that permits a release.

``SKIPPED``, ``UNKNOWN`` and ``NOT_RUN`` are all refusals. So is ``WARN`` unless
the project's configured policy explicitly allows it, which the policy names
rather than assuming.

The gate file is plain JSON so CI can read it without importing this package,
and so an operator can inspect exactly why a release is blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio
from opencode_toolkit.core.errors import StateError
from opencode_toolkit.core.fsio import ensure_dir
from opencode_toolkit.core.timeutil import utc_now
from opencode_toolkit.core.version import detect_version

GATE_KIND = "opencode-toolkit/release-gate"
GATE_SCHEMA = 1

#: Every mandatory check, in pipeline order. The gate is invalid if any is
#: missing, which prevents someone "fixing" a blocked release by deleting a line.
CHECK_NAMES: tuple[str, ...] = (
    "BUILD",
    "FORMAT",
    "LINT",
    "TYPECHECK",
    "UNIT_TEST",
    "INTEGRATION_TEST",
    "CLI_TEST",
    "SECURITY",
    "DEPENDENCY_AUDIT",
    "SECRET_SCAN",
    "DOCUMENTATION",
    "PACKAGE",
    "REPRODUCIBILITY",
)

#: Checks that must pass before anything may be published. Every one is
#: runnable on any host with a Python interpreter, so an unanswered question
#: always blocks the release rather than passing quietly.
PUBLISH_PREREQUISITES: tuple[str, ...] = CHECK_NAMES


class CheckStatus(str, Enum):
    """Status of one gate check."""

    PASS = "PASS"  # noqa: S105 - a status label
    FAIL = "FAIL"
    WARN = "WARN"
    SKIPPED = "SKIPPED"
    NOT_RUN = "NOT_RUN"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value

    @property
    def permits_release(self) -> bool:
        """``True`` only for :attr:`PASS`; every other status is a refusal.

        The property ignores the gate policy on purpose. Policy leniency
        (``allow_warnings``, ``allow_skip``) is applied once, by
        :meth:`GateResult.failures`, so a single status cannot be read as
        permitted in one place and blocking in another.
        """
        return self is CheckStatus.PASS


#: Statuses that are refusals regardless of policy.
BLOCKING_STATUSES = frozenset(
    {CheckStatus.FAIL, CheckStatus.NOT_RUN, CheckStatus.UNKNOWN, CheckStatus.SKIPPED}
)


@dataclass(slots=True)
class CheckResult:
    """One recorded check."""

    name: str
    status: CheckStatus
    detail: str = ""
    duration_seconds: float = 0.0
    evidence: str = ""
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the check.

        ``recorded_at`` falls back to the current time so an unrecorded
        timestamp never ships as an empty string.
        """
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "duration_seconds": round(self.duration_seconds, 3),
            "evidence": self.evidence,
            "recorded_at": self.recorded_at or utc_now(),
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> CheckResult:
        """Rebuild a check from a gate document entry.

        Args:
            document: dict[str, Any]: One entry of the gate's ``checks`` object.

        Returns:

        Raises:
            StateError: If the recorded status is missing or unrecognised; an
                unknown status is never coerced to a guess.
        """
        try:
            status = CheckStatus(str(document["status"]).upper())
        except (KeyError, ValueError) as exc:
            raise StateError(
                f"gate check has an invalid status: {exc}",
                code="release.bad_gate",
                details={"document": document},
            ) from exc
        return cls(
            name=str(document["name"]),
            status=status,
            detail=str(document.get("detail", "")),
            duration_seconds=float(document.get("duration_seconds", 0.0)),
            evidence=str(document.get("evidence", "")),
            recorded_at=str(document.get("recorded_at", "")),
        )


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Explicit, documented release policy."""

    #: Only PASS permits a release unless this is explicitly enabled.
    allow_warnings: bool = False
    #: Checks that may be SKIPPED because the environment cannot run them.
    conditionally_skippable: frozenset[str] = frozenset()
    #: Skipping a conditionally-skippable check still blocks unless listed here.
    allow_skip: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, Any]:
        """Return the policy plus its rules spelled out as prose.

        The prose is written into the gate file so an operator reading only the
        JSON can see what the policy permits without consulting the source.
        """
        return {
            "allow_warnings": self.allow_warnings,
            "conditionally_skippable": sorted(self.conditionally_skippable),
            "allow_skip": sorted(self.allow_skip),
            "policy": (
                "PASS is required for every mandatory check. FAIL, UNKNOWN, NOT_RUN "
                "and SKIPPED all block a release unless the check is listed in allow_skip."
            ),
        }


DEFAULT_POLICY = GatePolicy()


@dataclass(slots=True)
class GateResult:
    """The evaluated gate."""

    version: str
    checks: list[CheckResult] = field(default_factory=list)
    policy: GatePolicy = field(default_factory=lambda: DEFAULT_POLICY)
    commit: str = ""
    generated_at: str = ""

    # -- evaluation -------------------------------------------------------
    def get(self, name: str) -> CheckResult | None:
        """Return the recorded check called *name*, or ``None`` if absent.

        Args:
            name: str: Check name to look up; one of the mandatory ``CHECK_NAMES``.
        """
        return next((check for check in self.checks if check.name == name), None)

    def missing_checks(self) -> list[str]:
        """Return the mandatory checks with no recorded result, in pipeline order."""
        present = {check.name for check in self.checks}
        return [name for name in CHECK_NAMES if name not in present]

    def failures(self) -> list[CheckResult]:
        """Checks that block the release, with the reason each blocks."""
        blockers: list[CheckResult] = []
        for check in self.checks:
            if check.status is CheckStatus.PASS:
                continue
            if check.status is CheckStatus.WARN and self.policy.allow_warnings:
                continue
            if check.status is CheckStatus.SKIPPED and check.name in self.policy.allow_skip:
                continue
            blockers.append(check)
        return blockers

    @property
    def approved(self) -> bool:
        """``True`` only when every mandatory check is present and passing."""
        if self.missing_checks():
            return False
        return not self.failures()

    def render(self) -> str:
        """Return the human-readable gate table.

        Rendering lives on the result rather than on :class:`ReleaseGate` because
        ``load_gate`` hands back a bare :class:`GateResult`, and every caller that
        displays a gate has one of those.
        """
        lines = [
            f"RELEASE GATE -- opencode-toolkit {self.version}",
            f"commit:  {self.commit or '(not recorded)'}",
            f"policy:  allow_warnings={self.policy.allow_warnings} "
            f"allow_skip={sorted(self.policy.allow_skip) or 'none'}",
            "",
            f"{'CHECK':<20} {'STATUS':<9} DETAIL",
            f"{'-' * 20} {'-' * 9} {'-' * 40}",
        ]
        for check in CHECK_NAMES:
            found = self.get(check)
            status = found.status.value if found else "ABSENT"
            detail = (found.detail if found else "check absent from the gate")[:40]
            lines.append(f"{check:<20} {status:<9} {detail}")
        missing = self.missing_checks()
        if missing:
            lines.append("")
            lines.append(f"ABSENT CHECKS: {', '.join(missing)}")
        lines.append("")
        lines.append(f"DECISION: {self.decision}")
        lines.append(f"REASON:    {self.reason()}")
        return "\n".join(lines)

    @property
    def decision(self) -> str:
        """``"APPROVED"`` or ``"BLOCKED"``, derived from :attr:`approved`."""
        return "APPROVED" if self.approved else "BLOCKED"

    def reason(self) -> str:
        """A single sentence explaining the decision."""
        if self.approved:
            return f"all {len(CHECK_NAMES)} mandatory checks passed"
        missing = self.missing_checks()
        if missing:
            return f"{len(missing)} check(s) absent from the gate: {', '.join(missing)}"
        blockers = self.failures()
        detail = ", ".join(
            f"{check.name}={check.status.value}" + (f" ({check.detail})" if check.detail else "")
            for check in blockers
        )
        return f"{len(blockers)} blocking check(s): {detail}"

    # -- serialisation ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Return the full gate document.

        The decision, approval flag and reason are stored alongside the raw
        checks so a CI job reading only the file sees the same verdict the gate
        computed.
        """
        return {
            "kind": GATE_KIND,
            "schema": GATE_SCHEMA,
            "version": self.version,
            "commit": self.commit,
            "generated_at": self.generated_at or utc_now(),
            "required_checks": list(CHECK_NAMES),
            "policy": self.policy.to_dict(),
            "decision": self.decision,
            "approved": self.approved,
            "reason": self.reason(),
            "checks": {check.name: check.to_dict() for check in self.checks},
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> GateResult:
        """Rebuild a gate from a stored document.

        Args:
            document: dict[str, Any]: The decoded gate JSON.

        Returns:

        Raises:
            StateError: If the document is not a gate, carries an unsupported
                schema, or has a non-object ``checks`` field.
        """
        if document.get("kind") != GATE_KIND:
            raise StateError(
                "not an opencode-toolkit release gate document",
                code="release.bad_gate",
                details={"found_kind": document.get("kind"), "expected": GATE_KIND},
            )
        schema = document.get("schema")
        if schema != GATE_SCHEMA:
            raise StateError(
                f"unsupported gate schema {schema!r}; this build understands {GATE_SCHEMA}",
                code="release.schema_mismatch",
                details={"schema": schema, "supported": GATE_SCHEMA},
            )
        raw_checks = document.get("checks")
        if not isinstance(raw_checks, dict):
            raise StateError("gate 'checks' must be an object", code="release.bad_gate")
        policy_doc = document.get("policy", {})
        policy = GatePolicy(
            allow_warnings=bool(policy_doc.get("allow_warnings", False)),
            conditionally_skippable=frozenset(policy_doc.get("conditionally_skippable", [])),
            allow_skip=frozenset(policy_doc.get("allow_skip", [])),
        )
        return cls(
            version=str(document.get("version", "0.0.0")),
            checks=[CheckResult.from_dict(item) for item in raw_checks.values()],
            policy=policy,
            commit=str(document.get("commit", "")),
            generated_at=str(document.get("generated_at", "")),
        )

    def publish_permitted(self) -> tuple[bool, str]:
        """Return whether publishing may proceed, and why.

        Called by the publishing workflows before any upload happens. It is a
        function rather than a boolean so the refusal message can name the exact
        blocking checks.
        """
        if self.approved:
            return True, "release gate approved"
        return False, f"release gate blocked: {self.reason()}"


def new_gate(version: str | None = None, *, commit: str = "") -> GateResult:
    """Create a gate with every check present and ``NOT_RUN``.

    Seeding every check as ``NOT_RUN`` is deliberate: an omitted check and an
    unrun check are treated the same way, so nothing can be quietly forgotten.

    Args:
        version: str | None: Version under release; detected from ``pyproject.toml`` if omitted.
        commit: str: Commit the gate is being run against; recorded verbatim.
    """
    resolved = version or str(detect_version())
    return GateResult(
        version=resolved,
        checks=[
            CheckResult(name=name, status=CheckStatus.NOT_RUN, detail="not yet recorded")
            for name in CHECK_NAMES
        ],
        commit=commit,
        generated_at=utc_now(),
    )


def record(
    gate: GateResult,
    name: str,
    status: CheckStatus | str,
    *,
    detail: str = "",
    duration_seconds: float = 0.0,
    evidence: str = "",
) -> GateResult:
    """Return a copy of *gate* with *name* recorded.

    Accepts a string status so shell scripts can pass ``"$STATUS"`` without a
    lookup table, and refuses an unknown status rather than recording a lie.
    ``NOT_RUN`` blocks the release exactly as ``FAIL`` does.

    Args:
        gate: GateResult: The gate to copy; the original is left untouched.
        name: str: Name of the check being recorded.
        status: CheckStatus | str: Outcome, as a :class:`CheckStatus` or its string form.
        detail: str: Human-readable explanation of the outcome.
        duration_seconds: float: How long the check took; recorded as evidence.
        evidence: str: Path or command output backing the recorded outcome.
    """
    resolved = CheckStatus(status.upper()) if isinstance(status, str) else status
    if resolved is CheckStatus.PASS and not detail and not evidence:
        raise StateError(
            f"check {name} cannot be recorded as PASS without a detail or evidence field",
            code="release.unsubstantiated_pass",
            details={"check": name},
            hint="state what passed; an unsubstantiated PASS is indistinguishable from a guess",
        )
    checks = [check for check in gate.checks if check.name != name]
    checks.append(
        CheckResult(
            name=name,
            status=resolved,
            detail=detail,
            duration_seconds=duration_seconds,
            evidence=evidence,
            recorded_at=utc_now(),
        )
    )
    order = {check_name: index for index, check_name in enumerate(CHECK_NAMES)}
    checks.sort(key=lambda check: order.get(check.name, len(order)))
    return GateResult(
        version=gate.version,
        checks=checks,
        policy=gate.policy,
        commit=gate.commit,
        generated_at=utc_now(),
    )


@dataclass(slots=True)
class ReleaseGate:
    """File-backed gate."""

    path: Path
    result: GateResult = field(default_factory=new_gate)

    def __post_init__(self) -> None:
        if self.path.is_file():
            self.result = load_gate(self.path)

    def save(self) -> Path:
        """Atomically persist the gate."""
        ensure_dir(self.path.parent)
        jsonio.write(self.path, self.result.to_dict())
        return self.path

    def record(self, name: str, status: CheckStatus | str, **kwargs: Any) -> None:
        """Record one check outcome and persist the gate.

        The in-memory result is replaced before the write, so a rejected status
        leaves the file untouched rather than half-updated.

        Args:
            name: str: Name of the mandatory check being recorded.
            status: CheckStatus | str: The outcome, as a :class:`CheckStatus` or its string form.
            **kwargs: Any: Passed through to :func:`record` -- ``detail``, ``duration_seconds`` and ``evidence``.
        """
        self.result = record(self.result, name, status, **kwargs)
        self.save()

    def approved(self) -> bool:
        """``True`` when the persisted gate approves a release."""
        return self.result.approved

    def render(self) -> str:
        """Forward to the result, which owns the rendering."""
        return self.result.render()


def load_gate(path: Path) -> GateResult:
    """Read a gate document.

    Args:
        path: Path: Gate JSON file written by :func:`write_gate`.
    """
    if not path.is_file():
        raise StateError(
            f"release gate not found: {path}",
            code="release.gate_missing",
            details={"path": str(path)},
            hint="run `./scripts/quality-check` which writes the gate as each stage completes",
        )
    return GateResult.from_dict(jsonio.read(path))


def write_gate(path: Path, result: GateResult) -> Path:
    """Write *result* to *path* as a gate document and return the path.

    Args:
        path: Path: Destination file; parent directories are created as needed.
        result: GateResult: The evaluated gate to serialise.

    Returns:
    """
    ensure_dir(path.parent)
    jsonio.write(path, result.to_dict())
    return path


def gate_timestamp() -> str:
    """ISO-8601 timestamp used in gate metadata."""
    return datetime.now(timezone.utc).isoformat()
