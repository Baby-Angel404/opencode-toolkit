"""Drift comparison against a stored baseline.

The baseline is a JSON file written by ``opencode docs scan --write-baseline``.
Drift is computed from the signature subset only (see
:meth:`ApiSurface.digest_items`), because docstring prose is edited constantly
and reporting it as drift would make the check noise.

Three drift kinds are reported, each with a distinct remedy:

``added``      -- new public API with no baseline entry
``removed``    -- baseline entry no longer present
``changed``    -- same name, different signature
``undocumented``-- present in both, but with no docstring or missing parameters
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio
from opencode_toolkit.core.errors import StateError
from opencode_toolkit.live_docs.scanner import ApiItem, ApiSurface

BASELINE_KIND = "opencode-toolkit/docs-baseline"
BASELINE_SCHEMA = 1

DEFAULT_BASELINE_RELPATH = Path(".opencode") / "toolkit" / "docs" / "baseline.json"


@dataclass(frozen=True, slots=True)
class DriftItem:
    """One drift observation."""

    kind: str
    qualified_name: str
    file: str
    line: int
    detail: str
    signature_before: str = ""
    signature_after: str = ""
    undocumented_parameters: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return the drift item as JSON-serialisable data."""
        return {
            "kind": self.kind,
            "qualified_name": self.qualified_name,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
            "signature_before": self.signature_before,
            "signature_after": self.signature_after,
            "undocumented_parameters": list(self.undocumented_parameters),
        }


@dataclass(slots=True)
class DriftReport:
    """All drift between a surface and a baseline."""

    root: str
    items: list[DriftItem] = field(default_factory=list)
    baseline_path: str | None = None
    baseline_present: bool = True
    surface_counts: dict[str, int] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.items)

    def by_kind(self) -> dict[str, int]:
        """Return the number of items per drift kind, sorted by kind."""
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.kind] = counts.get(item.kind, 0) + 1
        return dict(sorted(counts.items()))

    def has_blocking(self) -> bool:
        """``True`` when there is drift a release gate should refuse.

        ``added`` and ``changed`` are blocking because they mean the documented
        surface no longer matches the code. ``undocumented`` is blocking too --
        an undocumented public function is the exact failure this tool exists to
        prevent. ``removed`` is informational: deleting code is usually
        deliberate.
        """
        return any(item.kind in {"added", "changed", "undocumented"} for item in self.items)

    def to_dict(self) -> dict[str, Any]:
        """Return the report, its counts and the blocking verdict as data."""
        return {
            "root": self.root,
            "baseline_path": self.baseline_path,
            "baseline_present": self.baseline_present,
            "counts": self.by_kind(),
            "surface_counts": self.surface_counts,
            "blocking": self.has_blocking(),
            "total": len(self.items),
            "items": [item.to_dict() for item in self.items],
        }


def baseline_document(surface: ApiSurface) -> dict[str, Any]:
    """Build the baseline document for *surface*.

    Args:
        surface: ApiSurface: Scanned surface to serialise; its ``root``, counts
            and prose-free digest become the baseline entries.
    """
    return {
        "kind": BASELINE_KIND,
        "schema": BASELINE_SCHEMA,
        "root": surface.root,
        "counts": surface.counts(),
        "items": surface.digest_items(),
    }


def write_baseline(path: Path, surface: ApiSurface, *, force: bool = False) -> Path:
    """Write *surface* as the baseline for *path*.

    An existing baseline is never replaced without ``force``: overwriting one is
    how a real drift report gets silently accepted, so it has to be a deliberate
    act with ``opencode docs diff`` reviewed first.

    Args:
        path: Path: Destination file for the JSON baseline; created or replaced.
        surface: ApiSurface: Surface to persist at *path*.
        force: bool: Replace an existing baseline instead of raising
            :class:`ConflictError`.
    """
    from opencode_toolkit.core.errors import ConflictError

    if path.exists() and not force:
        raise ConflictError(
            f"baseline already exists: {path}",
            conflicts=[str(path)],
            hint="pass --force to replace it, after reviewing `opencode docs diff`",
        )
    jsonio.write(path, baseline_document(surface))
    return path


def load_baseline(path: Path) -> list[dict[str, Any]]:
    """Read the baseline entries, validating the document kind and schema.

    Args:
        path: Path: Baseline file to read. Raises :class:`StateError` when it is
            missing, is not an opencode-toolkit baseline, or carries a schema
            this build does not understand.
    """
    if not path.is_file():
        raise StateError(
            f"documentation baseline not found: {path}",
            code="docs.baseline_missing",
            details={"path": str(path)},
            hint="run `opencode docs scan --write-baseline` to create it",
        )
    document = jsonio.read(path)
    if document.get("kind") != BASELINE_KIND:
        raise StateError(
            "not an opencode-toolkit docs baseline",
            code="docs.bad_baseline",
            details={"found_kind": document.get("kind"), "expected": BASELINE_KIND},
        )
    schema = document.get("schema")
    if schema != BASELINE_SCHEMA:
        raise StateError(
            f"unsupported baseline schema {schema!r}; this build understands {BASELINE_SCHEMA}",
            code="docs.schema_mismatch",
            details={"schema": schema, "supported": BASELINE_SCHEMA},
        )
    items = document.get("items")
    if not isinstance(items, list):
        raise StateError("baseline 'items' must be a list", code="docs.bad_baseline")
    return items


def _signature_of(entry: dict[str, Any]) -> str:
    return str(entry.get("signature", ""))


def diff_against_baseline(
    surface: ApiSurface,
    baseline: list[dict[str, Any]] | None,
    *,
    baseline_path: Path | None = None,
) -> DriftReport:
    """Compare *surface* against *baseline* entries.

    Passing ``None`` for *baseline* means "no baseline file"; every public item is
    then reported as ``added`` and the report says so explicitly, rather than
    silently reporting zero drift.

    Args:
        surface: ApiSurface: Current surface to compare against the baseline.
        baseline: list[dict[str, Any]] | None: Previously recorded digest
            entries; ``None`` means no baseline file exists.
        baseline_path: Path | None: Where the baseline lives, recorded in the
            report for display only; ``None`` leaves it unrecorded.
    """
    report = DriftReport(
        root=surface.root,
        baseline_path=str(baseline_path) if baseline_path else None,
        baseline_present=baseline is not None,
        surface_counts=surface.counts(),
    )
    if baseline is None:
        report.items.extend(
            DriftItem(
                kind="added",
                qualified_name=item.qualified_name,
                file=item.file,
                line=item.line,
                detail="no documentation baseline exists; every public item is reported as new",
                signature_after=item.signature(),
            )
            for item in surface.items
            if not item.heuristic
        )
        return report

    before = {str(entry.get("qualified_name")): entry for entry in baseline}
    after = {item.qualified_name: item for item in surface.items if not item.heuristic}

    for name in sorted(set(after) - set(before)):
        item = after[name]
        report.items.append(
            DriftItem(
                kind="added",
                qualified_name=name,
                file=item.file,
                line=item.line,
                detail="public API added since the baseline was written",
                signature_after=item.signature(),
            )
        )

    for name in sorted(set(before) - set(after)):
        entry = before[name]
        report.items.append(
            DriftItem(
                kind="removed",
                qualified_name=name,
                file=str(entry.get("file", "")),
                line=int(entry.get("line", 0)),
                detail="public API removed since the baseline was written",
                signature_before=_signature_of(entry),
            )
        )

    for name in sorted(set(before) & set(after)):
        entry = before[name]
        item = after[name]
        if _signature_of(entry) != item.signature():
            report.items.append(
                DriftItem(
                    kind="changed",
                    qualified_name=name,
                    file=item.file,
                    line=item.line,
                    detail="signature differs from the baseline",
                    signature_before=_signature_of(entry),
                    signature_after=item.signature(),
                )
            )
        undocumented = item.undocumented_parameters()
        if not item.documented:
            report.items.append(
                DriftItem(
                    kind="undocumented",
                    qualified_name=name,
                    file=item.file,
                    line=item.line,
                    detail="public item has no docstring",
                    signature_after=item.signature(),
                )
            )
        elif undocumented:
            report.items.append(
                DriftItem(
                    kind="undocumented",
                    qualified_name=name,
                    file=item.file,
                    line=item.line,
                    detail=f"docstring does not document: {', '.join(undocumented)}",
                    signature_after=item.signature(),
                    undocumented_parameters=tuple(undocumented),
                )
            )

    report.items.sort(key=lambda item: (item.file, item.line, item.kind))
    return report


def default_baseline_path(root: Path) -> Path:
    """Return the conventional baseline location for a scanned *root*.

    Args:
        root: Path: Scanned root; the baseline path is resolved inside it.
    """
    return root / DEFAULT_BASELINE_RELPATH


def summarise_for_report(report: DriftReport, *, items: list[ApiItem]) -> dict[str, Any]:
    """Combine drift counts with the undocumented-item list for text output.

    Args:
        report: DriftReport: Report whose per-kind counts are summarised.
        items: list[ApiItem]: Undocumented public items to include as data.
    """
    return {
        "drift": report.by_kind(),
        "undocumented": [item.to_dict() for item in items],
    }
