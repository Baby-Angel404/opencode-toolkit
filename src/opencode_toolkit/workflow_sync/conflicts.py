"""Three-way conflict detection.

Restoring a snapshot over a working tree is a three-way merge, not a copy. Each
path is compared against:

* ``base``    -- the snapshot being restored
* ``current`` -- what is on disk right now
* ``origin``  -- the snapshot the working tree was last synced from, if any

A path is a conflict only when the on-disk state and the incoming state have
*both* moved away from the base in different directions. A file that changed
locally while the incoming snapshot left it alone is simply "keep local" and is
reported as such, not as a conflict -- conflating the two would train users to
ignore the conflict list.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from opencode_toolkit.workflow_sync.models import Snapshot


class PathState(str, Enum):
    """How one path compares across base, current and incoming."""

    #: Identical everywhere.
    UNCHANGED = "unchanged"
    #: Only the incoming side has it.
    INCOMING_ADDED = "incoming_added"
    #: The working tree moved away from the base while the incoming side did
    #: not, so the local version stands and is never overwritten. Also covers a
    #: path that only the working tree has when no base is known. The name
    #: reflects the second case; the first is the common one in practice.
    LOCAL_ADDED = "local_added"
    #: Present in both and identical to the base.
    IDENTICAL = "identical"
    #: Both sides moved and landed on the same content. Reported as
    #: ``IDENTICAL`` rather than a state of its own: distinguishing it would add
    #: an enum member no caller can ever reach.
    #: Present in both and changed differently -- needs a human.
    CONFLICT = "conflict"
    #: Incoming removed it, current kept and changed it.
    CONFLICT_DELETE_MODIFY = "conflict_delete_modify"
    #: Current removed it, incoming changed it.
    CONFLICT_MODIFY_DELETE = "conflict_modify_delete"
    #: Incoming removed it, current left it alone -- safe to delete.
    INCOMING_DELETED = "incoming_deleted"
    #: Incoming kept it, current removed it -- keep the deletion.
    LOCAL_DELETED = "local_deleted"

    @property
    def is_conflict(self) -> bool:
        """``True`` when a human decision is required."""
        return self in _CONFLICT_STATES


_CONFLICT_STATES = frozenset(
    {PathState.CONFLICT, PathState.CONFLICT_DELETE_MODIFY, PathState.CONFLICT_MODIFY_DELETE}
)

#: States where the incoming snapshot wins and the file may be written.
INCOMING_WINS = frozenset({PathState.INCOMING_ADDED, PathState.INCOMING_DELETED})

#: States where the working tree is left untouched.
LOCAL_WINS = frozenset(
    {
        PathState.LOCAL_ADDED,
        PathState.LOCAL_DELETED,
        PathState.UNCHANGED,
        PathState.IDENTICAL,
    }
)


@dataclass(frozen=True, slots=True)
class ConflictReport:
    """Per-path merge decision plus the paths that need a human."""

    states: dict[str, PathState]
    conflicts: tuple[str, ...]
    incoming_wins: tuple[str, ...]
    local_wins: tuple[str, ...]

    @property
    def has_conflicts(self) -> bool:
        """``True`` when at least one path needs a human decision."""
        return bool(self.conflicts)

    def summary(self) -> dict[str, Any]:
        """Counts per state, for text and JSON output."""
        counts: dict[str, int] = {}
        for state in self.states.values():
            counts[state.value] = counts.get(state.value, 0) + 1
        return {
            "paths_examined": len(self.states),
            "conflict_count": len(self.conflicts),
            "counts": counts,
            "conflicts": list(self.conflicts),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialise the report, sorting states by path so output is deterministic."""
        return {
            "summary": self.summary(),
            "states": {path: state.value for path, state in sorted(self.states.items())},
            "incoming_wins": list(self.incoming_wins),
            "local_wins": list(self.local_wins),
        }


def _digest_map(snapshot: Snapshot | None) -> dict[str, str]:
    return {} if snapshot is None else {item.path: item.digest for item in snapshot.items}


def diff_snapshots(
    base: Snapshot | None,
    current: Snapshot | None,
    incoming: Snapshot,
) -> ConflictReport:
    """Three-way compare *incoming* against *base* and *current*.

    *base* is the snapshot the current tree was derived from (the "last synced"
    marker). Passing ``None`` means "unknown history", which degrades to a
    two-way compare: any local change then counts as a conflict, which is the
    conservative choice.

    Args:
        base: Snapshot | None: Snapshot the working tree was last synchronised
            from. ``None`` means the history is unknown, so every local
            difference is treated as a conflict.
        current: Snapshot | None: Observed state of the working tree. A path
            absent here is treated as deleted locally.
        incoming: Snapshot: Snapshot being restored; required, because it is the
            side of the comparison that must always be present.

    Returns:
        ConflictReport: Per-path classification, with the conflicts and the
            incoming-wins and local-wins sets already separated.
    """
    base_map = _digest_map(base)
    current_map = _digest_map(current)
    incoming_map = _digest_map(incoming)

    all_paths = sorted(set(base_map) | set(current_map) | set(incoming_map))
    states: dict[str, PathState] = {}
    conflicts: list[str] = []
    incoming_wins: list[str] = []
    local_wins: list[str] = []

    for path in all_paths:
        state = _classify(
            base_map.get(path),
            current_map.get(path),
            incoming_map.get(path),
        )
        states[path] = state
        if state.is_conflict:
            conflicts.append(path)
        elif state in INCOMING_WINS:
            incoming_wins.append(path)
        elif state in LOCAL_WINS:
            local_wins.append(path)

    return ConflictReport(
        states=states,
        conflicts=tuple(conflicts),
        incoming_wins=tuple(incoming_wins),
        local_wins=tuple(local_wins),
    )


def _classify(
    base: str | None,
    current: str | None,
    incoming: str | None,
) -> PathState:
    if incoming is not None and current is not None and incoming == current:
        return PathState.IDENTICAL

    if base is None:
        # No history: any difference between the two sides is a conflict.
        if incoming is None:
            return PathState.LOCAL_ADDED
        if current is None:
            return PathState.INCOMING_ADDED
        return PathState.CONFLICT

    if incoming == base:
        # Incoming side did not move; whatever the current tree says stands.
        if current == base:
            return PathState.UNCHANGED
        return PathState.LOCAL_ADDED if current is not None else PathState.LOCAL_DELETED

    if current == base:
        # Only the incoming side moved.
        return PathState.INCOMING_ADDED if incoming is not None else PathState.INCOMING_DELETED

    # Both sides moved away from the base.
    if incoming is None:
        return PathState.CONFLICT_DELETE_MODIFY
    if current is None:
        return PathState.CONFLICT_MODIFY_DELETE
    return PathState.CONFLICT


def plan_restore(report: ConflictReport, *, force: bool) -> tuple[list[str], list[str], list[str]]:
    """Turn a report into an executable plan.

    Returns ``(writes, deletions, blocked)``. With *force* not set, every
    conflicting path is blocked; with *force* set, conflicts are written anyway
    and returned in the third element as an explicit record that the user
    overrode the safety check.

    Args:
        report: ConflictReport: Classification produced by
            :func:`diff_snapshots`. Paths whose state is a conflict or an
            incoming change are planned; local-wins paths are left alone.
        force: bool: Write conflicting paths instead of refusing. Forcing does
            not remove a path from the third element; it is there to record the
            override.

    Returns:
        tuple[list[str], list[str], list[str]]: Workspace-relative paths to
            write, paths to delete, and paths held back as conflicts.
    """
    writes: list[str] = []
    deletions: list[str] = []
    blocked: list[str] = []
    for path, state in sorted(report.states.items()):
        if state.is_conflict:
            if force:
                writes.append(path)
                blocked.append(path)
            else:
                blocked.append(path)
            continue
        if state in INCOMING_WINS:
            if state == PathState.INCOMING_DELETED:
                deletions.append(path)
            else:
                writes.append(path)
    return writes, deletions, blocked
