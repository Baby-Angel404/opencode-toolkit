"""Workflow snapshot synchronisation.

Captures project state (configuration, notes, session metadata and tracked
files), stores it as an encrypted, checksummed snapshot, and reconciles snapshots
across two checkouts without ever silently overwriting a conflicting file.

Guarantees this module is responsible for:

* snapshots are authenticated (see :mod:`opencode_toolkit.workflow_sync.crypto`)
* an offline queue lets save/restore work with no network at all
* three-way conflict detection refuses destructive restores and reports the
  exact set of conflicting paths
"""

from __future__ import annotations

from opencode_toolkit.workflow_sync.conflicts import (
    ConflictReport,
    PathState,
    diff_snapshots,
)
from opencode_toolkit.workflow_sync.models import (
    QueueEntry,
    Snapshot,
    SnapshotItem,
    SyncReport,
    SyncStatus,
)
from opencode_toolkit.workflow_sync.store import SnapshotStore

__all__ = [
    "ConflictReport",
    "PathState",
    "QueueEntry",
    "Snapshot",
    "SnapshotItem",
    "SnapshotStore",
    "SyncReport",
    "SyncStatus",
    "diff_snapshots",
]
