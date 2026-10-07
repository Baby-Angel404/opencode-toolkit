"""Snapshot data model.

A snapshot is the unit of synchronisation: a named, timestamped, immutable
record of a set of tracked paths with their digests, plus the metadata needed to
explain what the snapshot was for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from opencode_toolkit.core.errors import StateError
from opencode_toolkit.core.timeutil import utc_now
from opencode_toolkit.core.version import detect_version

#: Marker written into every snapshot so a foreign file is rejected with a clear
#: message instead of a KeyError deep inside parsing.
SNAPSHOT_KIND = "opencode-toolkit/snapshot"
SNAPSHOT_SCHEMA = 1


def parse_timestamp(text: str) -> datetime:
    """Parse a snapshot timestamp, raising :class:`StateError` when malformed.

    Args:
        text: str: Timestamp in ``YYYY-MM-DDTHH:MM:SSZ`` form, as written by
            :func:`opencode_toolkit.core.timeutil.utc_now`.

    Raises:
        StateError: *text* does not match that format.
    """
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise StateError(
            f"invalid snapshot timestamp: {text!r}",
            details={"expected": "YYYY-MM-DDTHH:MM:SSZ"},
        ) from exc


@dataclass(frozen=True, slots=True)
class SnapshotItem:
    """One tracked file inside a snapshot.

    ``digest`` is the SHA-256 of the file bytes and is the only thing conflict
    detection compares; mode is recorded so a restore can restore permissions.
    """

    path: str
    digest: str
    size: int
    mode: int = 0o644
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the item form embedded in a snapshot document."""
        return {
            "path": self.path,
            "digest": self.digest,
            "size": self.size,
            "mode": self.mode,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> SnapshotItem:
        """Rebuild an item, converting a malformed document into a ``StateError``.

        Args:
            document: dict[str, Any]: One entry of a snapshot document's ``items`` list.

        Raises:
            StateError: A required key is missing or a value has the wrong type.
        """
        try:
            return cls(
                path=str(document["path"]),
                digest=str(document["digest"]),
                size=int(document["size"]),
                mode=int(document.get("mode", 0o644)),
                note=str(document.get("note", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError(
                f"malformed snapshot item: {exc}",
                details={"reason": type(exc).__name__},
            ) from exc


@dataclass(frozen=True, slots=True)
class Snapshot:
    """An immutable, named capture of tracked paths."""

    tag: str
    created_at: str
    workspace: str
    items: tuple[SnapshotItem, ...] = ()
    encrypted: bool = True
    tool_version: str = ""
    description: str = ""
    #: Content digests of the *decrypted* payload, used to detect corruption
    #: that survives AEAD verification (for example a wrong schema).
    payload_digest: str = ""

    def __post_init__(self) -> None:
        if not self.tag:
            raise StateError("snapshot tag must not be empty")

    @property
    def item_map(self) -> dict[str, SnapshotItem]:
        """Return ``{path: item}`` for conflict computation."""
        return {item.path: item for item in self.items}

    def total_bytes(self) -> int:
        """Sum of the tracked file sizes."""
        return sum(item.size for item in self.items)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a snapshot document, stamping kind, schema and tool version."""
        return {
            "kind": SNAPSHOT_KIND,
            "schema": SNAPSHOT_SCHEMA,
            "tag": self.tag,
            "created_at": self.created_at,
            "workspace": self.workspace,
            "encrypted": self.encrypted,
            "tool_version": self.tool_version or str(detect_version()),
            "description": self.description,
            "payload_digest": self.payload_digest,
            "item_count": len(self.items),
            "total_bytes": self.total_bytes(),
            "items": [item.to_dict() for item in self.items],
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Snapshot:
        """Rebuild a snapshot after checking kind and schema.

        Args:
            document: dict[str, Any]: A decoded snapshot document, sealed payload already opened.

        Raises:
            StateError: The document is not a snapshot, uses an unsupported
                schema, or its ``items`` is not a list.
        """
        if document.get("kind") != SNAPSHOT_KIND:
            raise StateError(
                "not an opencode-toolkit snapshot",
                details={"found_kind": document.get("kind")},
            )
        schema = document.get("schema")
        if schema != SNAPSHOT_SCHEMA:
            raise StateError(
                f"unsupported snapshot schema {schema!r}; this build understands {SNAPSHOT_SCHEMA}",
                details={"schema": schema, "supported": SNAPSHOT_SCHEMA},
            )
        raw_items = document.get("items")
        if not isinstance(raw_items, list):
            raise StateError("snapshot 'items' must be a list")
        return cls(
            tag=str(document.get("tag", "")),
            created_at=str(document.get("created_at", utc_now())),
            workspace=str(document.get("workspace", "")),
            items=tuple(SnapshotItem.from_dict(item) for item in raw_items),
            encrypted=bool(document.get("encrypted", True)),
            tool_version=str(document.get("tool_version", "")),
            description=str(document.get("description", "")),
            payload_digest=str(document.get("payload_digest", "")),
        )


@dataclass(frozen=True, slots=True)
class QueueEntry:
    """One deferred operation recorded while no transport was available."""

    identifier: str
    sequence: int
    operation: str
    tag: str
    created_at: str
    payload: dict[str, Any] = field(default_factory=dict)
    attempts: int = 0
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a queue entry; ``identifier`` is written as ``id``."""
        return {
            "id": self.identifier,
            "sequence": self.sequence,
            "operation": self.operation,
            "tag": self.tag,
            "created_at": self.created_at,
            "payload": self.payload,
            "attempts": self.attempts,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> QueueEntry:
        """Rebuild a queue entry, defaulting every absent field.

        Args:
            document: dict[str, Any]: One decoded record from the queue directory.
        """
        return cls(
            identifier=str(document.get("id", "")),
            sequence=int(document.get("sequence", 0)),
            operation=str(document.get("operation", "")),
            tag=str(document.get("tag", "")),
            created_at=str(document.get("created_at", utc_now())),
            payload=dict(document.get("payload", {})),
            attempts=int(document.get("attempts", 0)),
            last_error=str(document.get("last_error", "")),
        )


@dataclass(frozen=True, slots=True)
class SyncStatus:
    """Aggregate status of the snapshot store."""

    store_path: str
    snapshot_count: int
    latest_tag: str | None
    latest_created_at: str | None
    queued_operations: int
    encryption_available: bool
    cipher: str
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialise for ``opencode sync status`` output."""
        return {
            "store_path": self.store_path,
            "snapshot_count": self.snapshot_count,
            "latest_tag": self.latest_tag,
            "latest_created_at": self.latest_created_at,
            "queued_operations": self.queued_operations,
            "encryption_available": self.encryption_available,
            "cipher": self.cipher,
            "notes": list(self.notes),
        }


@dataclass(slots=True)
class SyncReport:
    """Outcome of a save, restore or push/pull operation."""

    action: str
    tag: str
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    #: Paths overwritten with ``--force``. Reported separately from ``conflicts``
    #: because the operator explicitly asked for them; a successful forced
    #: restore exits 0.
    forced: list[str] = field(default_factory=list)
    queued: bool = False
    encrypted: bool = True
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """``True`` when nothing conflicted and nothing errored.

        A forced override does not make a restore unsuccessful: the operator
        asked for it, and blocking on it afterwards would make ``--force``
        unusable from a script.
        """
        return not self.conflicts and not self.errors

    def to_dict(self) -> dict[str, Any]:
        """Serialise the report, sorting every path list for deterministic output."""
        return {
            "action": self.action,
            "tag": self.tag,
            "applied": sorted(self.applied),
            "skipped": sorted(self.skipped),
            "conflicts": sorted(self.conflicts),
            "forced": sorted(self.forced),
            "queued": self.queued,
            "encrypted": self.encrypted,
            "notes": list(self.notes),
            "errors": list(self.errors),
            "ok": self.ok,
        }
