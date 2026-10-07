"""Offline operation queue.

Every mutating sync operation is written to the queue *before* it is attempted
against a transport, and removed only after the transport confirms. That ordering
is what makes offline operation real rather than best-effort: if the process is
killed mid-push, the operation is still on disk and ``opencode sync status``
reports it.

The queue stores intent, not credentials. Remote destinations are referenced by
name; the passphrase is never enqueued.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio, logging
from opencode_toolkit.core.errors import StateError
from opencode_toolkit.core.fsio import ensure_dir
from opencode_toolkit.core.timeutil import to_stamp, utc_now
from opencode_toolkit.workflow_sync.models import QueueEntry

logger = logging.get_logger("workflow_sync.queue")

#: ``<stamp>-<sequence>-<id>-<operation>.json``. The sequence number is what
#: makes ordering deterministic: two entries enqueued within the same second
#: share a timestamp, and without it their relative order would depend on a
#: random uuid.
_ENTRY_RE = re.compile(
    r"^(?P<stamp>\d{8}T\d{6}Z)-(?P<sequence>\d{8})-(?P<id>[0-9a-f]{8})-(?P<op>[a-z_]+)\.json$"
)

#: Operations that may be queued. Anything else is a programming error.
ALLOWED_OPERATIONS = frozenset({"save", "push", "pull", "restore"})


class OfflineQueue:
    """A durable, ordered list of pending sync operations."""

    def __init__(self, root: Path) -> None:
        self.root = ensure_dir(root)

    def _path_for(self, entry: QueueEntry) -> Path:
        return self.root / (
            f"{_stamp(entry.created_at)}-{entry.sequence:08d}-{entry.identifier}-{entry.operation}.json"
        )

    def _next_sequence(self) -> int:
        """Return one past the highest sequence number already on disk."""
        highest = 0
        for path in self.root.glob("*.json"):
            match = _ENTRY_RE.match(path.name)
            if match is not None:
                highest = max(highest, int(match.group("sequence")))
        return highest + 1

    def enqueue(
        self, operation: str, tag: str, payload: dict[str, Any] | None = None
    ) -> QueueEntry:
        """Record an operation for later execution.

        The entry is written under mode ``0600`` and named so that the queue
        sorts in the order operations were requested.

        Args:
            operation: str: Operation to queue; must be one of
                :data:`ALLOWED_OPERATIONS`.
            tag: str: Snapshot tag the operation applies to, echoed into the
                result of :meth:`flush`.
            payload: dict[str, Any] | None: Operation arguments stored verbatim
                and handed back to the flush handler. Copied, so later mutation
                of the caller's dict does not rewrite queued state; defaults to
                an empty dict.

        Returns:
            QueueEntry: The written entry, including its generated identifier,
                sequence number and timestamp.

        Raises:
            StateError: *operation* is not an allowed operation.
        """
        if operation not in ALLOWED_OPERATIONS:
            raise StateError(
                f"cannot queue unknown operation {operation!r}",
                code="sync.unknown_operation",
                details={"allowed": sorted(ALLOWED_OPERATIONS)},
            )
        entry = QueueEntry(
            identifier=uuid.uuid4().hex[:8],
            sequence=self._next_sequence(),
            operation=operation,
            tag=tag,
            created_at=utc_now(),
            payload=dict(payload or {}),
        )
        self._write(entry)
        logger.info("queued %s for %s (offline)", operation, tag)
        return entry

    def _write(self, entry: QueueEntry) -> None:
        path = self._path_for(entry)
        jsonio.write(path, entry.to_dict())
        path.chmod(0o600)

    def pending(self) -> list[QueueEntry]:
        """Return queued entries, oldest first."""
        entries: list[QueueEntry] = []
        for path in sorted(self.root.glob("*.json")):
            document = jsonio.read(path)
            entries.append(QueueEntry.from_dict(document))
        entries.sort(key=lambda entry: (entry.created_at, entry.sequence))
        return entries

    def flush(
        self,
        handler: Callable[[QueueEntry], bool],
        *,
        max_attempts: int = 3,
    ) -> dict[str, list[str]]:
        """Attempt every queued operation with *handler*.

        Returns ``{applied: [...], failed: [...], remaining: [...]}``. An entry
        is removed only when *handler* returns ``True``; a failure increments
        ``attempts`` and, past ``max_attempts``, leaves the entry in place with
        the error recorded so nothing is silently dropped.

        Args:
            handler: Callable[[QueueEntry], bool]: Called once per queued entry
                in oldest-first order. Returning ``True`` deletes the entry;
                returning ``False`` or raising counts as a failure, and a raised
                exception is recorded on the entry as
                ``"<ExcName>: <message>"``.
            max_attempts: int: Failure count at which an entry stops being
                retried and moves from ``"failed"`` to ``"remaining"``. The
                entry stays on disk either way.

        Returns:
            dict[str, list[str]]: Entries listed as ``"<operation>:<tag>"``
                under ``applied``, ``failed`` and ``remaining``. ``remaining``
                holds entries that hit *max_attempts* during this flush, not a
                running total.
        """
        result: dict[str, list[str]] = {"applied": [], "failed": [], "remaining": []}
        for entry in self.pending():
            try:
                succeeded = handler(entry)
            except Exception as exc:
                succeeded = False
                message = f"{type(exc).__name__}: {exc}"
            else:
                message = "" if succeeded else "handler reported failure"
            if succeeded:
                path = self._path_for(entry)
                path.unlink(missing_ok=True)
                result["applied"].append(f"{entry.operation}:{entry.tag}")
                continue
            attempts = entry.attempts + 1
            self._write(
                QueueEntry(
                    identifier=entry.identifier,
                    sequence=entry.sequence,
                    operation=entry.operation,
                    tag=entry.tag,
                    created_at=entry.created_at,
                    payload=entry.payload,
                    attempts=attempts,
                    last_error=message,
                )
            )
            bucket = "remaining" if attempts >= max_attempts else "failed"
            result[bucket].append(f"{entry.operation}:{entry.tag}")
        return result

    def clear(self) -> int:
        """Remove every queued entry, returning how many were removed."""
        count = 0
        for path in self.root.glob("*.json"):
            path.unlink()
            count += 1
        return count

    def __len__(self) -> int:
        return len(list(self.root.glob("*.json")))


def _stamp(iso: str) -> str:
    """Filesystem-friendly timestamp that sorts chronologically."""
    return to_stamp(iso)
