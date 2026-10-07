"""Synchronisation between two snapshot stores.

The transport is an explicit abstraction with one shipped implementation:
:class:`DirectoryTransport`, which synchronises to another directory on the same
machine (a shared volume, a synced folder, a second checkout). This keeps the
component fully functional with **no network**, which is the point.

There is deliberately **no** network transport. ``opencode sync push`` to an
``https://`` remote reports ``NOT_IMPLEMENTED`` with the exact configuration
that would be required, instead of pretending to sync.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from opencode_toolkit.core import jsonio, logging
from opencode_toolkit.core.errors import NetworkError, StateError, UsageError
from opencode_toolkit.core.fsio import sha256_file
from opencode_toolkit.workflow_sync.models import Snapshot, SyncReport
from opencode_toolkit.workflow_sync.store import (
    BLOB_DIR,
    SNAPSHOT_SUFFIX,
    SnapshotStore,
    validate_tag,
)

logger = logging.get_logger("workflow_sync.sync")


class Transport(Protocol):
    """Where snapshots are synchronised to."""

    @property
    def name(self) -> str:
        """Short identifier recorded in push and pull results."""
        ...

    @property
    def online(self) -> bool:
        """``True`` when the destination is currently reachable."""
        ...

    def push(self, store: SnapshotStore, tag: str, *, passphrase: str | None = None) -> None:
        """Send one sealed snapshot, and whatever content it references, out.

        Args:
            store: SnapshotStore: Store holding the snapshot to send.
            tag: str: Tag of the snapshot to push.
            passphrase: str | None: Passphrase for an encrypted snapshot. An
                implementation that needs to read the manifest to decide what
                else must travel requires it; the value is never written or
                logged.
        """
        ...

    def pull(self, store: SnapshotStore, tag: str) -> None:
        """Fetch one sealed snapshot from the destination into *store*.

        Args:
            store: SnapshotStore: Store the fetched snapshot is written into.
            tag: str: Tag of the snapshot to fetch.
        """
        ...

    def has(self, tag: str) -> bool:
        """``True`` when the destination already holds *tag*.

        Args:
            tag: str: Snapshot tag to probe for. Implementations must answer
                without transferring the snapshot, so the caller can skip a
                redundant push.
        """
        ...


class DirectoryTransport:
    """Synchronise to another directory on the same filesystem tree."""

    def __init__(self, remote: Path) -> None:
        self.remote = Path(remote).expanduser()

    @property
    def name(self) -> str:
        """Identifier prefixed ``directory:`` so a report never implies a network sync."""
        return f"directory:{self.remote}"

    @property
    def online(self) -> bool:
        """A directory is always reachable; the offline case is a missing root."""
        return self.remote.is_dir()

    def has(self, tag: str) -> bool:
        """``True`` when the remote directory holds the document for *tag*.

        Args:
            tag: str: Snapshot tag to probe for; validated because it becomes
                part of the filename checked.

        Raises:
            StateError: *tag* is not a safe identifier.
        """
        return (self.remote / f"{validate_tag(tag)}{SNAPSHOT_SUFFIX}").is_file()

    def push(self, store: SnapshotStore, tag: str, *, passphrase: str | None = None) -> None:
        """Copy the sealed snapshot for *tag*, and the blobs it references, out.

        The blobs travel because :meth:`pull` restores them from this side: a
        snapshot document is a manifest of content digests, so sending the
        document alone produces a remote that exists but cannot be restored from.
        Blobs are content-addressed, so one already present is left untouched.

        Args:
            store: SnapshotStore: Store holding the snapshot to send.
            tag: str: Tag of the snapshot to push.
            passphrase: str | None: Passphrase used to read the sealed manifest
                and learn which blobs it references. Required for an encrypted
                snapshot; the value is never written or logged.

        Raises:
            StateError: The tag is unsafe, the local snapshot is missing, the
                passphrase is absent for an encrypted snapshot, or the store is
                missing content the manifest references.
        """
        source = store.snapshot_path(tag)
        if not source.is_file():
            raise StateError(f"cannot push missing snapshot {tag!r}", details={"tag": tag})
        snapshot = store.load(tag, passphrase=passphrase)
        self.remote.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, self.remote / source.name)

        remote_blobs = self.remote / BLOB_DIR
        for item in snapshot.items:
            blob = store.blob_dir / item.digest
            if not blob.is_file():
                raise StateError(
                    f"snapshot {tag!r} references missing content {item.digest[:12]}...",
                    details={"tag": tag, "digest": item.digest},
                    hint="the local store is incomplete; re-create the snapshot with `opencode sync save`",
                )
            destination = remote_blobs / blob.name
            if destination.exists():
                continue
            remote_blobs.mkdir(parents=True, exist_ok=True)
            shutil.copy2(blob, destination)
        logger.info("pushed %s with %d blob(s) to %s", tag, len(snapshot.items), self.remote)

    def pull(self, store: SnapshotStore, tag: str) -> None:
        """Copy the remote snapshot for *tag* into *store*, blobs included.

        Existing blobs are never overwritten: the remote copy is by name the
        same content-addressed entry, and clobbering a local blob would rewrite
        history that other snapshots still reference.

        Args:
            store: SnapshotStore: Store the snapshot and its blobs are written into.
            tag: str: Tag of the snapshot to fetch.

        Raises:
            StateError: The tag is unsafe or the remote holds no such snapshot.
        """
        source = self.remote / f"{validate_tag(tag)}{SNAPSHOT_SUFFIX}"
        if not source.is_file():
            raise StateError(
                f"remote {self.name} does not have snapshot {tag!r}",
                details={"tag": tag, "remote": str(self.remote)},
            )
        shutil.copy2(source, store.snapshot_path(tag))
        # The remote carries only the sealed document; blobs travel alongside it.
        remote_blobs = self.remote / "blobs"
        if remote_blobs.is_dir():
            store.blob_dir.mkdir(parents=True, exist_ok=True)
            for blob in remote_blobs.glob("*"):
                destination = store.blob_dir / blob.name
                if not destination.exists():
                    shutil.copy2(blob, destination)


def unavailable_transport(target: str, *, create: bool = False) -> Transport:
    """Build a transport for *target*, or explain precisely why none is available.

    *create* allows the destination not to exist yet. It is set for ``push``,
    which is the operation that legitimately creates a remote, and left off for
    ``pull``, where a missing directory means the operator named the wrong path.

    Args:
        target: str: Remote named on the command line; a local directory path
            with ``~`` expanded. An ``http://`` or ``https://`` URL is rejected,
            since no network transport is implemented.
        create: bool: Allow a directory transport to be returned for a path that
            does not exist yet.

    Returns:
        Transport: A :class:`DirectoryTransport` for the local path. The
            returned transport's ``online`` property is ``False`` while the
            directory is missing, even with *create* set.

    Raises:
        NetworkError: *target* is a URL; no network transport exists.
        UsageError: *target* does not exist and *create* is not set.
    """
    if target.startswith(("http://", "https://")):
        raise NetworkError(
            "no network transport is implemented for remote sync",
            code="sync.transport_unavailable",
            details={
                "requested": target,
                "implemented": ["file:// directory path", "local directory path"],
            },
            hint=(
                "point --remote at a local directory (shared volume, synced folder, second checkout), "
                "or add a Transport implementation that satisfies the documented protocol"
            ),
        )
    path = Path(target).expanduser()
    if not path.exists():
        if create:
            return DirectoryTransport(path)
        raise UsageError(
            f"remote path does not exist: {path}",
            details={"path": str(path)},
            hint="create the directory first, or use `opencode sync save` to work entirely offline",
        )
    return DirectoryTransport(path)


@dataclass(slots=True)
class PushResult:
    """Outcome of one push."""

    tag: str
    transport: str
    transferred: bool
    already_present: bool
    note: str = ""


def push(
    store: SnapshotStore, tag: str, transport: Transport, *, passphrase: str | None = None
) -> PushResult:
    """Push one snapshot, skipping the copy when the remote already matches.

    Args:
        store: SnapshotStore: Local store holding the sealed snapshot.
        tag: str: Tag of the snapshot to push.
        transport: Transport: Destination to push to. It decides what travels;
            only the sealed document and the blobs it references do.
        passphrase: str | None: Passphrase for an encrypted snapshot; the
            transport needs it to learn which blobs the manifest references.

    Returns:
        PushResult: Whether anything was transferred, plus a note when the copy
            was skipped because the remote already had a document of that name.

    Raises:
        StateError: The tag is unsafe, the local snapshot is missing, or the
            passphrase is absent for an encrypted snapshot.
    """
    if transport.has(tag):
        return PushResult(
            tag=tag,
            transport=transport.name,
            transferred=False,
            already_present=True,
            note="remote already has this snapshot with the same name; nothing sent",
        )
    transport.push(store, tag, passphrase=passphrase)
    return PushResult(tag=tag, transport=transport.name, transferred=True, already_present=False)


def pull(
    store: SnapshotStore,
    tag: str,
    transport: Transport,
    *,
    passphrase: str | None = None,
) -> Snapshot:
    """Pull one snapshot into *store*, index it, and return the decoded snapshot.

    Args:
        store: SnapshotStore: Store the snapshot and its blobs are written into.
        tag: str: Tag of the snapshot to fetch.
        transport: Transport: Source the snapshot is fetched from. Existing local
            blobs are never overwritten.
        passphrase: str | None: Passphrase used to unseal the snapshot; required
            only when the fetched document is encrypted.

    Returns:
        Snapshot: The decoded snapshot, so the caller gets verified content
            rather than having to reload it.

    Raises:
        StateError: The tag is unsafe, the remote holds no such snapshot, or the
            snapshot is encrypted with no passphrase supplied.
    """
    transport.pull(store, tag)
    document = jsonio.read(store.snapshot_path(tag))
    store.record_pulled(
        tag=tag,
        created_at=str(document.get("created_at", "")),
        item_count=int(document.get("item_count", 0)),
        total_bytes=int(document.get("total_bytes", 0)),
        encrypted=bool(document.get("encrypted", True)),
        source=transport.name,
    )
    return store.load(tag, passphrase=passphrase)


def verify_copy(source: Path, target: Path) -> bool:
    """Return ``True`` when two files have identical digests.

    Args:
        source: Path: First file to compare.
        target: Path: Second file to compare. A missing file on either side
            returns ``False`` rather than raising, because this backs a
            post-copy verification where absence means the copy failed.
    """
    if not source.is_file() or not target.is_file():
        return False
    return sha256_file(source) == sha256_file(target)


def summarise(report: SyncReport) -> str:
    """One-line human summary used by the CLI.

    Args:
        report: SyncReport: Outcome to describe. Counts are appended only for
            the non-empty fields, so an uneventful sync stays short.
    """
    parts = [f"{report.action} {report.tag}"]
    if report.applied:
        parts.append(f"{len(report.applied)} applied")
    if report.conflicts:
        parts.append(f"{len(report.conflicts)} conflicted")
    if report.queued:
        parts.append("queued")
    return ", ".join(parts)
