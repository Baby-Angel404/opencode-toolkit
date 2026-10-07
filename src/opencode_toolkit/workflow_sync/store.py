"""Encrypted snapshot store and restore.

Layout under the state directory::

    snapshots/
        index.json                 -- listing metadata (no secrets)
        <tag>.snapshot.json        -- sealed payload (ciphertext + tag only)
        blobs/<sha256>             -- content-addressed tracked file contents

Tracked file contents live in a content-addressed blob store, so two snapshots
sharing a file store it once. Everything under ``snapshots/`` is written
atomically and mode ``0600``; the index contains digests and tags only.

Encryption applies to the snapshot document by default. Pass
``--no-encrypt`` only for state that is provably non-sensitive, and the report
says so explicitly rather than silently degrading.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio, logging
from opencode_toolkit.core.config import SyncPolicy
from opencode_toolkit.core.errors import (
    ConflictError,
    NotFoundError,
    StateError,
    StorageError,
)
from opencode_toolkit.core.fsio import (
    ensure_dir,
    sha256_bytes,
    sha256_file,
    write_bytes_atomic,
    write_new,
    write_text_atomic,
)
from opencode_toolkit.core.redact import redact_env_assignments
from opencode_toolkit.core.timeutil import utc_now
from opencode_toolkit.core.version import detect_version
from opencode_toolkit.workflow_sync import crypto
from opencode_toolkit.workflow_sync.conflicts import ConflictReport, diff_snapshots, plan_restore
from opencode_toolkit.workflow_sync.models import (
    SNAPSHOT_KIND,
    SNAPSHOT_SCHEMA,
    Snapshot,
    SnapshotItem,
    SyncReport,
    SyncStatus,
)

logger = logging.get_logger("workflow_sync.store")

#: Magic prefix identifying a sealed blob. Blobs are sealed exactly like the
#: snapshot document: sealing only the manifest would leave every tracked file's
#: contents sitting in plaintext on disk.
SEALED_MAGIC = b"OCTKSEAL1\n"

INDEX_NAME = "index.json"
POINTER_NAME = "last-synced.json"
SNAPSHOT_SUFFIX = ".snapshot.json"
BLOB_DIR = "blobs"

#: Tags must be filesystem-safe and stable; they become filenames.
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

#: Paths that are never captured, even if a caller asks for the whole workspace.
FORBIDDEN_TRACKED = frozenset({".git", ".venv", "node_modules", "__pycache__", ".ssh", ".aws"})

#: Tracked by default. Callers can extend, never implicitly shrink, without saying so.
DEFAULT_TRACKED = (
    ".opencode/toolkit/config.json",
    "opencode.yml",
    "opencode.json",
    "AGENTS.md",
    "README.md",
    "docs",
    "examples",
)


def validate_tag(tag: str) -> str:
    """Return *tag* when it is a safe snapshot identifier.

    Args:
        tag: str: Candidate tag. Tags become filenames, so the allowed shape is
            1-64 characters of letters, digits, dot, underscore or dash, starting
            alphanumeric.

    Raises:
        StateError: *tag* does not match that shape.
    """
    if not _TAG_RE.match(tag):
        raise StateError(
            f"invalid snapshot tag: {tag!r}",
            code="sync.invalid_tag",
            details={
                "tag": tag,
                "allowed": "alphanumeric, dot, underscore, dash; 1-64 characters; must start alphanumeric",
            },
        )
    return tag


def default_tag(prefix: str = "snapshot") -> str:
    """Return a sortable, collision-resistant default tag.

    Args:
        prefix: str: Readable prefix joined to a UTC stamp of the form
            ``20260102T030405Z``; defaults to ``"snapshot"``.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}"


class SnapshotStore:
    """Filesystem-backed store for encrypted snapshots and their blobs."""

    def __init__(self, root: Path, policy: SyncPolicy | None = None) -> None:
        self.root = ensure_dir(root)
        self.policy = policy or SyncPolicy()
        self._ensure_layout()

    # -- layout -----------------------------------------------------------
    def _ensure_layout(self) -> None:
        ensure_dir(self.root)
        ensure_dir(self.blob_dir)
        index = self.root / INDEX_NAME
        if not index.exists():
            jsonio.write(
                index, {"kind": "opencode-toolkit/snapshot-index", "schema": 1, "entries": []}
            )
            index.chmod(stat.S_IRUSR | stat.S_IWUSR)
        pointer = self.root / POINTER_NAME
        if not pointer.exists():
            jsonio.write(pointer, {"last_applied": None, "history": []})
            pointer.chmod(stat.S_IRUSR | stat.S_IWUSR)

    @property
    def blob_dir(self) -> Path:
        """Directory holding the content-addressed tracked file contents."""
        return self.root / BLOB_DIR

    @property
    def index_path(self) -> Path:
        """Path of the listing metadata; it holds tags and digests, never secrets."""
        return self.root / INDEX_NAME

    @property
    def pointer_path(self) -> Path:
        """Path of the last-applied marker used as the three-way merge base."""
        return self.root / POINTER_NAME

    # -- last-applied pointer --------------------------------------------
    def last_applied(self) -> str | None:
        """Tag of the snapshot the working tree was last synchronised from."""
        if not self.pointer_path.exists():
            return None
        document = jsonio.read(self.pointer_path)
        value = document.get("last_applied")
        return str(value) if value else None

    def set_last_applied(self, tag: str) -> None:
        """Record *tag* as the base for the next three-way merge.

        The tag is moved to the end of a bounded history, which keeps repeated
        restores of the same snapshot from filling the marker with duplicates.
        The write is followed by a chmod because the marker names the snapshot a
        working tree was synced from.

        Args:
            tag: str: Tag of the snapshot that was just applied.
        """
        document = jsonio.read(self.pointer_path) if self.pointer_path.exists() else {"history": []}
        history = [item for item in document.get("history", []) if item != tag]
        jsonio.write(
            self.pointer_path,
            {"last_applied": tag, "history": [*history, tag][-20:]},
        )
        self.pointer_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def record_pulled(
        self,
        *,
        tag: str,
        created_at: str,
        item_count: int,
        total_bytes: int,
        encrypted: bool,
        source: str,
    ) -> None:
        """Index a snapshot obtained from a remote transport.

        Args:
            tag: str: Tag of the pulled snapshot; it becomes an index entry and
                a filename, so it must already be a safe identifier.
            created_at: str: Timestamp recorded for the snapshot, taken from the
                remote document rather than generated locally.
            item_count: int: Number of items in the remote snapshot. Passed
                explicitly because the sealed document is not decrypted here.
            total_bytes: int: Total plaintext size of those items, in bytes.
            encrypted: bool: Whether the remote snapshot was sealed.
            source: str: Human-readable origin used in the index description.
        """
        self._index_add(
            Snapshot(
                tag=tag,
                created_at=created_at,
                workspace="",
                encrypted=encrypted,
                description=f"pulled from {source}",
            ),
            item_count=item_count,
            total_bytes=total_bytes,
        )

    def snapshot_path(self, tag: str) -> Path:
        """Return the path holding the sealed document for *tag*.

        Args:
            tag: str: Snapshot tag; validated because it becomes a filename.

        Raises:
            StateError: The tag is not a safe identifier.
        """
        return self.root / f"{validate_tag(tag)}{SNAPSHOT_SUFFIX}"

    # -- blobs ------------------------------------------------------------
    def put_blob(self, data: bytes, *, encrypt: bool = False, passphrase: str | None = None) -> str:
        """Store *data* content-addressed and return the digest of the plaintext.

        The blob is addressed by the **plaintext** digest so two snapshots that
        share a file share one blob. Its *contents* are sealed when *encrypt* is
        set; the ciphertext then varies per snapshot, which is why the file is
        only rewritten when it does not yet exist.

        Args:
            data: bytes: Plaintext content to store; the returned digest is taken
                over these bytes, not over any ciphertext.
            encrypt: bool: Seal the blob contents. Defaulting to ``False`` here is
                safe only because the caller has already decided the snapshot's
                encryption posture.
            passphrase: str | None: Passphrase used to seal the blob; required
                when *encrypt* is ``True``.

        Returns:
            str: Lowercase hex SHA-256 digest of *data*, which is also the blob's
                filename.

        Raises:
            StateError: *encrypt* is set but no passphrase was supplied.
        """
        digest = sha256_bytes(data)
        target = self.blob_dir / digest
        if target.exists():
            return digest
        if encrypt:
            if not passphrase:
                raise StateError(
                    "encryption is enabled but no passphrase was supplied for blob storage",
                    code="sync.passphrase_required",
                    details={"digest": digest},
                )
            sealed = crypto.seal(data, passphrase, iterations=self.policy.kdf_iterations)
            payload = SEALED_MAGIC + jsonio.dump_compact(sealed.to_dict()).encode("utf-8")
        else:
            payload = data
        write_bytes_atomic(target, payload, mode=0o600)
        return digest

    def get_blob(self, digest: str, *, passphrase: str | None = None) -> bytes:
        """Read a blob, decrypting when sealed and always verifying its digest.

        The digest is checked against the *decrypted* content, so a blob that was
        tampered with is rejected by authentication and a blob that decrypts to
        the wrong bytes is rejected by the digest. Neither check can be skipped.

        Args:
            digest: str: Lowercase hex SHA-256 digest of the plaintext, taken
                from :meth:`put_blob`.
            passphrase: str | None: Passphrase used to unseal the blob; required
                only when the stored blob is encrypted.

        Raises:
            StateError: The digest is malformed, the blob is encrypted and no
                passphrase was supplied, or the content does not match *digest*.
            NotFoundError: No blob is stored under *digest*.
        """
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise StateError(f"malformed blob digest: {digest!r}", code="sync.invalid_digest")
        path = self.blob_dir / digest
        if not path.is_file():
            raise NotFoundError(
                f"snapshot content is missing from the store: {digest[:12]}...",
                code="sync.missing_blob",
                details={"digest": digest, "path": str(path)},
                hint="the snapshot cannot be restored; re-create it with `opencode sync save`",
            )
        raw = path.read_bytes()
        data = self._decode_blob(raw, digest, passphrase=passphrase)
        actual = sha256_bytes(data)
        if actual != digest:
            raise StateError(
                "blob content does not match its digest; the store is corrupt",
                code="sync.blob_corrupt",
                details={"expected": digest, "actual": actual},
            )
        return data

    def _decode_blob(self, raw: bytes, digest: str, *, passphrase: str | None) -> bytes:
        """Return the plaintext for a stored blob, raising on a malformed one."""
        if not raw.startswith(SEALED_MAGIC):
            if SEALED_MAGIC[:1] in raw[:1]:
                raise StateError(
                    "blob is neither plaintext nor a recognised sealed payload",
                    code="sync.blob_corrupt",
                    details={"digest": digest, "first_byte": raw[:1].hex()},
                    hint="the store has been tampered with or truncated",
                )
            return raw
        if not passphrase:
            raise StateError(
                "blob is encrypted and needs a passphrase",
                code="sync.passphrase_required",
                details={"digest": digest},
            )
        document = jsonio.loads(
            raw[len(SEALED_MAGIC) :].decode("utf-8"), source=f"blob:{digest[:12]}"
        )
        return crypto.open_sealed(crypto.SealedPayload.from_dict(document), passphrase)

    # -- save -------------------------------------------------------------
    def save(
        self,
        workspace: Path,
        *,
        tag: str | None = None,
        description: str = "",
        tracked: tuple[str, ...] = DEFAULT_TRACKED,
        encrypt: bool | None = None,
        passphrase: str | None = None,
    ) -> tuple[Snapshot, SyncReport]:
        """Capture *tracked* paths from *workspace* into a new snapshot.

        Args:
            workspace: Path: Root that every captured path is made relative to;
                resolved before capture. Symlinks and the directories in
                :data:`FORBIDDEN_TRACKED` are never captured.
            tag: str | None: Tag for the new snapshot; generated with
                :func:`default_tag` when ``None``. Snapshots are immutable, so a
                tag already in use is refused rather than overwritten.
            description: str: Free-text note stored alongside the snapshot.
            tracked: tuple[str, ...]: Workspace-relative paths to capture. A
                directory contributes all of its files.
            encrypt: bool | None: Seal the snapshot. ``None`` defers to
                ``policy.encrypt_by_default``.
            passphrase: str | None: Passphrase used to seal the snapshot and any
                tracked file contents; required when encryption is in effect.

        Returns:
            tuple[Snapshot, SyncReport]: The stored snapshot and a report of the
                paths written plus the encryption notes.

        Raises:
            ConflictError: *tag* names an existing snapshot.
            StateError: Encryption is enabled with no passphrase, or none of the
                *tracked* paths exist.
        """
        tag = validate_tag(tag or default_tag())
        path = self.snapshot_path(tag)
        if path.exists():
            raise ConflictError(
                f"snapshot {tag!r} already exists",
                conflicts=[str(path)],
                hint="choose another tag; snapshots are immutable by design",
            )

        should_encrypt = self.policy.encrypt_by_default if encrypt is None else encrypt
        items = self._collect(workspace, tracked, encrypt=should_encrypt, passphrase=passphrase)
        if not items:
            raise StateError(
                "nothing to snapshot: none of the tracked paths exist",
                code="sync.nothing_tracked",
                details={"tracked": list(tracked), "workspace": str(workspace)},
            )

        payload = Snapshot(
            tag=tag,
            created_at=utc_now(),
            workspace=str(workspace),
            items=tuple(items),
            encrypted=should_encrypt,
            tool_version=str(detect_version()),
            description=description,
        )
        document = payload.to_dict()
        document["payload_digest"] = sha256_bytes(
            jsonio.dump_compact(document["items"]).encode("utf-8")
        )

        if should_encrypt:
            if not passphrase:
                raise StateError(
                    "encryption is enabled but no passphrase was supplied",
                    code="sync.passphrase_required",
                    details={"tag": tag},
                    hint="supply a passphrase, or pass --no-encrypt if this state holds nothing sensitive",
                )
            sealed = crypto.seal(
                jsonio.dump_compact(document).encode("utf-8"),
                passphrase,
                iterations=self.policy.kdf_iterations,
            )
            # The sealed blob is nested so its own "tag" field (the
            # authentication tag) cannot collide with snapshot metadata.
            jsonio.write(
                path,
                {
                    "kind": SNAPSHOT_KIND,
                    "schema": SNAPSHOT_SCHEMA,
                    "tag": tag,
                    "created_at": payload.created_at,
                    "item_count": len(items),
                    "total_bytes": payload.total_bytes(),
                    "encrypted": True,
                    "sealed": sealed.to_dict(),
                },
            )
        else:
            jsonio.write(path, document)

        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self._index_add(payload)

        report = SyncReport(
            action="save",
            tag=tag,
            applied=[item.path for item in items],
            encrypted=should_encrypt,
            notes=(
                [
                    f"sealed with {crypto.CIPHER_HMAC_CTR} and PBKDF2-HMAC-SHA256 x{self.policy.kdf_iterations}"
                ]
                if should_encrypt
                else ["snapshot stored unencrypted; it contains no credential material"]
            ),
        )
        return payload, report

    def _collect(
        self,
        workspace: Path,
        tracked: tuple[str, ...],
        *,
        encrypt: bool,
        passphrase: str | None,
    ) -> list[SnapshotItem]:
        items: list[SnapshotItem] = []
        workspace = workspace.resolve()
        for relative in tracked:
            candidate = workspace / relative
            if candidate.is_symlink():
                logger.debug("skipping symlink %s", relative)
                continue
            if candidate.is_file():
                items.append(
                    self._item_for(workspace, candidate, encrypt=encrypt, passphrase=passphrase)
                )
            elif candidate.is_dir():
                for path in self._walk(candidate, workspace):
                    items.append(
                        self._item_for(workspace, path, encrypt=encrypt, passphrase=passphrase)
                    )
        items.sort(key=lambda item: item.path)
        deduped: list[SnapshotItem] = []
        seen: set[str] = set()
        for item in items:
            if item.path in seen:
                continue
            seen.add(item.path)
            deduped.append(item)
        return deduped

    def _walk(self, root: Path, workspace: Path) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(
                d for d in dirnames if d not in FORBIDDEN_TRACKED and not d.startswith(".")
            )
            for name in sorted(filenames):
                candidate = Path(dirpath) / name
                try:
                    candidate.relative_to(workspace)
                except ValueError:  # pragma: no cover - os.walk stays under root
                    continue
                yield candidate

    def _item_for(
        self,
        workspace: Path,
        path: Path,
        *,
        encrypt: bool,
        passphrase: str | None,
    ) -> SnapshotItem:
        relative = path.relative_to(workspace).as_posix()
        data = path.read_bytes()
        if self.policy.redact_env_files and path.name in {".env", ".env.local", ".env.production"}:
            lines = data.decode("utf-8", "replace").splitlines()
            data = "\n".join(redact_env_assignments(lines)).encode("utf-8")
        digest = self.put_blob(data, encrypt=encrypt, passphrase=passphrase)
        return SnapshotItem(
            path=relative,
            digest=digest,
            size=len(data),
            mode=stat.S_IMODE(path.stat().st_mode) & 0o777,
        )

    # -- load -------------------------------------------------------------
    def load(self, tag: str, *, passphrase: str | None = None) -> Snapshot:
        """Load a snapshot, decrypting and verifying it when necessary.

        Args:
            tag: str: Tag of the snapshot to read; validated because it becomes a
                filename.
            passphrase: str | None: Passphrase used to unseal the snapshot; required
                only when the stored document is encrypted.

        Raises:
            NotFoundError: No snapshot is stored under *tag*.
            StateError: The document is not a snapshot, is encrypted with no
                passphrase supplied, or its payload digest does not match, meaning
                it was modified.
        """
        path = self.snapshot_path(tag)
        if not path.is_file():
            raise NotFoundError(
                f"no snapshot named {tag!r}",
                code="sync.snapshot_not_found",
                details={"tag": tag, "known": [item["tag"] for item in self._index()]},
                hint="run `opencode sync list` to see available snapshots",
            )
        document = jsonio.read(path)
        if document.get("kind") != SNAPSHOT_KIND:
            raise StateError(
                f"{path} is not a snapshot document",
                details={"found_kind": document.get("kind")},
            )
        if document.get("encrypted") or "sealed" in document:
            if not passphrase:
                raise StateError(
                    f"snapshot {tag!r} is encrypted and needs a passphrase",
                    code="sync.passphrase_required",
                    details={"tag": tag},
                )
            sealed = crypto.SealedPayload.from_dict(document["sealed"])
            plain = crypto.open_sealed(sealed, passphrase)
            payload = jsonio.loads(plain.decode("utf-8"), source=str(path))
        else:
            payload = document

        snapshot = Snapshot.from_dict(payload)
        expected = payload.get("payload_digest")
        if expected:
            actual = sha256_bytes(jsonio.dump_compact(payload["items"]).encode("utf-8"))
            if actual != expected:
                raise StateError(
                    "snapshot payload digest mismatch; the file has been modified",
                    code="sync.payload_corrupt",
                    details={"expected": expected, "actual": actual, "tag": tag},
                )
        return snapshot

    # -- restore ----------------------------------------------------------
    def restore(
        self,
        workspace: Path,
        tag: str,
        *,
        passphrase: str | None = None,
        base_tag: str | None = None,
        force: bool = False,
    ) -> tuple[ConflictReport, SyncReport]:
        """Restore *tag* into *workspace*, refusing to clobber conflicts.

        Args:
            workspace: Path: Directory the snapshot is written into; resolved
                before writing.
            tag: str: Tag of the snapshot to restore.
            passphrase: str | None: Passphrase used to unseal the snapshot and
                its blobs; required only for encrypted snapshots.
            base_tag: str | None: Snapshot recorded as the merge base, normally
                the one last applied via ``set_last_applied``. ``None`` disables
                the three-way comparison, so every differing path is treated as
                changed on both sides.
            force: bool: Overwrite conflicting paths instead of refusing. The
                overwritten paths are listed in the report either way.

        Returns:
            tuple[ConflictReport, SyncReport]: The full diff of base, current and
                snapshot state, and what was actually written, deleted, skipped
                or blocked.

        Raises:
            NotFoundError: *tag* or *base_tag* names no stored snapshot.
            StateError: A snapshot is encrypted and no passphrase was supplied.
        """
        snapshot = self.load(tag, passphrase=passphrase)
        base = self.load(base_tag, passphrase=passphrase) if base_tag else None
        current = self.snapshot_of(workspace, [item.path for item in snapshot.items])
        report = diff_snapshots(base, current, snapshot)
        writes, deletions, blocked = plan_restore(report, force=force)

        result = SyncReport(action="restore", tag=tag, encrypted=snapshot.encrypted)
        if force:
            result.forced = list(blocked)
        else:
            result.conflicts = list(blocked)
        if blocked and not force:
            result.notes.append(
                f"{len(blocked)} path(s) changed both locally and in the snapshot; "
                "nothing was written for them"
            )
            result.notes.append(
                "re-run with --force to overwrite, after reviewing the conflict list"
            )
            return report, result

        for relative in writes:
            item = snapshot.item_map[relative]
            data = self.get_blob(item.digest, passphrase=passphrase)
            target = workspace / relative
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                write_bytes_atomic(target, data, mode=item.mode)
                result.applied.append(relative)
            except StorageError as exc:
                result.errors.append(f"{relative}: {exc.message}")

        for relative in deletions:
            target = workspace / relative
            try:
                target.unlink(missing_ok=True)
                result.skipped.append(relative)
            except OSError as exc:
                result.errors.append(f"{relative}: {exc.strerror or exc}")

        if blocked and force:
            result.notes.append(
                f"--force overwrote {len(blocked)} conflicting path(s): "
                f"{', '.join(sorted(blocked))}"
            )
        if not result.errors:
            self.set_last_applied(tag)
        return report, result

    def snapshot_of(self, workspace: Path, paths: tuple[str, ...] | list[str]) -> Snapshot:
        """Build an in-memory snapshot describing the *current* state of *paths*.

        Args:
            workspace: Path: Directory the relative paths are resolved against;
                resolved first. Paths that are not regular files are omitted, so
                a missing or deleted file simply does not appear in the result.
            paths: tuple[str, ...] | list[str]: Workspace-relative paths to
                describe, normally taken from the snapshot being compared
                against.

        Returns:
            Snapshot: A snapshot tagged ``"<current>"``, unencrypted, holding each
                file's digest, size and permission bits.
        """
        items: list[SnapshotItem] = []
        workspace = workspace.resolve()
        for relative in sorted(paths):
            candidate = workspace / relative
            if not candidate.is_file():
                continue
            digest = sha256_file(candidate)
            stat_result = candidate.stat()
            items.append(
                SnapshotItem(
                    path=relative,
                    digest=digest,
                    size=stat_result.st_size,
                    mode=stat.S_IMODE(stat_result.st_mode) & 0o777,
                )
            )
        return Snapshot(
            tag="<current>",
            created_at=utc_now(),
            workspace=str(workspace),
            items=tuple(items),
            encrypted=False,
        )

    # -- index ------------------------------------------------------------
    def _index(self) -> list[dict[str, Any]]:
        if not self.index_path.exists():
            return []
        document = jsonio.read(self.index_path)
        entries = document.get("entries", [])
        return list(entries) if isinstance(entries, list) else []

    def _index_add(
        self,
        snapshot: Snapshot,
        *,
        item_count: int | None = None,
        total_bytes: int | None = None,
    ) -> None:
        entries = [entry for entry in self._index() if entry.get("tag") != snapshot.tag]
        entries.append(
            {
                "tag": snapshot.tag,
                "created_at": snapshot.created_at,
                "item_count": len(snapshot.items) if item_count is None else item_count,
                "total_bytes": snapshot.total_bytes() if total_bytes is None else total_bytes,
                "encrypted": snapshot.encrypted,
                "description": snapshot.description,
                "workspace": snapshot.workspace,
            }
        )
        entries.sort(
            key=lambda entry: (str(entry.get("created_at", "")), str(entry.get("tag", "")))
        )
        jsonio.write(
            self.index_path,
            {"kind": "opencode-toolkit/snapshot-index", "schema": 1, "entries": entries},
        )
        self.index_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def list_snapshots(self) -> list[dict[str, Any]]:
        """Return index entries, newest first."""
        entries = self._index()
        entries.sort(
            key=lambda entry: (str(entry.get("created_at", "")), str(entry.get("tag", ""))),
            reverse=True,
        )
        return entries

    def delete(self, tag: str) -> None:
        """Remove a snapshot document. Blob GC is deliberately not automatic.

        Only the snapshot document and its index entry are removed. Referenced
        blobs stay on disk, because another snapshot may still need them; reclaim
        their space with ``opencode pack gc``.

        Args:
            tag: str: Tag of the snapshot to delete; validated because it becomes
                a filename.

        Raises:
            NotFoundError: No snapshot is stored under *tag*.
        """
        path = self.snapshot_path(tag)
        if not path.exists():
            raise NotFoundError(
                f"no snapshot named {tag!r}", code="sync.snapshot_not_found", details={"tag": tag}
            )
        path.unlink()
        entries = [entry for entry in self._index() if entry.get("tag") != tag]
        jsonio.write(
            self.index_path,
            {"kind": "opencode-toolkit/snapshot-index", "schema": 1, "entries": entries},
        )

    def status(self) -> SyncStatus:
        """Return aggregate store status for ``opencode sync status``."""
        entries = self.list_snapshots()
        latest = entries[0] if entries else None
        return SyncStatus(
            store_path=str(self.root),
            snapshot_count=len(entries),
            latest_tag=latest.get("tag") if latest else None,
            latest_created_at=latest.get("created_at") if latest else None,
            queued_operations=len(list((self.root.parent / "queue").glob("*.json")))
            if (self.root.parent / "queue").is_dir()
            else 0,
            encryption_available=True,
            cipher=crypto.CIPHER_HMAC_CTR,
            notes=(
                "snapshots are content-addressed; deleting a snapshot does not free blobs "
                "until `opencode pack gc` is run",
            ),
        )


def write_passphrase_hint(path: Path, *, iterations: int) -> None:
    """Persist only the KDF parameters, never any key material.

    Args:
        path: Path: File to create; must not already exist.
        iterations: int: PBKDF2-HMAC-SHA256 iteration count this store derives
            keys with, recorded so the cost can be reproduced or raised later.

    Raises:
        ConflictError: *path* already exists; the hint is deliberately not
            rewritten on disk.
    """
    write_new(
        path,
        jsonio.dumps(
            {
                "note": "Key derivation parameters for this store. No key material is stored here.",
                "kdf": "pbkdf2-hmac-sha256",
                "iterations": iterations,
            }
        )
        + "\n",
        mode=0o600,
    )


def atomic_text(path: Path, text: str) -> None:
    """Thin wrapper so tests can assert the store only uses atomic writes.

    Args:
        path: Path: Destination file; parent directories are created if needed.
        text: str: Text content written in one atomic replace.
    """
    write_text_atomic(path, text)
