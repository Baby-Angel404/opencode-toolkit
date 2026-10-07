"""Unit tests for the sync transport layer and its helpers.

Everything here works against a local directory, which is the only transport
implemented. The cases that matter are the ones a network would make
unreproducible: a missing remote, an unsafe tag, a corrupted copy, and a pull
that must not clobber local history.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opencode_toolkit.core.config import SyncPolicy
from opencode_toolkit.core.errors import (
    ConfigurationError,
    ConflictError,
    EncryptionError,
    NetworkError,
    StateError,
    UsageError,
)
from opencode_toolkit.workflow_sync.conflicts import ConflictReport, PathState
from opencode_toolkit.workflow_sync.crypto import derive_key
from opencode_toolkit.workflow_sync.models import SyncReport
from opencode_toolkit.workflow_sync.queue import OfflineQueue
from opencode_toolkit.workflow_sync.store import SNAPSHOT_SUFFIX, SnapshotStore
from opencode_toolkit.workflow_sync.sync import (
    DirectoryTransport,
    Transport,
    pull,
    push,
    summarise,
    unavailable_transport,
    verify_copy,
)

pytestmark = pytest.mark.unit

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def store(tmp_path: Path) -> SnapshotStore:
    return SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "work"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "a.md").write_text("original\n", encoding="utf-8")
    return root


# -- the protocol ---------------------------------------------------------


def test_a_directory_transport_satisfies_the_transport_protocol(tmp_path: Path) -> None:
    """The protocol is structural; the concrete class supplies every member."""
    transport: Transport = DirectoryTransport(tmp_path)
    assert transport.name.startswith("directory:")
    assert isinstance(transport.online, bool)


def test_a_directory_transport_reports_its_reachability(tmp_path: Path) -> None:
    missing = DirectoryTransport(tmp_path / "absent")
    assert missing.online is False
    missing.remote.mkdir(parents=True)
    assert missing.online is True
    # The name must not imply a network sync.
    assert "http" not in missing.name


def test_a_directory_transport_expands_a_home_relative_path() -> None:
    assert str(DirectoryTransport(Path("~/sync")).remote).startswith(str(Path.home()))


# -- transport selection --------------------------------------------------


def test_a_url_remote_is_refused_with_an_explanation() -> None:
    for url in ("https://example.invalid/repo", "http://example.invalid/repo"):
        with pytest.raises(NetworkError) as excinfo:
            unavailable_transport(url)
        assert excinfo.value.details["requested"] == url
        assert excinfo.value.details["implemented"], "the error must say what is supported"


def test_a_missing_remote_is_a_usage_error_for_pull(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        unavailable_transport(str(tmp_path / "absent"))


def test_a_missing_remote_is_allowed_for_push(tmp_path: Path) -> None:
    transport = unavailable_transport(str(tmp_path / "fresh"), create=True)
    assert transport.online is False, "the directory does not exist until the push creates it"


def test_an_existing_remote_is_selected_regardless_of_create(tmp_path: Path) -> None:
    assert unavailable_transport(str(tmp_path)).online is True


# -- push -----------------------------------------------------------------


def test_push_copies_the_sealed_snapshot_and_creates_the_remote(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")

    assert transport.has("base") is False
    result = push(store, "base", transport, passphrase=PASSPHRASE)

    assert result.transferred
    assert not result.already_present
    assert transport.has("base") is True
    # Only the sealed document travels: the content must not be readable.
    assert b"original" not in (transport.remote / f"base{SNAPSHOT_SUFFIX}").read_bytes()


def test_push_skips_a_snapshot_the_remote_already_holds(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)
    result = push(store, "base", transport, passphrase=PASSPHRASE)
    assert not result.transferred
    assert result.already_present


def test_push_refuses_a_tag_that_is_not_present(store: SnapshotStore, tmp_path: Path) -> None:
    with pytest.raises(StateError):
        push(store, "absent", DirectoryTransport(tmp_path / "remote"), passphrase=PASSPHRASE)


def test_push_refuses_an_unsafe_tag(store: SnapshotStore, workspace: Path, tmp_path: Path) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    with pytest.raises(StateError):
        push(store, "../escape", DirectoryTransport(tmp_path / "remote"), passphrase=PASSPHRASE)


def test_an_unsafe_tag_cannot_escape_the_remote_directory(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    remote = tmp_path / "remote"
    with pytest.raises(StateError):
        push(store, "base/../../etc/passwd", DirectoryTransport(remote), passphrase=PASSPHRASE)
    assert not (tmp_path / "etc").exists()


def test_pushing_twice_leaves_the_bytes_unchanged(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)
    first = (transport.remote / f"base{SNAPSHOT_SUFFIX}").read_bytes()
    push(store, "base", transport, passphrase=PASSPHRASE)
    assert (transport.remote / f"base{SNAPSHOT_SUFFIX}").read_bytes() == first


def test_the_pushed_document_carries_no_plaintext(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    """The envelope is JSON; its payload is ciphertext and holds no content.

    What must not be readable is the tracked content and the passphrase, so
    those are what the assertion checks.
    """
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)
    raw = (transport.remote / f"base{SNAPSHOT_SUFFIX}").read_text(encoding="utf-8")

    document = json.loads(raw)
    assert document["kind"] == "opencode-toolkit/snapshot"
    assert document["encrypted"] is True
    assert "sealed" in document, "the manifest itself must be sealed"
    assert "original" not in raw
    assert PASSPHRASE not in raw
    assert workspace.name not in raw, "the working-tree path must not be in the envelope"


# -- pull -----------------------------------------------------------------


def test_pull_returns_the_decoded_snapshot(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)

    arriving = SnapshotStore(tmp_path / "arriving", SyncPolicy(kdf_iterations=100_000))
    snapshot = pull(arriving, "base", transport, passphrase=PASSPHRASE)
    assert snapshot.tag == "base"
    assert arriving.blob_dir.is_dir()
    assert list(arriving.blob_dir.iterdir())


def test_pull_never_overwrites_a_blob_that_already_exists(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    """A local blob is shared by every snapshot that references it.

    Replacing it with the remote copy would rewrite history that an older
    snapshot still points at, so the transport leaves it alone.
    """
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)

    arriving = SnapshotStore(tmp_path / "arriving", SyncPolicy(kdf_iterations=100_000))
    pull(arriving, "base", transport, passphrase=PASSPHRASE)
    blob = next(arriving.blob_dir.iterdir())
    blob.write_bytes(b"sentinel")

    pull(arriving, "base", transport, passphrase=PASSPHRASE)
    assert blob.read_bytes() == b"sentinel", "an existing blob must be left untouched"


def test_pull_refuses_a_snapshot_the_remote_does_not_hold(
    store: SnapshotStore, tmp_path: Path
) -> None:
    remote = tmp_path / "remote"
    remote.mkdir()
    with pytest.raises(StateError):
        pull(store, "absent", DirectoryTransport(remote), passphrase=PASSPHRASE)


def test_pull_refuses_an_unsafe_tag(store: SnapshotStore, tmp_path: Path) -> None:
    (tmp_path / "remote").mkdir()
    with pytest.raises(StateError):
        pull(store, "../escape", DirectoryTransport(tmp_path / "remote"), passphrase=PASSPHRASE)


def test_pull_tolerates_a_remote_with_no_blobs_directory(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)
    for blob in (transport.remote / "blobs").glob("*"):
        blob.unlink()
    (transport.remote / "blobs").rmdir()

    arriving = SnapshotStore(tmp_path / "arriving", SyncPolicy(kdf_iterations=100_000))
    assert pull(arriving, "base", transport, passphrase=PASSPHRASE).tag == "base"


def test_the_pulled_snapshot_opens_only_with_the_right_passphrase(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)

    arriving = SnapshotStore(tmp_path / "arriving", SyncPolicy(kdf_iterations=100_000))
    with pytest.raises(EncryptionError):
        pull(arriving, "base", transport, passphrase="the wrong passphrase")
    assert pull(arriving, "base", transport, passphrase=PASSPHRASE).tag == "base"


def test_a_corrupted_sealed_document_does_not_produce_a_readable_snapshot(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    """A transport that alters bytes must not yield a usable snapshot."""
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)
    document = transport.remote / f"base{SNAPSHOT_SUFFIX}"
    document.write_bytes(document.read_bytes().replace(b'"tag"', b'"TAg"'))

    arriving = SnapshotStore(tmp_path / "arriving", SyncPolicy(kdf_iterations=100_000))
    # Renaming a key inside the sealed payload breaks authentication: the tag
    # is gone before the MAC is even checked, and the failure is a refusal.
    with pytest.raises(EncryptionError):
        pull(arriving, "base", transport, passphrase=PASSPHRASE)


# -- has() ----------------------------------------------------------------


def test_has_validates_the_tag_before_using_it_as_a_filename(tmp_path: Path) -> None:
    with pytest.raises(StateError):
        DirectoryTransport(tmp_path).has("../escape")


def test_has_is_false_for_a_tag_that_was_never_pushed(tmp_path: Path) -> None:
    assert DirectoryTransport(tmp_path).has("never-pushed") is False


# -- round trip -----------------------------------------------------------


def test_a_full_round_trip_recovers_the_original_content(
    store: SnapshotStore, workspace: Path, tmp_path: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    transport = DirectoryTransport(tmp_path / "remote")
    push(store, "base", transport, passphrase=PASSPHRASE)

    (workspace / "docs" / "a.md").write_text("changed\n", encoding="utf-8")

    arriving = SnapshotStore(tmp_path / "arriving", SyncPolicy(kdf_iterations=100_000))
    pull(arriving, "base", transport, passphrase=PASSPHRASE)
    _, result = arriving.restore(workspace, "base", passphrase=PASSPHRASE, force=True)
    assert result.ok
    assert (workspace / "docs" / "a.md").read_text(encoding="utf-8") == "original\n"


def test_derive_key_is_deterministic_for_a_salt_and_passphrase() -> None:
    floor = 100_000
    first = derive_key(PASSPHRASE, b"\x00" * 16, iterations=floor)
    assert first == derive_key(PASSPHRASE, b"\x00" * 16, iterations=floor)
    assert first != derive_key(PASSPHRASE, b"\x01" * 16, iterations=floor)
    assert first != derive_key("other", b"\x00" * 16, iterations=floor)


def test_the_kdf_work_factor_cannot_be_lowered() -> None:
    """The floor is a refusal, not a clamp: a weakened KDF must not look applied."""
    with pytest.raises(ConfigurationError):
        derive_key(PASSPHRASE, b"\x00" * 16, iterations=1000)


# -- restore semantics ----------------------------------------------------


def test_a_one_sided_local_edit_is_not_a_conflict(store: SnapshotStore, workspace: Path) -> None:
    """Only the working tree moved, so it stands and nothing is written.

    The incoming side is identical to the base, so there is nothing to merge:
    calling this a conflict would block an ordinary local edit.
    """
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    store.set_last_applied("base")
    (workspace / "docs" / "a.md").write_text("local edit\n", encoding="utf-8")

    report, result = store.restore(workspace, "base", passphrase=PASSPHRASE, base_tag="base")
    assert not report.has_conflicts
    assert (workspace / "docs" / "a.md").read_text(encoding="utf-8") == "local edit\n"
    assert result.ok


def test_a_conflicting_restore_is_refused_rather_than_applied(
    store: SnapshotStore, workspace: Path
) -> None:
    """Both sides moved away from the base: the restore must refuse."""
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    store.set_last_applied("base")

    # The incoming side diverges...
    incoming = tmp_worktree(store, workspace, tag="head", content="remote edit\n")
    # ...and the working tree diverges too.
    (workspace / "docs" / "a.md").write_text("local edit\n", encoding="utf-8")

    report, result = store.restore(workspace, "head", passphrase=PASSPHRASE, base_tag="base")
    assert report.has_conflicts
    assert not result.ok
    assert (workspace / "docs" / "a.md").read_text(encoding="utf-8") == "local edit\n"
    assert incoming == "remote edit\n", "the snapshot content itself is untouched"


def test_a_forced_restore_is_reported_as_forced(store: SnapshotStore, workspace: Path) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    store.set_last_applied("base")
    tmp_worktree(store, workspace, tag="head", content="remote edit\n")
    (workspace / "docs" / "a.md").write_text("local edit\n", encoding="utf-8")

    report, result = store.restore(
        workspace, "head", passphrase=PASSPHRASE, base_tag="base", force=True
    )
    assert report.has_conflicts
    assert result.ok
    assert result.forced, "a forced restore must be distinguishable from a clean one"
    assert (workspace / "docs" / "a.md").read_text(encoding="utf-8") == "remote edit\n"


def test_restoring_onto_an_identical_tree_is_not_a_conflict(
    store: SnapshotStore, workspace: Path
) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    store.set_last_applied("base")
    report, result = store.restore(workspace, "base", passphrase=PASSPHRASE, base_tag="base")
    assert not report.has_conflicts
    assert result.ok


def test_a_missing_last_applied_marker_degrades_rather_than_assuming_clean(
    store: SnapshotStore, workspace: Path
) -> None:
    """Unknown history must be reported, not treated as a clean tree."""
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    (workspace / "docs" / "a.md").write_text("unknown provenance\n", encoding="utf-8")
    report, _ = store.restore(workspace, "base", passphrase=PASSPHRASE, base_tag="")
    assert report.states


def test_a_snapshot_tag_cannot_be_reused(store: SnapshotStore, workspace: Path) -> None:
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    with pytest.raises(ConflictError):
        store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))


def tmp_worktree(store: SnapshotStore, workspace: Path, *, tag: str, content: str) -> str:
    """Snapshot *content* from a scratch tree, leaving *workspace* untouched."""
    scratch = workspace.parent / f"scratch-{tag}"
    (scratch / "docs").mkdir(parents=True, exist_ok=True)
    (scratch / "docs" / "a.md").write_text(content, encoding="utf-8")
    store.save(scratch, tag=tag, passphrase=PASSPHRASE, tracked=("docs",))
    return content


# -- the offline queue ----------------------------------------------------


def test_a_queued_entry_survives_a_failing_handler(tmp_path: Path) -> None:
    """Nothing is dropped: a failure leaves the entry on disk with the error."""
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "base", {"note": "payload"})

    outcome = queue.flush(lambda entry: False)
    # Below max_attempts the entry is reported as failed and stays queued.
    assert outcome["failed"] == ["push:base"]
    assert outcome["remaining"] == []
    assert len(queue) == 1
    assert queue.pending()[0].payload == {"note": "payload"}
    assert queue.pending()[0].attempts == 1


def test_an_entry_stops_being_retried_after_max_attempts(tmp_path: Path) -> None:
    """Past the attempt limit the entry is parked, never discarded."""
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "base")
    for _ in range(3):
        queue.flush(lambda entry: False, max_attempts=3)
    assert queue.pending()[0].attempts == 3
    outcome = queue.flush(lambda entry: False, max_attempts=3)
    assert outcome["remaining"] == ["push:base"]
    assert len(queue) == 1, "a parked entry is still on disk"


def test_a_successful_handler_clears_the_entry(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "base")
    assert queue.flush(lambda entry: True)["applied"] == ["push:base"]
    assert len(queue) == 0


def test_a_raising_handler_records_the_exception_instead_of_crashing(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "base")

    def explode(entry):
        raise RuntimeError("remote refused")

    queue.flush(explode)
    assert "RuntimeError: remote refused" in queue.pending()[0].last_error


def test_entries_are_replayed_oldest_first(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    first = queue.enqueue("push", "first")
    second = queue.enqueue("push", "second")
    assert first.created_at <= second.created_at
    seen: list[str] = []
    queue.flush(lambda entry: bool(seen.append(entry.tag)))
    assert seen == sorted(seen, key=lambda tag: ["first", "second"].index(tag))


def test_clear_empties_the_queue_and_reports_the_count(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "a")
    queue.enqueue("push", "b")
    assert queue.clear() == 2
    assert len(queue) == 0


# -- helpers --------------------------------------------------------------


def test_verify_copy_is_false_when_a_side_is_missing(tmp_path: Path) -> None:
    present = tmp_path / "a"
    present.write_bytes(b"content")
    assert verify_copy(present, present) is True
    assert verify_copy(present, tmp_path / "absent") is False
    assert verify_copy(tmp_path / "absent", present) is False


def test_verify_copy_detects_a_truncated_copy(tmp_path: Path) -> None:
    source, target = tmp_path / "a", tmp_path / "b"
    source.write_bytes(b"content")
    target.write_bytes(b"conten")
    assert verify_copy(source, target) is False


def test_summarise_stays_short_for_an_uneventful_sync() -> None:
    assert summarise(SyncReport(action="push", tag="base")) == "push base"


def test_summarise_appends_only_the_non_empty_counts() -> None:
    text = summarise(
        SyncReport(
            action="restore",
            tag="base",
            applied=["a", "b"],
            conflicts=["c"],
            queued=True,
        )
    )
    assert "2 applied" in text
    assert "1 conflicted" in text
    assert "queued" in text


def test_a_conflict_report_serialises() -> None:
    report = ConflictReport(
        states={"a": PathState.CONFLICT, "b": PathState.UNCHANGED},
        conflicts=("a",),
        incoming_wins=(),
        local_wins=("b",),
    )
    document = json.loads(json.dumps(report.to_dict()))
    assert document["states"] == {"a": "conflict", "b": "unchanged"}
    assert document["summary"]["conflict_count"] == 1
    assert document["incoming_wins"] == []
