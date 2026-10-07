"""Crypto and workflow-sync unit tests."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from opencode_toolkit.core.config import SyncPolicy
from opencode_toolkit.core.errors import (
    ConfigurationError,
    ConflictError,
    EncryptionError,
    NotFoundError,
    StateError,
)
from opencode_toolkit.workflow_sync import crypto
from opencode_toolkit.workflow_sync.conflicts import (
    INCOMING_WINS,
    LOCAL_WINS,
    PathState,
    diff_snapshots,
    plan_restore,
)
from opencode_toolkit.workflow_sync.models import Snapshot, SnapshotItem
from opencode_toolkit.workflow_sync.queue import OfflineQueue
from opencode_toolkit.workflow_sync.store import SnapshotStore, validate_tag

pytestmark = pytest.mark.unit

PASSPHRASE = "correct horse battery staple"
FAST = 100_000


# -- crypto ----------------------------------------------------------------


def test_roundtrip_recovers_the_plaintext() -> None:
    payload = b"project state " * 100
    sealed = crypto.seal(payload, PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    assert crypto.open_sealed(sealed, PASSPHRASE) == payload


def test_ciphertext_does_not_contain_the_plaintext() -> None:
    secret = b"super-secret-project-state"
    sealed = crypto.seal(secret, PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    assert secret not in sealed.ciphertext
    assert secret not in sealed.to_dict()["ciphertext"].encode()


def test_ciphertext_uses_a_fresh_salt_and_nonce_each_time() -> None:
    first = crypto.seal(b"same", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    second = crypto.seal(b"same", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    assert first.salt != second.salt
    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext


def test_wrong_passphrase_is_rejected() -> None:
    sealed = crypto.seal(b"x", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    with pytest.raises(EncryptionError) as excinfo:
        crypto.open_sealed(sealed, "wrong passphrase entirely")
    assert excinfo.value.code == "crypto.decrypt_failed"


def test_tampered_ciphertext_is_rejected() -> None:
    sealed = crypto.seal(
        b"sensitive data here", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR
    )
    tampered = dataclasses.replace(
        sealed, ciphertext=sealed.ciphertext[:-1] + bytes([sealed.ciphertext[-1] ^ 0x01])
    )
    with pytest.raises(EncryptionError):
        crypto.open_sealed(tampered, PASSPHRASE)


def test_tampered_tag_is_rejected() -> None:
    sealed = crypto.seal(
        b"sensitive data here", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR
    )
    tampered = dataclasses.replace(sealed, tag=b"\x00" * len(sealed.tag))
    with pytest.raises(EncryptionError):
        crypto.open_sealed(tampered, PASSPHRASE)


def test_tampered_metadata_is_rejected() -> None:
    """The header binds the version, cipher and KDF parameters."""
    sealed = crypto.seal(b"data", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    with pytest.raises(EncryptionError):
        crypto.open_sealed(dataclasses.replace(sealed, iterations=200_000), PASSPHRASE)
    with pytest.raises(EncryptionError):
        crypto.open_sealed(dataclasses.replace(sealed, cipher="unknown-cipher"), PASSPHRASE)


def test_unknown_payload_version_is_reported_clearly() -> None:
    sealed = crypto.seal(b"data", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    with pytest.raises(EncryptionError) as excinfo:
        crypto.open_sealed(dataclasses.replace(sealed, version=99), PASSPHRASE)
    assert "version" in excinfo.value.message


def test_json_roundtrip_of_a_sealed_payload() -> None:
    payload = b"round trip me"
    sealed = crypto.seal(payload, PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    restored = crypto.SealedPayload.from_dict(sealed.to_dict())
    assert restored == sealed
    assert crypto.open_sealed(restored, PASSPHRASE) == payload


def test_empty_passphrase_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        crypto.seal(b"x", "")
    sealed = crypto.seal(b"x", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    with pytest.raises(EncryptionError):
        crypto.open_sealed(sealed, "")


def test_iteration_floor_is_enforced_not_warned() -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        crypto.seal(b"x", PASSPHRASE, iterations=1000)
    assert str(crypto.MIN_ITERATIONS) in excinfo.value.message


def test_default_iteration_count_is_modern() -> None:
    assert crypto.DEFAULT_ITERATIONS >= 600_000


def test_kdf_actually_depends_on_the_iteration_count() -> None:
    """Guards against an implementation that hard-codes the work factor."""
    low = crypto.derive_key("pw", b"s" * 16, iterations=FAST)
    high = crypto.derive_key("pw", b"s" * 16, iterations=FAST * 2)
    assert low != high
    assert len(low) == crypto.KEY_BYTES


def test_malformed_payload_document_is_reported() -> None:
    with pytest.raises(EncryptionError):
        crypto.SealedPayload.from_dict({"format": "not-a-sealed-blob"})
    with pytest.raises(EncryptionError):
        crypto.SealedPayload.from_dict({"format": "opencode-toolkit/sealed", "version": 1})


def test_unsupported_cipher_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        crypto.seal(b"x", PASSPHRASE, iterations=FAST, cipher="rot13")


def test_empty_payload_roundtrips() -> None:
    sealed = crypto.seal(b"", PASSPHRASE, iterations=FAST, cipher=crypto.CIPHER_HMAC_CTR)
    assert crypto.open_sealed(sealed, PASSPHRASE) == b""


# -- conflict detection ----------------------------------------------------


def _snapshot(tag: str, digests: dict[str, str]) -> Snapshot:
    return Snapshot(
        tag=tag,
        created_at="2026-01-01T00:00:00Z",
        workspace="/ws",
        items=tuple(
            SnapshotItem(path=path, digest=digest, size=10)
            for path, digest in sorted(digests.items())
        ),
        encrypted=False,
    )


@pytest.mark.parametrize(
    ("base", "current", "incoming", "expected"),
    [
        ({"a": "1"}, {"a": "1"}, {"a": "1"}, PathState.IDENTICAL),
        ({"a": "1"}, {"a": "1"}, {"a": "2"}, PathState.INCOMING_ADDED),
        ({"a": "1"}, {"a": "2"}, {"a": "1"}, PathState.LOCAL_ADDED),
        ({"a": "1"}, {"a": "1"}, {"a": "1"}, PathState.IDENTICAL),
        ({"a": "1"}, {"a": "2"}, {"a": "2"}, PathState.IDENTICAL),
        ({"a": "1"}, {"a": "2"}, {"a": "3"}, PathState.CONFLICT),
        ({"a": "1"}, {"a": "2"}, {}, PathState.CONFLICT_DELETE_MODIFY),
        ({"a": "1"}, {}, {"a": "2"}, PathState.CONFLICT_MODIFY_DELETE),
        ({"a": "1"}, {"a": "1"}, {}, PathState.INCOMING_DELETED),
        ({"a": "1"}, {}, {"a": "1"}, PathState.LOCAL_DELETED),
    ],
)
def test_three_way_classification(
    base: dict, current: dict, incoming: dict, expected: PathState
) -> None:
    report = diff_snapshots(
        _snapshot("base", base), _snapshot("current", current), _snapshot("incoming", incoming)
    )
    assert report.states["a"] is expected
    assert report.has_conflicts is expected.is_conflict


def test_paths_present_on_only_one_side_are_classified_per_path() -> None:
    """A path the other side never had is added or deleted, not a conflict."""
    report = diff_snapshots(
        _snapshot("base", {"a": "1"}),
        _snapshot("current", {"a": "1", "b": "2"}),
        _snapshot("incoming", {"a": "1", "c": "3"}),
    )
    assert report.states["b"] is PathState.LOCAL_ADDED
    assert report.states["c"] is PathState.INCOMING_ADDED
    assert not report.has_conflicts


def test_missing_history_is_conservative() -> None:
    """With no known base, any disagreement must be treated as a conflict."""
    report = diff_snapshots(None, _snapshot("cur", {"a": "1"}), _snapshot("in", {"a": "2"}))
    assert report.has_conflicts
    report_same = diff_snapshots(None, _snapshot("cur", {"a": "1"}), _snapshot("in", {"a": "1"}))
    assert not report_same.has_conflicts


def test_missing_history_reports_new_paths_not_as_conflicts() -> None:
    report = diff_snapshots(None, _snapshot("cur", {}), _snapshot("in", {"a": "1"}))
    assert report.states["a"] is PathState.INCOMING_ADDED
    assert not report.has_conflicts


def test_plan_restore_blocks_conflicts_without_force() -> None:
    report = diff_snapshots(
        _snapshot("base", {"a": "1"}), _snapshot("cur", {"a": "2"}), _snapshot("in", {"a": "3"})
    )
    writes, _, blocked = plan_restore(report, force=False)
    assert writes == []
    assert blocked == ["a"]


def test_plan_restore_with_force_records_the_override() -> None:
    report = diff_snapshots(
        _snapshot("base", {"a": "1"}), _snapshot("cur", {"a": "2"}), _snapshot("in", {"a": "3"})
    )
    writes, _, blocked = plan_restore(report, force=True)
    assert writes == ["a"]
    assert blocked == ["a"]


def test_path_state_partition_is_total() -> None:
    for state in PathState:
        assert (state in INCOMING_WINS) or (state in LOCAL_WINS) or state.is_conflict


# -- tags ------------------------------------------------------------------


@pytest.mark.parametrize("tag", ["snapshot", "s-2026", "a.b_c", "A1"])
def test_valid_tags(tag: str) -> None:
    assert validate_tag(tag) == tag


@pytest.mark.parametrize("tag", ["", "../escape", "with/slash", "-leading", "x" * 100, "has space"])
def test_invalid_tags(tag: str) -> None:
    with pytest.raises(StateError):
        validate_tag(tag)


# -- store -----------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path, fast_sync_policy: SyncPolicy) -> SnapshotStore:
    return SnapshotStore(tmp_path / "snapshots", fast_sync_policy)


def test_save_then_load_roundtrip(store: SnapshotStore, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("content", encoding="utf-8")
    snapshot, report = store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    assert len(snapshot.items) == 1
    assert report.encrypted
    loaded = store.load("t1", passphrase=PASSPHRASE)
    assert loaded.item_map["docs/a.md"].digest == snapshot.items[0].digest


def test_encrypted_snapshot_hides_content_on_disk(store: SnapshotStore, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("PLAINTEXT-MARKER", encoding="utf-8")
    store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    raw = (store.snapshot_path("t1")).read_bytes()
    assert b"PLAINTEXT-MARKER" not in raw
    assert b"sealed" in raw


def test_loading_an_encrypted_snapshot_without_a_passphrase_fails_clearly(
    store: SnapshotStore, workspace: Path
) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    with pytest.raises(StateError) as excinfo:
        store.load("t1")
    assert excinfo.value.code == "sync.passphrase_required"


def test_saving_without_a_passphrase_when_encryption_is_on_fails(
    store: SnapshotStore, workspace: Path
) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    with pytest.raises(StateError) as excinfo:
        store.save(workspace, tag="t1", passphrase=None, tracked=("docs",))
    assert excinfo.value.code == "sync.passphrase_required"


def test_saving_the_same_tag_twice_conflicts(store: SnapshotStore, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    with pytest.raises(ConflictError):
        store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))


def test_loading_a_missing_snapshot_lists_the_alternatives(
    store: SnapshotStore, workspace: Path
) -> None:
    with pytest.raises(NotFoundError) as excinfo:
        store.load("nope")
    assert excinfo.value.code == "sync.snapshot_not_found"


def test_save_with_no_matching_paths_fails(store: SnapshotStore, workspace: Path) -> None:
    with pytest.raises(StateError) as excinfo:
        store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("does/not/exist",))
    assert excinfo.value.code == "sync.nothing_tracked"


def test_blob_corruption_is_detected(store: SnapshotStore, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    snapshot, _ = store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    blob = store.blob_dir / snapshot.items[0].digest
    blob.write_bytes(b"corrupted")
    with pytest.raises(StateError) as excinfo:
        store.get_blob(snapshot.items[0].digest)
    assert excinfo.value.code == "sync.blob_corrupt"


def test_missing_blob_is_reported_not_silently_ignored(
    store: SnapshotStore, workspace: Path
) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    snapshot, _ = store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    (store.blob_dir / snapshot.items[0].digest).unlink()
    with pytest.raises(NotFoundError) as excinfo:
        store.get_blob(snapshot.items[0].digest)
    assert excinfo.value.code == "sync.missing_blob"


def test_index_records_every_snapshot(store: SnapshotStore, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    store.save(workspace, tag="t2", passphrase=PASSPHRASE, tracked=("docs",))
    assert [entry["tag"] for entry in store.list_snapshots()] == ["t2", "t1"]


def test_last_applied_pointer_roundtrips(store: SnapshotStore) -> None:
    assert store.last_applied() is None
    store.set_last_applied("t1")
    assert store.last_applied() == "t1"


def test_delete_removes_the_snapshot_and_its_index_entry(
    store: SnapshotStore, workspace: Path
) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    store.delete("t1")
    assert not store.snapshot_path("t1").exists()
    assert store.list_snapshots() == []


def test_snapshot_document_state_is_owner_only(store: SnapshotStore, workspace: Path) -> None:
    import stat

    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    store.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    mode = stat.S_IMODE(store.snapshot_path("t1").stat().st_mode)
    assert mode == 0o600


def test_foreign_document_is_rejected(store: SnapshotStore) -> None:
    from opencode_toolkit.core import jsonio

    jsonio.write(store.snapshot_path("foreign"), {"kind": "something-else"})
    with pytest.raises(StateError) as excinfo:
        store.load("foreign")
    assert "not a snapshot" in excinfo.value.message


def test_corrupt_payload_digest_is_detected(store: SnapshotStore, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    store.save(workspace, tag="plain", passphrase=None, encrypt=False, tracked=("docs",))
    document = store.snapshot_path("plain").read_text(encoding="utf-8")
    store.snapshot_path("plain").write_text(
        document.replace('"payload_digest": "', '"payload_digest": "00'), encoding="utf-8"
    )
    with pytest.raises(StateError) as excinfo:
        store.load("plain")
    assert excinfo.value.code == "sync.payload_corrupt"


# -- offline queue ---------------------------------------------------------


def test_queue_records_and_flushes(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    entry = queue.enqueue("push", "t1", {"remote": "/nowhere"})
    assert len(queue) == 1
    result = queue.flush(lambda item: True)
    assert result["applied"] == ["push:t1"]
    assert len(queue) == 0
    assert entry.identifier


def test_queue_keeps_failures_and_records_the_error(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "t1")

    def failing(item) -> bool:
        raise RuntimeError("network down")

    result = queue.flush(failing, max_attempts=5)
    assert len(result["failed"]) == 1
    assert len(queue) == 1
    assert "network down" in queue.pending()[0].last_error


def test_queue_retries_until_the_limit_then_parks_the_entry(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "t1")
    first = queue.flush(lambda item: False, max_attempts=2)
    assert first["failed"] == ["push:t1"]
    assert queue.pending()[0].attempts == 1
    second = queue.flush(lambda item: False, max_attempts=2)
    assert second["remaining"] == ["push:t1"]
    assert queue.pending()[0].attempts == 2
    assert len(queue) == 1, "a parked entry must never be silently discarded"


def test_queue_rejects_unknown_operations(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    with pytest.raises(StateError):
        queue.enqueue("rm -rf", "t1")


def test_queue_preserves_insertion_order_within_one_second(tmp_path: Path) -> None:
    """Two entries enqueued in the same second must still flush in order."""
    queue = OfflineQueue(tmp_path / "queue")
    enqueued = [queue.enqueue("save", f"t{index}") for index in range(5)]
    assert [entry.tag for entry in queue.pending()] == [entry.tag for entry in enqueued]


def test_queue_never_stores_credentials(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "t1", {"remote": "/mnt/share"})
    body = "".join(path.read_text() for path in (queue.root).glob("*.json"))
    assert "passphrase" not in body.lower()
    assert "password" not in body.lower()
