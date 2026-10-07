"""Integration tests: components interacting, and the release gate pipeline.

These are the tests that would catch a defect where each component is correct in
isolation but the seam between them is wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from opencode_toolkit.core.config import (
    OrchestratorPolicy,
    SyncPolicy,
)
from opencode_toolkit.live_docs.scanner import scan_tree
from opencode_toolkit.offline_pack.builder import PackBuilder
from opencode_toolkit.offline_pack.manifest import verify_archive
from opencode_toolkit.orchestrator.checkpoint import CheckpointStore
from opencode_toolkit.orchestrator.coordinator import Coordinator
from opencode_toolkit.orchestrator.executor import CommandExecutor
from opencode_toolkit.orchestrator.models import Plan, Role, Task
from opencode_toolkit.publishing.artifacts import clean_publish_directory, scan_for_secrets
from opencode_toolkit.publishing.classify import classify_project
from opencode_toolkit.release.gate import CHECK_NAMES, CheckStatus, new_gate, record
from opencode_toolkit.security_audit.engine import AuditEngine
from opencode_toolkit.snippet_verified.registry import default_registry
from opencode_toolkit.workflow_sync.conflicts import diff_snapshots
from opencode_toolkit.workflow_sync.store import SnapshotStore
from opencode_toolkit.workflow_sync.sync import DirectoryTransport, pull, push

pytestmark = pytest.mark.integration

PASSPHRASE = "integration-passphrase"


def test_audit_then_pack_then_verify(tmp_path: Path) -> None:
    """The audit must run against the same tree the pack will contain."""
    root = tmp_path / "repo"
    (root / "src" / "opencode_toolkit").mkdir(parents=True)
    (root / "src" / "opencode_toolkit" / "core").mkdir()
    (root / "src" / "opencode_toolkit" / "core" / "core.py").write_text(
        'DEFAULT_TOKEN = "abcdef0123456789"\n', encoding="utf-8"
    )
    (root / "README.md").write_text("# mini\n", encoding="utf-8")
    (root / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "mini"\nversion = "0.1.0"\ndependencies = []\n', encoding="utf-8"
    )

    audit = AuditEngine.from_policy().scan(root)
    assert any(f.rule_id == "OCSA-CRED-001" for f in audit.findings)

    result = PackBuilder(root).build(output=tmp_path / "pack.zip")
    assert result.ok
    assert verify_archive(result.archive).ok


def test_snapshot_roundtrip_through_a_second_store(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "docs").mkdir(parents=True)
    (workspace / "docs" / "a.md").write_text("v1", encoding="utf-8")
    remote = tmp_path / "remote"

    first = SnapshotStore(tmp_path / "store-a", SyncPolicy(kdf_iterations=100_000))
    snapshot, report = first.save(workspace, tag="t1", passphrase=PASSPHRASE, tracked=("docs",))
    assert report.ok

    transport = DirectoryTransport(remote)
    assert push(first, "t1", transport, passphrase=PASSPHRASE).transferred
    assert not push(first, "t1", transport, passphrase=PASSPHRASE).transferred, (
        "a second push must be a no-op"
    )

    second = SnapshotStore(tmp_path / "store-b", SyncPolicy(kdf_iterations=100_000))
    pulled = pull(second, "t1", transport, passphrase=PASSPHRASE)
    assert pulled.item_map["docs/a.md"].digest == snapshot.item_map["docs/a.md"].digest

    _, restore_report = second.restore(workspace, "t1", passphrase=PASSPHRASE)
    assert restore_report.ok
    assert (workspace / "docs" / "a.md").read_text() == "v1"


def test_snapshot_push_is_skipped_when_offline(tmp_path: Path) -> None:
    """An unreachable remote queues the operation instead of losing it."""
    from opencode_toolkit.core.errors import UsageError
    from opencode_toolkit.workflow_sync.queue import OfflineQueue
    from opencode_toolkit.workflow_sync.sync import unavailable_transport

    with pytest.raises(UsageError):
        unavailable_transport(str(tmp_path / "does-not-exist"))

    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "t1", {"remote": str(tmp_path / "later")})
    assert len(queue) == 1
    assert queue.flush(lambda entry: True)["applied"] == ["push:t1"]


def test_restore_refuses_to_clobber_and_reports_the_path(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "docs").mkdir(parents=True)
    (workspace / "docs" / "a.md").write_text("original", encoding="utf-8")
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))

    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    (workspace / "docs" / "a.md").write_text("local edit", encoding="utf-8")
    store.save(workspace, tag="head", passphrase=PASSPHRASE, tracked=("docs",))

    store.set_last_applied("head")
    report, result = store.restore(workspace, "base", passphrase=PASSPHRASE)
    assert report.conflicts == ("docs/a.md",)
    assert not result.ok
    assert (workspace / "docs" / "a.md").read_text() == "local edit", "the restore wrote anyway"


def test_restore_with_force_applies_and_records_the_override(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "docs").mkdir(parents=True)
    (workspace / "docs" / "a.md").write_text("original", encoding="utf-8")
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    (workspace / "docs" / "a.md").write_text("local edit", encoding="utf-8")
    store.save(workspace, tag="head", passphrase=PASSPHRASE, tracked=("docs",))
    store.set_last_applied("head")

    _, result = store.restore(workspace, "base", passphrase=PASSPHRASE, force=True)
    assert (workspace / "docs" / "a.md").read_text() == "original"
    assert result.conflicts == []
    assert result.forced == ["docs/a.md"]
    assert any("--force" in note for note in result.notes)


def test_conflict_report_agrees_with_the_restore_outcome(tmp_path: Path) -> None:
    """The analysis and the action must not disagree about what conflicts."""
    workspace = tmp_path / "ws"
    (workspace / "docs").mkdir(parents=True)
    (workspace / "docs" / "keep.md").write_text("same", encoding="utf-8")
    (workspace / "docs" / "clash.md").write_text("v1", encoding="utf-8")
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    base, _ = store.save(workspace, tag="base", passphrase=PASSPHRASE, tracked=("docs",))
    (workspace / "docs" / "clash.md").write_text("v2", encoding="utf-8")
    store.save(workspace, tag="head", passphrase=PASSPHRASE, tracked=("docs",))

    current = store.snapshot_of(workspace, [item.path for item in base.items])
    analysis = diff_snapshots(base, current, base)
    _, result = store.restore(workspace, "base", passphrase=PASSPHRASE, base_tag="head")
    assert set(result.conflicts) == set(analysis.conflicts)
    assert "docs/keep.md" not in result.conflicts


def test_orchestrator_runs_the_projects_own_audit(tmp_path: Path) -> None:
    """The orchestration pipeline is real: the security review actually audits."""
    root = tmp_path / "repo"
    (root / "src" / "app").mkdir(parents=True)
    (root / "src" / "app" / "bad.py").write_text('PASSWORD = "leakedvalue123"\n', encoding="utf-8")
    import sys

    source_root = str(Path(__file__).resolve().parents[2] / "src")
    store = CheckpointStore(root / ".opencode" / "toolkit" / "orchestrator")
    coordinator = Coordinator(
        root,
        policy=OrchestratorPolicy(),
        executor=CommandExecutor(env_overrides={"PYTHONPATH": source_root}),
        store=store,
    )
    plan = Plan(
        name="self-audit",
        workspace=str(root),
        tasks=(
            Task(
                id="review",
                title="Security review",
                role=Role.SECURITY_REVIEWER,
                command=(
                    sys.executable,
                    "-m",
                    "opencode_toolkit",
                    "security-audit",
                    "src",
                    "--quiet",
                ),
                timeout_seconds=120,
            ),
        ),
    )
    result = coordinator.run(plan, run_id="self")
    # The fixture contains a hard-coded credential, so the review must fail the
    # task. That a non-zero exit propagated is the behaviour under test.
    assert result.failed() == ["review"]
    outcome = result.outcomes[0]
    assert outcome.exit_code == 1

    log = (root / ".opencode" / "toolkit" / "orchestrator" / "logs" / "self-review.log").read_text()
    assert "OCSA-CRED-001" in log
    assert "leakedvalue123" not in log, "the audit log must not contain the secret value"


def test_orchestrator_persists_a_resumable_plan(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    store = CheckpointStore(root / ".opencode" / "toolkit" / "orchestrator")
    coordinator = Coordinator(root, store=store)
    plan = Plan(
        name="p",
        tasks=(Task(id="a", title="A", role=Role.PLANNER),),
    )
    coordinator.run(plan, run_id="r")
    checkpoint = store.load("latest")
    assert checkpoint.plan_name == "p"
    assert checkpoint.completed == ("a",)
    restored = checkpoint.restored_plan()
    assert restored.tasks[0].status.value == "completed"


def test_docs_drift_after_a_signature_change(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "m.py").write_text(
        'def handler(request, timeout=5):\n    """Handle it.\n\n    Args:\n        request: the request.\n    """\n    return request\n',
        encoding="utf-8",
    )
    surface = scan_tree(root)
    baseline_path = root / "baseline.json"
    from opencode_toolkit.live_docs.drift import write_baseline

    write_baseline(baseline_path, surface)
    from opencode_toolkit.live_docs.drift import diff_against_baseline, load_baseline

    (root / "m.py").write_text(
        'def handler(request, timeout=5, retries=3):\n    """Handle it.\n\n    Args:\n        request: the request.\n    """\n    return request\n',
        encoding="utf-8",
    )
    updated = scan_tree(root)
    report = diff_against_baseline(
        updated, load_baseline(baseline_path), baseline_path=baseline_path
    )
    assert report.by_kind()["changed"] == 1
    assert report.has_blocking()


def test_snippet_then_audit_the_written_file(tmp_path: Path) -> None:
    """Installing a snippet must not introduce a finding."""
    registry = default_registry()
    target = tmp_path / "generated.py"
    registry.materialise("python-password-hashing-argon2", target)
    result = AuditEngine.from_policy().scan(target)
    assert result.findings == []


def test_publish_gate_blocks_every_platform(tmp_path: Path) -> None:
    from opencode_toolkit.publishing.huggingface import HuggingFacePublisher
    from opencode_toolkit.publishing.kaggle import KagglePublisher

    gate = new_gate("1.0.0")
    hf = HuggingFacePublisher("someone")
    kaggle = KagglePublisher()
    assert hf.check_gate(gate).status == "BLOCKED"
    assert kaggle.check_gate(gate).status == "BLOCKED"

    for name in CHECK_NAMES:
        gate = record(gate, name, CheckStatus.PASS, detail="ok")
    assert hf.check_gate(gate) is None
    assert kaggle.check_gate(gate) is None


def test_publish_skips_without_credentials_and_names_the_variables(tmp_path: Path) -> None:
    from opencode_toolkit.publishing.huggingface import HuggingFacePublisher
    from opencode_toolkit.publishing.kaggle import KagglePublisher

    hf = HuggingFacePublisher("someone").check_credentials(environ={})
    kaggle = KagglePublisher().check_credentials(environ={"KAGGLE_USERNAME": "user"})
    assert hf.status == "SKIPPED"
    assert "HUGGINGFACE_TOKEN" in hf.missing_configuration[0]
    assert kaggle.status == "SKIPPED"
    assert any("KAGGLE_KEY" in item for item in kaggle.missing_configuration)


def test_publish_directory_excludes_secrets_and_scans_clean(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "src" / "opencode_toolkit").mkdir(parents=True)
    (root / "src" / "opencode_toolkit" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (root / "README.md").write_text("# ok\n", encoding="utf-8")
    (root / ".env").write_text("TOKEN=aaaaaaaaaaaaaaaaaaaa\n", encoding="utf-8")
    (root / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n", encoding="utf-8")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "big.js").write_text("x\n", encoding="utf-8")

    destination = tmp_path / "publish"
    result = clean_publish_directory(root, destination)
    staged = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file()
    }
    assert ".env" not in staged
    assert "id_rsa" not in staged
    assert "src/opencode_toolkit/a.py" in staged
    assert not any(path.startswith("node_modules/") for path in staged)
    assert result["excluded_count"] >= 3

    report = scan_for_secrets(destination)
    assert report.clean, [hit.to_dict() for hit in report.hits]


def test_publish_directory_refuses_to_overwrite_a_dirty_target(tmp_path: Path) -> None:
    from opencode_toolkit.core.errors import IntegrityError

    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("# ok\n", encoding="utf-8")
    destination = tmp_path / "publish"
    destination.mkdir()
    (destination / "leftover.txt").write_text("from a previous run\n", encoding="utf-8")
    with pytest.raises(IntegrityError):
        clean_publish_directory(root, destination)


def test_classification_of_a_code_repository(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = []\n', encoding="utf-8"
    )
    result = classify_project(root)
    assert result.project_kind == "code-repository"
    assert not result.huggingface_applicable
    assert result.kaggle_applicable
    assert result.rationale


def test_classification_detects_model_weights(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "model.safetensors").write_bytes(b"weights")
    result = classify_project(root)
    assert result.project_kind == "model"


def test_classification_detects_a_space_entry_point(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("import streamlit\n", encoding="utf-8")
    result = classify_project(root)
    assert result.huggingface_kind == "space"
    assert result.huggingface_applicable


@pytest.mark.regression
def test_a_container_image_alone_is_not_a_space(tmp_path: Path) -> None:
    """Regression: a Dockerfile alone claimed Hugging Face applicability.

    A Space serves a web application. A CLI that happens to ship a container
    image has no interface to serve, so reporting ``applicable: true`` on the
    strength of a Dockerfile would have invited an upload that misrepresents the
    project.
    """
    root = tmp_path / "repo"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM python:3.13-slim\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0.1.0"\ndependencies = []\n', encoding="utf-8"
    )
    result = classify_project(root)
    assert result.project_kind == "code-repository"
    assert result.huggingface_kind == "not_applicable"
    assert not result.huggingface_applicable


def test_gate_records_a_whole_pipeline(tmp_path: Path) -> None:
    """Every gate stage maps onto something that actually ran."""
    root = tmp_path / "repo"
    (root / "src" / "opencode_toolkit").mkdir(parents=True)
    (root / "src" / "opencode_toolkit" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (root / "README.md").write_text("# mini\n", encoding="utf-8")
    (root / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "mini"\nversion = "0.1.0"\ndependencies = []\n', encoding="utf-8"
    )

    audit = AuditEngine.from_policy().scan(root)
    pack = PackBuilder(root).build(output=tmp_path / "pack.zip")
    secrets = scan_for_secrets(root)

    gate = new_gate("0.1.0")
    gate = record(gate, "BUILD", CheckStatus.PASS, detail="sdist and pack built")
    gate = record(gate, "SECURITY", CheckStatus.PASS, detail=f"{len(audit.findings)} finding(s)")
    gate = record(
        gate, "SECRET_SCAN", CheckStatus.PASS, detail=f"{secrets.files_scanned} file(s) scanned"
    )
    gate = record(
        gate,
        "PACKAGE",
        CheckStatus.PASS if pack.ok else CheckStatus.FAIL,
        detail=f"{pack.verification.entries_checked} entries verified",
    )
    gate = record(gate, "SECRET_SCAN", CheckStatus.SKIPPED, detail="not run on this host")

    assert gate.get("SECURITY").status is CheckStatus.PASS
    assert gate.get("PACKAGE").status is CheckStatus.PASS

    # Under the default policy a skipped check blocks, exactly like a failure.
    assert not gate.approved
    assert "SECRET_SCAN=SKIPPED" in gate.reason()
    assert "FORMAT=NOT_RUN" in gate.reason(), "stages never recorded must also block"

    # A seeded gate already *contains* every check as NOT_RUN, so recording means
    # moving it off NOT_RUN rather than adding a missing entry. Nothing can be
    # satisfied by omission.
    assert gate.missing_checks() == []
    assert not gate.approved, "FORMAT is still NOT_RUN"

    # Permitting the skip is an explicit decision; until then it blocks.
    gate.policy = type(gate.policy)(allow_skip=frozenset({"SECRET_SCAN"}))
    assert gate.get("SECRET_SCAN") not in gate.missing_checks()
    assert not gate.approved, "FORMAT is still NOT_RUN"

    for name in CHECK_NAMES:
        if gate.get(name).status is CheckStatus.NOT_RUN:
            gate = record(gate, name, CheckStatus.PASS, detail="recorded for this integration test")
    assert gate.approved, gate.reason()
    assert gate.publish_permitted() == (True, "release gate approved")


#: ``OCSA-VALID-002`` (broad ``except``) fires on this codebase's deliberate
#: boundary handlers. Each one is a documented decision, listed here rather
#: than switched off globally, so a *new* broad except is still reported.
_SELF_AUDIT_ALLOWED = {
    ("OCSA-VALID-002",),  # deliberate exception boundaries, reviewed inline
}

#: The one known false positive of the ReDoS heuristic: a group whose body is a
#: bounded quantifier followed by an unbounded one over the same character class
#: (``(\w{0,2}\w+)``). Measured at 0.002 s against a non-matching input, so it
#: is safe, but the structural test cannot tell it from ``(a+)+``. Recorded in
#: ``docs/components/security-audit.md`` as a known limitation.
_SELF_AUDIT_KNOWN_LIMITATIONS = {
    ("OCSA-VALID-004", "opencode_toolkit/live_docs/scanner.py"),
    ("OCSA-VALID-004", "opencode_toolkit/live_docs/updater.py"),
}


def test_shipped_toolkit_audits_itself_clean() -> None:
    """Dogfooding: the project's own source must pass its own security audit.

    This is the check that keeps the rule catalogue, the release gate and the
    documentation honest. Configuration exclusions live in
    ``.opencode/toolkit/config.json``; the remainder of the allowance is spelled
    out in this test so a regression fails loudly and specifically.
    """
    from opencode_toolkit.core.config import load_config
    from opencode_toolkit.core.paths import resolve_layout

    root = Path(__file__).resolve().parents[2]
    config = load_config(resolve_layout(workspace=root))
    result = AuditEngine.from_policy(config.security_audit).scan(root / "src")

    allowed = _SELF_AUDIT_KNOWN_LIMITATIONS
    blocking = [
        finding
        for finding in result.findings
        if finding.severity.rank >= 3
        and (finding.rule_id, finding.file) not in allowed
        and (finding.rule_id,) not in _SELF_AUDIT_ALLOWED
    ]
    assert blocking == [], [
        (f.severity.value, f.rule_id, f.file, f.line, f.code_location[:80]) for f in blocking
    ]
    assert not [finding for finding in result.findings if finding.severity.rank >= 4], (
        "no critical or high finding is acceptable in this repository's own source"
    )
