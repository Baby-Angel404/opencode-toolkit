"""Unit tests for snippets, orchestrator, offline pack, live docs and release."""

from __future__ import annotations

import json
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

from opencode_toolkit.core.config import OrchestratorPolicy, PackPolicy
from opencode_toolkit.core.errors import (
    ConflictError,
    IntegrityError,
    NotFoundError,
    StateError,
    UsageError,
)
from opencode_toolkit.core.version import Version
from opencode_toolkit.live_docs.drift import (
    baseline_document,
    default_baseline_path,
    diff_against_baseline,
    load_baseline,
    write_baseline,
)
from opencode_toolkit.live_docs.scanner import Parameter, scan_tree
from opencode_toolkit.live_docs.updater import apply_updates, plan_file, preview_diff
from opencode_toolkit.offline_pack.builder import KNOWN_COMPONENTS, PackBuilder, inspect_pack
from opencode_toolkit.offline_pack.licenses import (
    EXCLUDED_RESTRICTED,
    EXCLUDED_UNKNOWN,
    LICENSE_POLICY,
    redistribution_decision,
)
from opencode_toolkit.offline_pack.manifest import verify_archive, write_manifest_json
from opencode_toolkit.orchestrator.checkpoint import CheckpointStore
from opencode_toolkit.orchestrator.coordinator import Coordinator
from opencode_toolkit.orchestrator.executor import CommandExecutor, NullExecutor, RecordingExecutor
from opencode_toolkit.orchestrator.graph import DependencyGraph, GraphError
from opencode_toolkit.orchestrator.models import Plan, Role, Task, TaskStatus, TaskWrite
from opencode_toolkit.release.artifacts import build_artifacts
from opencode_toolkit.release.changelog import (
    Fragment,
    changelog_markdown,
    load_fragments,
    write_fragment,
)
from opencode_toolkit.release.gate import (
    CHECK_NAMES,
    CheckStatus,
    GatePolicy,
    GateResult,
    new_gate,
    record,
)
from opencode_toolkit.release.sbom import sbom_document, sbom_summary
from opencode_toolkit.release.version import bump_version, find_version_line, next_prerelease
from opencode_toolkit.snippet_verified.models import (
    Snippet,
    SnippetStatus,
    SnippetValidationError,
)
from opencode_toolkit.snippet_verified.registry import (
    SnippetRegistry,
    default_registry,
    registry_stats,
)

pytestmark = pytest.mark.unit


# ==========================================================================
# snippets
# ==========================================================================


def test_bundled_registry_loads_and_validates() -> None:
    registry = default_registry()
    assert len(registry) >= 12
    stats = registry_stats(registry)
    assert stats["total"] == len(registry)
    assert set(stats["by_category"]) >= {"authentication", "authorization", "validation", "testing"}


def test_every_snippet_documents_its_risk_surface() -> None:
    for snippet in default_registry().all():
        assert len(snippet.security_notes) >= 2, snippet.id
        assert len(snippet.edge_cases) >= 1, snippet.id
        assert len(snippet.maintenance_notes) >= 1, snippet.id
        assert snippet.status in tuple(SnippetStatus)


def test_snippet_lookup_suggests_alternatives() -> None:
    registry = default_registry()
    with pytest.raises(NotFoundError) as excinfo:
        registry.get("python-password-hashin-argon2")
    assert excinfo.value.details["suggestions"]
    assert excinfo.value.hint


@pytest.mark.parametrize(
    ("query", "expected_fragment"),
    [
        ("password", "python-password-hashing-argon2"),
        ("jwt", "typescript-jwt-verification"),
        ("atomic", "python-atomic-file-write"),
        ("innerHTML", "typescript-safe-html-render"),
    ],
)
def test_search_finds_the_expected_snippet(query: str, expected_fragment: str) -> None:
    hits = default_registry().search(query)
    assert expected_fragment in {hit.snippet.id for hit in hits}
    assert hits == sorted(hits, key=lambda hit: (-hit.score, hit.snippet.id))


def test_search_rejects_an_empty_query() -> None:
    with pytest.raises(UsageError):
        default_registry().search("   ")


def test_search_reason_is_explicit_for_fuzzy_matches() -> None:
    hits = default_registry().search("pyhton-validating")
    if hits:
        assert "fuzzy" in hits[0].reason or "substring" in hits[0].reason


@pytest.mark.parametrize(
    "override",
    [
        {"implementation": "x = 1\n"},
        {"security_notes": []},
        {"edge_cases": []},
        {"maintenance_notes": []},
        {"status": "unknown"},
        {"category": "unknown"},
        {"language": "brainfuck"},
        {"version": "not-a-version"},
        {"id": "Not Kebab Case"},
        {"dependencies": "not-a-list"},
        {"security_notes": ["", "  "]},
    ],
)
def test_snippet_validation_rejects_malformed_entries(override: dict) -> None:
    document = {
        "id": "valid-id",
        "language": "python",
        "version": "1.0.0",
        "status": "stable",
        "category": "authentication",
        "implementation": "def f():\n    x = 1\n    y = 2\n    return x + y\n",
        "dependencies": [],
        "security_notes": ["a note"],
        "edge_cases": ["an edge"],
        "maintenance_notes": ["a note"],
    }
    document.update(override)
    with pytest.raises(SnippetValidationError) as excinfo:
        Snippet.from_dict(document)
    assert excinfo.value.details["problems"]


def test_registry_reports_every_invalid_snippet_at_once() -> None:
    document = {
        "snippets": [
            {
                "id": "a",
                "language": "python",
                "version": "1.0.0",
                "status": "stable",
                "category": "testing",
            },
            {
                "id": "b",
                "language": "nope",
                "version": "1.0.0",
                "status": "stable",
                "category": "testing",
            },
        ]
    }
    with pytest.raises(SnippetValidationError) as excinfo:
        SnippetRegistry.from_dict(document)
    assert len(excinfo.value.details["problems"]) >= 2


def test_registry_rejects_duplicate_ids() -> None:
    snippet = {
        "id": "dup",
        "language": "python",
        "version": "1.0.0",
        "status": "stable",
        "category": "testing",
        "implementation": "def f():\n    x = 1\n    y = 2\n    return x + y\n",
        "dependencies": [],
        "security_notes": ["n"],
        "edge_cases": ["e"],
        "maintenance_notes": ["m"],
    }
    with pytest.raises(SnippetValidationError) as excinfo:
        SnippetRegistry.from_dict({"snippets": [snippet, snippet]})
    assert "duplicate" in excinfo.value.message


def test_materialise_writes_a_provenance_header(tmp_path: Path) -> None:
    registry = default_registry()
    target = tmp_path / "out.py"
    result = registry.materialise("python-constant-time-compare", target)
    content = target.read_text()
    assert "opencode-verified-snippet: python-constant-time-compare" in content
    assert "Security notes:" in content
    assert result["created"] is True


def test_materialise_refuses_to_overwrite(tmp_path: Path) -> None:
    registry = default_registry()
    target = tmp_path / "out.py"
    target.write_text("# my own code\n", encoding="utf-8")
    with pytest.raises(ConflictError):
        registry.materialise("python-constant-time-compare", target)
    assert target.read_text() == "# my own code\n"


def test_materialise_with_force_replaces_and_records_the_previous_digest(tmp_path: Path) -> None:
    from opencode_toolkit.core.fsio import sha256_file

    registry = default_registry()
    target = tmp_path / "out.py"
    target.write_text("# my own code\n", encoding="utf-8")
    before = sha256_file(target)
    result = registry.materialise("python-constant-time-compare", target, overwrite=True)
    assert result["previous_sha256"] == before
    assert result["created"] is False


def test_deprecated_snippets_are_not_installed_without_force() -> None:
    document = {
        "snippets": [
            {
                "id": "old-thing",
                "language": "python",
                "version": "0.1.0",
                "status": "deprecated",
                "category": "testing",
                "summary": "superseded",
                "implementation": "def f():\n    x = 1\n    y = 2\n    return x + y\n",
                "dependencies": [],
                "security_notes": ["n"],
                "edge_cases": ["e"],
                "maintenance_notes": ["use the new thing instead"],
            }
        ]
    }
    registry = SnippetRegistry.from_dict(document)
    import tempfile

    with pytest.raises(UsageError) as excinfo:
        registry.materialise("old-thing", Path(tempfile.mkdtemp()) / "x.py")
    assert excinfo.value.code == "snippet.deprecated"


def test_verify_detects_user_modifications(tmp_path: Path) -> None:
    registry = default_registry()
    target = tmp_path / "out.py"
    registry.materialise("python-constant-time-compare", target)
    assert registry.verify("python-constant-time-compare", target)["matches"]
    # Edit the body, not the provenance header: the header repeats the API name
    # and would make a naive find-and-replace a no-op.
    snippet = registry.get("python-constant-time-compare")
    body_start = target.read_text(encoding="utf-8").index(snippet.implementation)
    text = target.read_text(encoding="utf-8")
    text = (
        text[:body_start]
        + snippet.implementation.replace("hmac.compare_digest", "operator.eq", 1)
        + text[body_start + len(snippet.implementation) :]
    )
    target.write_text(text, encoding="utf-8")
    result = registry.verify("python-constant-time-compare", target)
    assert result["header_present"] is True
    assert result["matches"] is False


@pytest.mark.regression
def test_verify_reports_a_file_that_never_had_the_snippet_as_not_installed(
    tmp_path: Path,
) -> None:
    """Regression: any existing file was reported as "present but modified".

    ``present`` was derived from the *file* existing rather than from the
    snippet being in it, so verifying a snippet against an unrelated file claimed
    the code had drifted when nothing had ever been installed there.
    """
    registry = default_registry()
    target = tmp_path / "unrelated.py"
    target.write_text("import os\n\nprint(os.getcwd())\n", encoding="utf-8")

    result = registry.verify("python-constant-time-compare", target)
    assert result["present"] is False, "the snippet is not in this file"
    assert result["matches"] is False
    assert result["header_present"] is False


def test_verify_still_detects_an_edit_below_the_body(tmp_path: Path) -> None:
    """Appending after the snippet keeps it verbatim, so it is unmodified."""
    registry = default_registry()
    target = tmp_path / "out.py"
    registry.materialise("python-constant-time-compare", target)
    target.write_text(target.read_text(encoding="utf-8") + "\n# my tweak\n", encoding="utf-8")
    result = registry.verify("python-constant-time-compare", target)
    assert result["matches"] is True, "text added after the snippet does not modify it"
    assert result["header_present"] is True


def test_verify_reports_an_absent_file(tmp_path: Path) -> None:
    result = default_registry().verify("python-constant-time-compare", tmp_path / "missing.py")
    assert result["present"] is False
    assert result["matches"] is False


# ==========================================================================
# orchestrator
# ==========================================================================


def _task(**kwargs) -> Task:
    defaults = {"id": "t", "title": "t", "role": Role.PLANNER}
    return Task(**{**defaults, **kwargs})


def test_graph_computes_execution_levels() -> None:
    graph = DependencyGraph.build(
        [
            _task(id="a", role=Role.PLANNER),
            _task(id="b", role=Role.CODE_AUTHOR, depends_on=("a",)),
            _task(id="c", role=Role.TESTER, depends_on=("b",)),
            _task(id="d", role=Role.SECURITY_REVIEWER, depends_on=("b",)),
            _task(id="e", role=Role.DOCUMENTATION_MAINTAINER, depends_on=("d",)),
        ]
    )
    assert [sorted(level) for level in graph.levels] == [["a"], ["b"], ["c", "d"], ["e"]]
    assert graph.depth == 4


def test_graph_detects_cycles() -> None:
    with pytest.raises(GraphError) as excinfo:
        DependencyGraph.build(
            [
                _task(id="a", depends_on=("b",)),
                _task(id="b", depends_on=("a",)),
            ]
        )
    assert set(excinfo.value.details["tasks_in_cycle"]) == {"a", "b"}


def test_graph_detects_self_dependency() -> None:
    with pytest.raises(GraphError) as excinfo:
        DependencyGraph.build([_task(id="a", depends_on=("a",))])
    assert any("itself" in problem for problem in excinfo.value.details["problems"])


def test_graph_detects_unknown_dependency() -> None:
    with pytest.raises(GraphError) as excinfo:
        DependencyGraph.build([_task(id="a", depends_on=("ghost",))])
    assert any("unknown task" in problem for problem in excinfo.value.details["problems"])


def test_graph_detects_duplicate_ids() -> None:
    with pytest.raises(GraphError):
        DependencyGraph.build([_task(id="a"), _task(id="a", role=Role.CODE_AUTHOR)])


def test_graph_detects_write_collisions() -> None:
    with pytest.raises(GraphError) as excinfo:
        DependencyGraph.build(
            [
                _task(id="a", role=Role.CODE_AUTHOR, writes=(TaskWrite(path="f.py"),)),
                _task(id="b", role=Role.CODE_AUTHOR, writes=(TaskWrite(path="f.py"),)),
            ]
        )
    assert any("both write" in problem for problem in excinfo.value.details["problems"])


def test_testers_may_not_write_files() -> None:
    with pytest.raises(UsageError) as excinfo:
        DependencyGraph.build([_task(id="a", role=Role.TESTER, writes=(TaskWrite(path="f.py"),))])
    assert excinfo.value.code == "orchestrator.role_capability_violation"


def test_planner_may_not_execute_commands() -> None:
    with pytest.raises(UsageError) as excinfo:
        DependencyGraph.build([_task(id="a", role=Role.PLANNER, command=("ls",))])
    assert excinfo.value.code == "orchestrator.role_capability_violation"


def test_empty_task_id_is_rejected() -> None:
    with pytest.raises(UsageError):
        DependencyGraph.build([_task(id="  ", role=Role.PLANNER)])


def test_ready_set_respects_dependencies() -> None:
    graph = DependencyGraph.build(
        [
            _task(id="a", role=Role.PLANNER),
            _task(id="b", role=Role.CODE_AUTHOR, depends_on=("a",)),
        ]
    )
    assert [task.id for task in graph.ready(set())] == ["a"]
    assert [task.id for task in graph.ready({"a"})] == ["b"]
    assert graph.ready({"a", "b"}) == []
    assert graph.downstream_of("a") == {"b"}


def _demo_plan(workspace: Path) -> Plan:
    return Plan(
        name="demo",
        workspace=str(workspace),
        tasks=(
            _task(id="plan", title="Plan", role=Role.PLANNER),
            _task(
                id="author",
                title="Author",
                role=Role.CODE_AUTHOR,
                depends_on=("plan",),
                command=(sys.executable, "-c", "print('authored')"),
            ),
            _task(
                id="test",
                title="Test",
                role=Role.TESTER,
                depends_on=("author",),
                command=(sys.executable, "-c", "raise SystemExit(1)"),
            ),
            _task(id="review", title="Review", role=Role.SECURITY_REVIEWER, depends_on=("author",)),
            # Documentation depends on the tests passing, so a failing test must
            # block it rather than silently produce docs for untested behaviour.
            _task(
                id="docs", title="Docs", role=Role.DOCUMENTATION_MAINTAINER, depends_on=("test",)
            ),
        ),
    )


def test_run_blocks_downstream_of_a_failure(tmp_path: Path) -> None:
    store = CheckpointStore(tmp_path / "orch")
    coordinator = Coordinator(
        tmp_path, policy=OrchestratorPolicy(), executor=CommandExecutor(), store=store
    )
    result = coordinator.run(_demo_plan(tmp_path), run_id="r1")
    assert not result.ok
    assert result.completed() == ["author", "plan", "review"]
    assert result.failed() == ["test"]
    assert set(result.blocked()) == {"docs"}
    assert any("dependency" in error for error in result.errors)


def test_resume_does_not_rerun_completed_tasks(tmp_path: Path) -> None:
    store = CheckpointStore(tmp_path / "orch")
    executor = RecordingExecutor(NullExecutor())
    coordinator = Coordinator(tmp_path, executor=executor, store=store)
    plan = Plan(
        name="resume",
        tasks=(
            _task(id="a", title="A", role=Role.PLANNER),
            _task(id="b", title="B", role=Role.PLANNER, depends_on=("a",)),
        ),
    )
    first = coordinator.run(plan, run_id="r1")
    assert first.ok
    assert len(executor.calls) == 2

    checkpoint = store.load("latest")
    second = coordinator.run(plan, run_id="r1", resume_from=checkpoint)
    assert second.ok
    assert len(executor.calls) == 2, "resume re-executed completed tasks"


def test_command_executor_runs_and_redacts(tmp_path: Path) -> None:
    task = _task(
        id="a",
        role=Role.TESTER,
        command=(
            sys.executable,
            "-c",
            'print("api_key=supersecretvalue123456")',
        ),
    )
    outcome = CommandExecutor().execute(task, workspace=tmp_path, run_id="r")
    assert outcome.ok
    assert "supersecretvalue123456" not in outcome.output
    assert "redacted" in outcome.output


def test_command_executor_enforces_a_timeout(tmp_path: Path) -> None:
    task = _task(
        id="a",
        role=Role.TESTER,
        command=(sys.executable, "-c", "import time; time.sleep(30)"),
        timeout_seconds=1,
    )
    outcome = CommandExecutor().execute(task, workspace=tmp_path, run_id="r")
    assert not outcome.ok
    assert "timeout" in outcome.error
    assert outcome.retryable


def test_command_executor_reports_a_missing_binary(tmp_path: Path) -> None:
    task = _task(id="a", role=Role.TESTER, command=("definitely-not-a-real-binary",))
    outcome = CommandExecutor().execute(task, workspace=tmp_path, run_id="r")
    assert not outcome.ok
    assert "command not found" in outcome.error


def test_command_executor_confirms_a_declared_write_happened(tmp_path: Path) -> None:
    target = tmp_path / "output.txt"
    target.write_text("pre-existing\n", encoding="utf-8")
    task = _task(
        id="a",
        role=Role.CODE_AUTHOR,
        command=(sys.executable, "-c", "open('output.txt','w').write('new')"),
        writes=(TaskWrite(path="output.txt"),),
    )
    outcome = CommandExecutor().execute(task, workspace=tmp_path, run_id="r")
    assert outcome.ok
    assert outcome.writes_verified == ["output.txt"]


def test_command_executor_flags_a_declared_write_that_never_happened(tmp_path: Path) -> None:
    task = _task(
        id="a",
        role=Role.CODE_AUTHOR,
        command=(sys.executable, "-c", "print('did nothing')"),
        writes=(TaskWrite(path="never_created.txt"),),
    )
    outcome = CommandExecutor().execute(task, workspace=tmp_path, run_id="r")
    assert not outcome.ok
    assert outcome.conflicts == ["never_created.txt"]


def test_command_executor_flags_an_unchanged_declared_write(tmp_path: Path) -> None:
    from opencode_toolkit.core.fsio import sha256_file

    target = tmp_path / "output.txt"
    target.write_text("unchanged\n", encoding="utf-8")
    task = _task(
        id="a",
        role=Role.CODE_AUTHOR,
        command=(sys.executable, "-c", "print('ran but wrote nothing')"),
        writes=(TaskWrite(path="output.txt", expected_sha256=sha256_file(target)),),
    )
    outcome = CommandExecutor().execute(task, workspace=tmp_path, run_id="r")
    assert not outcome.ok
    assert outcome.conflicts == ["output.txt"]


def _crashing_command() -> tuple[str, ...]:
    """Return a command that dies the way a crash does, on any platform.

    ``os.kill(getpid(), SIGKILL)`` gives a *negative* returncode on POSIX, which
    is exactly what the retry policy reads as a crash. Windows has no SIGKILL at
    all -- the attribute does not even exist -- and it reports a positive exit
    code when a process dies, so there the same retry decision is reached
    through the other branch the policy accepts.
    """
    if os.name == "nt":
        return (sys.executable, "-c", "raise SystemExit(124)")
    return (sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)")


def test_task_retries_a_retryable_failure(tmp_path: Path) -> None:
    """A killed process is retried; a clean non-zero exit is not."""
    store = CheckpointStore(tmp_path / "orch")
    coordinator = Coordinator(
        tmp_path,
        policy=OrchestratorPolicy(max_task_retries=2),
        executor=CommandExecutor(),
        store=store,
    )
    plan = Plan(
        name="retry",
        tasks=(
            _task(
                id="a",
                title="A",
                role=Role.TESTER,
                command=_crashing_command(),
            ),
        ),
    )
    result = coordinator.run(plan, run_id="r")
    assert result.failed() == ["a"]
    events = [record["event"] for record in store.journal(run_id="r")]
    assert events.count("task_started") == 3
    assert events.count("task_retry") == 2


def test_deterministic_failure_is_not_retried(tmp_path: Path) -> None:
    store = CheckpointStore(tmp_path / "orch")
    coordinator = Coordinator(
        tmp_path,
        policy=OrchestratorPolicy(max_task_retries=2),
        executor=CommandExecutor(),
        store=store,
    )
    plan = Plan(
        name="noretry",
        tasks=(
            _task(
                id="a",
                title="A",
                role=Role.TESTER,
                command=(sys.executable, "-c", "import sys; sys.exit(1)"),
            ),
        ),
    )
    result = coordinator.run(plan, run_id="r")
    assert result.failed() == ["a"]
    events = [record["event"] for record in store.journal(run_id="r")]
    assert events.count("task_started") == 1


def test_journal_records_every_transition(tmp_path: Path) -> None:
    store = CheckpointStore(tmp_path / "orch")
    coordinator = Coordinator(tmp_path, executor=NullExecutor(), store=store)
    coordinator.run(
        Plan(name="j", tasks=(_task(id="a", title="A", role=Role.PLANNER),)), run_id="r"
    )
    events = [record["event"] for record in store.journal(run_id="r")]
    assert events[0] == "run_started"
    assert events[-1] == "run_finished"
    assert "task_started" in events
    assert "task_finished" in events


def test_checkpoints_are_written_per_transition(tmp_path: Path) -> None:
    store = CheckpointStore(tmp_path / "orch")
    coordinator = Coordinator(tmp_path, executor=NullExecutor(), store=store)
    coordinator.run(
        Plan(
            name="c",
            tasks=(
                _task(id="a", title="A", role=Role.PLANNER),
                _task(id="b", title="B", role=Role.PLANNER, depends_on=("a",)),
            ),
        ),
        run_id="r",
    )
    assert len(store.list_checkpoints()) == 2


def test_checkpoint_restores_plan_state(tmp_path: Path) -> None:
    store = CheckpointStore(tmp_path / "orch")
    coordinator = Coordinator(tmp_path, executor=CommandExecutor(), store=store)
    coordinator.run(
        Plan(
            name="r",
            tasks=(
                _task(id="a", title="A", role=Role.PLANNER),
                _task(
                    id="b",
                    title="B",
                    role=Role.TESTER,
                    command=(sys.executable, "-c", "import sys; sys.exit(3)"),
                ),
            ),
        ),
        run_id="r",
    )
    checkpoint = store.load("latest")
    restored = checkpoint.restored_plan()
    statuses = {task.id: task.status for task in restored.tasks}
    assert statuses["a"] is TaskStatus.COMPLETED
    assert statuses["b"] is TaskStatus.FAILED


def test_plan_roundtrip(tmp_path: Path) -> None:
    from opencode_toolkit.core import jsonio

    plan = _demo_plan(tmp_path)
    document = plan.to_dict()
    jsonio.write(tmp_path / "plan.json", document)
    assert Plan.from_dict(jsonio.read(tmp_path / "plan.json")).name == plan.name


def test_plan_from_foreign_document_is_rejected() -> None:
    with pytest.raises(StateError) as excinfo:
        Plan.from_dict({"kind": "something-else", "tasks": []})
    assert excinfo.value.code == "orchestrator.not_a_plan"


def test_plan_with_no_tasks_is_rejected() -> None:
    with pytest.raises(StateError):
        Plan.from_dict({"kind": "opencode-toolkit/plan", "schema": 1, "tasks": []})


# ==========================================================================
# offline pack
# ==========================================================================


@pytest.fixture
def pack_root(tmp_path: Path) -> Path:
    """A miniature repository the pack builder can package."""
    root = tmp_path / "repo"
    (root / "src" / "opencode_toolkit" / "core").mkdir(parents=True)
    (root / "src" / "opencode_toolkit" / "security_audit").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "src" / "opencode_toolkit" / "core" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (root / "src" / "opencode_toolkit" / "security_audit" / "b.py").write_text(
        "B = 2\n", encoding="utf-8"
    )
    (root / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
    (root / "README.md").write_text("# Mini\n", encoding="utf-8")
    (root / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "mini"\nversion = "0.1.0"\ndependencies = []\n'
        '[project.optional-dependencies]\ndev = ["pytest>=8", "ruff>=0.6"]\n',
        encoding="utf-8",
    )
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (root / ".env").write_text("SECRET_TOKEN=abcdef123456\n", encoding="utf-8")
    return root


def test_pack_builds_and_verifies(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, policy=PackPolicy(), version=Version(1, 0, 0))
    result = builder.build(output=tmp_path / "pack.zip")
    assert result.ok
    assert result.verification.entries_checked == len(result.manifest.entries)
    assert "package/src/opencode_toolkit/core/a.py" in {
        entry.path for entry in result.manifest.entries
    }


def test_pack_excludes_secrets_and_vcs_metadata(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    result = builder.build(output=tmp_path / "pack.zip")
    paths = {entry.path for entry in result.manifest.entries}
    assert ".env" not in paths
    assert not any(path.startswith(".git/") for path in paths)


def test_pack_is_byte_reproducible(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    first = builder.build(output=tmp_path / "one.zip")
    second = builder.build(output=tmp_path / "two.zip")
    assert first.archive.read_bytes() == second.archive.read_bytes()
    assert first.manifest.content_digest() == second.manifest.content_digest()


def test_pack_verification_detects_tampering(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    result = builder.build(output=tmp_path / "pack.zip")

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(result.archive) as source, zipfile.ZipFile(tampered, "w") as sink:
        for name in source.namelist():
            data = source.read(name)
            if name.endswith("a.py"):
                data = b"A = 999\n"
            sink.writestr(name, data)

    report = verify_archive(tampered)
    assert not report.ok
    assert any("a.py" in path for path in report.mismatched)


def test_pack_verification_detects_a_removed_file(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    result = builder.build(output=tmp_path / "pack.zip")
    stripped = tmp_path / "stripped.zip"
    with zipfile.ZipFile(result.archive) as source, zipfile.ZipFile(stripped, "w") as sink:
        for name in source.namelist():
            if not name.endswith("a.py"):
                sink.writestr(name, source.read(name))
    report = verify_archive(stripped)
    assert not report.ok
    assert report.missing


def test_pack_verification_detects_an_extra_file(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    result = builder.build(output=tmp_path / "pack.zip")
    extra = tmp_path / "extra.zip"
    with zipfile.ZipFile(result.archive) as source, zipfile.ZipFile(extra, "w") as sink:
        for name in source.namelist():
            sink.writestr(name, source.read(name))
        sink.writestr("package/smuggled.py", b"x = 1\n")
    assert not verify_archive(extra).ok


def test_unknown_component_is_rejected(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    with pytest.raises(UsageError) as excinfo:
        builder.resolve_components(["not-a-component"])
    assert excinfo.value.code == "pack.unknown_component"


def test_core_is_always_included(pack_root: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    assert "core" in builder.resolve_components(["security-audit"])


def test_component_selection_limits_the_contents(pack_root: Path, tmp_path: Path) -> None:
    """Selecting a component excludes the others, except core which is required."""
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    result = builder.build(components=["security-audit"], output=tmp_path / "one.zip")
    paths = {entry.path for entry in result.manifest.entries}
    assert "package/src/opencode_toolkit/security_audit/b.py" in paths
    assert "package/src/opencode_toolkit/core/a.py" in paths, (
        "core is a hard dependency of every component"
    )
    assert result.manifest.components == ["core", "security-audit"]


def test_licence_policy_refuses_unknown_dependencies() -> None:
    decision = redistribution_decision("some-unknown-package", installed=True)
    assert not decision.bundled
    assert decision.reason == EXCLUDED_UNKNOWN


def test_licence_policy_refuses_restrictive_licences() -> None:
    decision = redistribution_decision("example-restricted-dependency", installed=True)
    assert not decision.bundled
    assert decision.reason == EXCLUDED_RESTRICTED


def test_licence_policy_requires_attribution() -> None:
    decision = redistribution_decision("pytest", installed=True, include_attribution=False)
    assert not decision.bundled


def test_licence_policy_allows_a_permitted_dependency() -> None:
    decision = redistribution_decision("pytest", installed=True)
    assert decision.bundled
    assert decision.spdx == "MIT"


def test_every_curated_licence_cites_its_source() -> None:
    # `entry`, not `record`: the latter would shadow the imported `record`
    # helper inside the loop and silently break any later call.
    for name, entry in LICENSE_POLICY.items():
        assert entry.reference, name
        assert entry.spdx, name


def test_pack_records_excluded_dependencies_with_reasons(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    result = builder.build(output=tmp_path / "pack.zip")
    names = {item["name"] for item in result.manifest.excluded}
    assert {"pytest", "ruff"} <= names
    for item in result.manifest.excluded:
        assert item["reason"]


def test_pack_inspect_summarises_contents(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    result = builder.build(output=tmp_path / "pack.zip")
    summary = inspect_pack(result.archive)
    assert summary["version"] == "1.0.0"
    assert summary["entries_by_component"]["core"] == 1
    assert summary["licenses"][0]["spdx"] == "Apache-2.0"


def test_pack_checksums_file_matches_the_manifest(pack_root: Path, tmp_path: Path) -> None:
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    result = builder.build(output=tmp_path / "pack.zip")
    with zipfile.ZipFile(result.archive) as bundle:
        body = bundle.read("SHA256SUMS").decode()
        manifest = json.loads(bundle.read("manifest.json"))
    for entry in manifest["entries"]:
        assert f"{entry['sha256']}  {entry['path']}" in body


def test_incremental_pack_requires_a_verified_base(pack_root: Path, tmp_path: Path) -> None:
    """An unreadable base is refused, and so is a readable base that fails verify."""
    builder = PackBuilder(pack_root, version=Version(1, 0, 0))
    corrupt = tmp_path / "corrupt.zip"
    corrupt.write_bytes(b"not a zip at all")
    with pytest.raises(IntegrityError):
        builder.build(output=tmp_path / "inc.zip", incremental_base=corrupt)

    base = builder.build(output=tmp_path / "base.zip")
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(base.archive) as source, zipfile.ZipFile(tampered, "w") as sink:
        for name in source.namelist():
            data = source.read(name)
            if name.endswith("a.py"):
                data = b"tampered\n"
            sink.writestr(name, data)
    with pytest.raises(UsageError) as excinfo:
        builder.build(output=tmp_path / "inc.zip", incremental_base=tampered)
    assert excinfo.value.code == "pack.incremental_base_invalid"


def test_manifest_serialisation_is_deterministic() -> None:
    from opencode_toolkit.offline_pack.manifest import PackEntry, PackManifest

    manifest = PackManifest(
        name="p",
        version="1.0.0",
        created_at="2026-01-01T00:00:00Z",
        entries=[PackEntry(path="b.py", sha256="0" * 64, size=1)],
    )
    manifest.entries.append(PackEntry(path="a.py", sha256="1" * 64, size=2))
    assert write_manifest_json(manifest) == write_manifest_json(manifest)
    assert (
        manifest.content_digest()
        == PackManifest(
            name="p",
            version="1.0.0",
            created_at="2026-01-01T00:00:00Z",
            entries=list(reversed(manifest.entries)),
        ).content_digest()
    )


def test_known_components_match_the_package_layout() -> None:
    from opencode_toolkit.offline_pack.builder import COMPONENT_PATHS
    from opencode_toolkit.offline_pack.manifest import KNOWN_COMPONENTS as manifest_components

    assert set(COMPONENT_PATHS) == set(KNOWN_COMPONENTS) == set(manifest_components)


# ==========================================================================
# live docs
# ==========================================================================

DOC_SOURCE = '''"""Module summary.

Prose that must survive a rewrite untouched.
"""

import os


def alpha(first, second=3, *, flag=True):
    """Do the alpha thing.

    Longer prose about the alpha thing.

    Args:
        first: the first input.
        second: the second input.

    Returns:
        A tuple of results.

    Raises:
        ValueError: when the inputs are bad.

    Note:
        This note must survive verbatim.
    """
    return first, second, flag


def undocumented(x):
    return x


class Widget:
    """A widget."""

    def __init__(self, size):
        """Build it.

        Args:
            size: how big.
        """
        self.size = size


def _private(x):
    return x
'''


@pytest.fixture
def doc_tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "m.py").write_text(DOC_SOURCE, encoding="utf-8")
    return root


def test_scanner_extracts_python_api(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    names = {item.qualified_name for item in surface.items}
    assert names == {"alpha", "undocumented", "Widget"}
    alpha = next(item for item in surface.items if item.name == "alpha")
    assert alpha.documented
    assert [p.name for p in alpha.parameters] == ["first", "second", "flag"]
    assert alpha.undocumented_parameters() == ["flag"]
    assert alpha.is_async is False


def test_scanner_marks_heuristic_items(doc_tree: Path) -> None:
    (doc_tree / "app.js").write_text(
        "export function doThing(a, b) {\n  return a;\n}\n", encoding="utf-8"
    )
    (doc_tree / "svc.go").write_text(
        "package m\n\nfunc Handler(w int) error {\n\treturn nil\n}\n", encoding="utf-8"
    )
    surface = scan_tree(doc_tree)
    js = next(item for item in surface.items if item.file.endswith("app.js"))
    go = next(item for item in surface.items if item.file.endswith("svc.go"))
    assert js.heuristic and go.heuristic
    assert js.name == "doThing" and go.name == "Handler"


def test_scanner_reports_parse_errors(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def f(:\n", encoding="utf-8")
    surface = scan_tree(tmp_path)
    assert surface.parse_errors
    assert "syntax" in surface.parse_errors[0]["error"]


def test_scan_is_deterministic(doc_tree: Path) -> None:
    assert scan_tree(doc_tree).digest_items() == scan_tree(doc_tree).digest_items()


def test_missing_baseline_reports_everything_as_added(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    report = diff_against_baseline(surface, None, baseline_path=default_baseline_path(doc_tree))
    assert report.by_kind() == {"added": len(surface.items)}
    assert report.has_blocking()


def test_baseline_roundtrip(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    path = write_baseline(default_baseline_path(doc_tree), surface)
    report = diff_against_baseline(surface, load_baseline(path), baseline_path=path)
    assert report.by_kind() == {"undocumented": 2}
    assert {item.qualified_name for item in report.items} == {"alpha", "undocumented"}


def test_baseline_write_refuses_to_clobber(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    path = default_baseline_path(doc_tree)
    write_baseline(path, surface)
    with pytest.raises(ConflictError):
        write_baseline(path, surface)


@pytest.mark.regression
def test_baseline_write_force_replaces_existing(doc_tree: Path) -> None:
    """Regression: ``--force`` was advertised by the parser but never honoured.

    The flag existed, the hint told the operator to use it, and the write still
    refused -- so a regenerated baseline was impossible without deleting the file
    by hand.
    """
    surface = scan_tree(doc_tree)
    path = default_baseline_path(doc_tree)
    write_baseline(path, surface)
    first = path.read_text(encoding="utf-8")
    write_baseline(path, surface, force=True)
    assert path.read_text(encoding="utf-8") == first


def test_baseline_from_foreign_document_is_rejected(tmp_path: Path) -> None:
    from opencode_toolkit.core import jsonio

    path = tmp_path / "baseline.json"
    jsonio.write(path, {"kind": "something-else", "items": []})
    with pytest.raises(StateError):
        load_baseline(path)


def test_baseline_schema_mismatch_is_reported(tmp_path: Path) -> None:
    from opencode_toolkit.core import jsonio

    path = tmp_path / "baseline.json"
    jsonio.write(path, {"kind": "opencode-toolkit/docs-baseline", "schema": 999, "items": []})
    with pytest.raises(StateError) as excinfo:
        load_baseline(path)
    assert excinfo.value.code == "docs.schema_mismatch"


def test_signature_change_is_reported_as_changed(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    path = write_baseline(default_baseline_path(doc_tree), surface)
    (doc_tree / "m.py").write_text(
        DOC_SOURCE.replace(
            "def alpha(first, second=3, *, flag=True):",
            "def alpha(first, second=3, *, flag=True, extra=None):",
        ),
        encoding="utf-8",
    )
    updated = scan_tree(doc_tree)
    report = diff_against_baseline(updated, load_baseline(path), baseline_path=path)
    assert report.by_kind().get("changed") == 1
    assert report.has_blocking()


def test_updater_adds_a_missing_parameter_and_preserves_prose(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    items = [item for item in surface.items if item.file == "m.py"]
    before = (doc_tree / "m.py").read_text(encoding="utf-8")
    diffs = preview_diff(doc_tree, items)
    assert diffs
    patch = diffs[0]["diff"]
    assert "flag: TODO" in patch
    for preserved in (
        "Prose that must survive a rewrite untouched.",
        "Longer prose about the alpha thing.",
        "ValueError: when the inputs are bad.",
        "This note must survive verbatim.",
        "the first input.",
    ):
        assert preserved in before
    applied = apply_updates(doc_tree, items, write=False)
    assert [item.status for item in applied.files] == ["updated"]
    assert (doc_tree / "m.py").read_text(encoding="utf-8") == before, "a dry run must not write"


def test_updater_write_only_changes_owned_sections(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    items = [item for item in surface.items if item.file == "m.py"]
    apply_updates(doc_tree, items, write=True)
    after = (doc_tree / "m.py").read_text(encoding="utf-8")
    assert "flag: TODO" in after
    for preserved in (
        '"""Module summary.',
        "Prose that must survive a rewrite untouched.",
        "This note must survive verbatim.",
        "first: the first input.",
        "ValueError: when the inputs are bad.",
    ):
        assert preserved in after
    import ast

    ast.parse(after)


def test_updater_skips_functions_without_an_args_block(doc_tree: Path) -> None:
    (doc_tree / "n.py").write_text(
        'def no_blocks(a, b):\n    """Just prose.\n\n    More prose.\n    """\n    return a\n',
        encoding="utf-8",
    )
    surface = scan_tree(doc_tree)
    items = [item for item in surface.items if item.file == "n.py"]
    update, text = plan_file(doc_tree, items)
    assert update.status == "unchanged"
    assert text == (doc_tree / "n.py").read_text(encoding="utf-8")


def test_updater_reports_a_file_it_cannot_read(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    items = [item for item in surface.items if item.file == "m.py"]
    (doc_tree / "m.py").unlink()
    update, _ = plan_file(doc_tree, items)
    assert update.status == "needs_review"


def test_drift_report_is_serialisable_and_blocks(doc_tree: Path) -> None:
    surface = scan_tree(doc_tree)
    report = diff_against_baseline(surface, None, baseline_path=None)
    assert report.has_blocking()
    assert report.by_kind() == {"added": len(surface.items)}
    payload = report.to_dict()
    assert payload["blocking"] is True
    assert json.loads(json.dumps(payload))["total"] == len(report.items)


def test_baseline_document_is_self_describing(doc_tree: Path) -> None:
    document = baseline_document(scan_tree(doc_tree))
    assert document["kind"] == "opencode-toolkit/docs-baseline"
    assert document["items"]


def test_scanner_ignores_private_names(doc_tree: Path) -> None:
    assert "_private" not in {item.qualified_name for item in scan_tree(doc_tree).items}


def test_parameter_signature_rendering() -> None:
    assert Parameter(name="x", annotation="int", default="1").signature() == "x: int = 1"
    assert Parameter(name="args", kind="var_positional").signature() == "args"


# ==========================================================================
# release: version, changelog, gate, sbom, artefacts
# ==========================================================================


@pytest.mark.parametrize(
    ("version", "kind", "expected"),
    [
        ("1.2.3", "major", "2.0.0"),
        ("1.2.3", "minor", "1.3.0"),
        ("1.2.3", "patch", "1.2.4"),
        ("1.2.3-rc.1", "patch", "1.2.4"),
    ],
)
def test_version_bumps(version: str, kind: str, expected: str) -> None:
    assert str(bump_version(Version.parse(version), kind)) == expected


def test_unknown_bump_kind_is_rejected() -> None:
    from opencode_toolkit.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        bump_version(Version(1, 0, 0), "epoch")


def test_prerelease_labels_are_validated() -> None:
    from opencode_toolkit.core.errors import ConfigurationError

    assert str(next_prerelease(Version(1, 0, 0), "rc.1")) == "1.0.0-rc.1"
    with pytest.raises(ConfigurationError):
        next_prerelease(Version(1, 0, 0), "final")


def test_find_version_line_locates_the_project_table() -> None:
    text = "[tool.ruff]\nversion = 'not this'\n\n[project]\nversion = \"1.2.3\"\n"
    line, value = find_version_line(text)
    assert value == "1.2.3"
    assert text.splitlines()[line - 1].strip().startswith("version")


def test_find_version_line_reports_a_malformed_file() -> None:
    from opencode_toolkit.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        find_version_line("[tool.ruff]\nline-length = 100\n")


def test_changelog_fragment_roundtrip(tmp_path: Path) -> None:
    fragment = Fragment(id="f1", kind="fixed", area="sync", description="Fix the thing.")
    write_fragment(tmp_path, fragment)
    assert load_fragments(tmp_path) == [fragment]


def test_changelog_rejects_an_unknown_type() -> None:
    from opencode_toolkit.core.errors import StateError

    with pytest.raises(StateError):
        Fragment(id="f", kind="tweaked", area="", description="x")


def test_changelog_rejects_an_empty_description() -> None:
    from opencode_toolkit.core.errors import StateError

    with pytest.raises(StateError):
        Fragment(id="f", kind="fixed", area="", description="   ")


def test_changelog_renders_grouped_sections(tmp_path: Path) -> None:
    write_fragment(tmp_path, Fragment(id="a", kind="added", area="pack", description="Add X."))
    write_fragment(tmp_path, Fragment(id="b", kind="fixed", area="docs", description="Fix Y."))
    text = changelog_markdown(tmp_path)
    assert "### Added" in text
    assert "### Fixed" in text
    assert "Add X." in text
    assert "## Unreleased" in text


def test_changelog_preserves_history(tmp_path: Path) -> None:
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\npreamble\n\n## 1.0.0 - 2026-01-01\n\n### Added\n\n* Old thing\n",
        encoding="utf-8",
    )
    text = changelog_markdown(tmp_path)
    assert "## 1.0.0 - 2026-01-01" in text
    assert "* Old thing" in text


def test_changelog_flags_breaking_changes(tmp_path: Path) -> None:
    write_fragment(
        tmp_path,
        Fragment(id="a", kind="removed", area="cli", description="Remove --legacy.", breaking=True),
    )
    assert "**Breaking change.**" in changelog_markdown(tmp_path)


# -- release gate ----------------------------------------------------------


def test_new_gate_is_blocked_because_nothing_has_run() -> None:
    gate = new_gate("1.0.0")
    assert not gate.approved
    assert gate.decision == "BLOCKED"
    assert len(gate.checks) == len(CHECK_NAMES)
    assert all(check.status is CheckStatus.NOT_RUN for check in gate.checks)


def test_gate_requires_every_check_to_be_present() -> None:
    gate = new_gate("1.0.0")
    trimmed = GateResult(version="1.0.0", checks=gate.checks[:-1])
    assert not trimmed.approved
    assert "absent" in trimmed.reason()


def test_not_run_blocks_even_when_everything_else_passes() -> None:
    gate = new_gate("1.0.0")
    for name in CHECK_NAMES:
        gate = record(gate, name, CheckStatus.PASS, detail="ok")
    assert gate.approved
    # Re-open one check: an unrun check must block exactly like a failure.
    gate = record(gate, "UNIT_TEST", CheckStatus.NOT_RUN)
    assert not gate.approved
    assert "UNIT_TEST=NOT_RUN" in gate.reason()


@pytest.mark.parametrize(
    "status",
    [CheckStatus.SKIPPED, CheckStatus.UNKNOWN, CheckStatus.FAIL],
)
def test_every_non_pass_status_blocks(status: CheckStatus) -> None:
    gate = new_gate("1.0.0")
    for name in CHECK_NAMES:
        gate = record(gate, name, CheckStatus.PASS, detail="ok")
    gate = record(gate, "PACKAGE", status, detail="environment limitation")
    assert not gate.approved


def test_a_gate_with_every_check_present_but_one_missing_a_record_is_blocked() -> None:
    gate = new_gate("1.0.0")
    gate.checks = [check for check in gate.checks if check.name != "PACKAGE"]
    assert not gate.approved
    assert "PACKAGE" in gate.reason()


def test_unsubstantiated_pass_is_refused() -> None:
    gate = new_gate("1.0.0")
    with pytest.raises(StateError) as excinfo:
        record(gate, "BUILD", CheckStatus.PASS)
    assert excinfo.value.code == "release.unsubstantiated_pass"


def test_policy_can_permit_a_named_skip() -> None:
    gate = new_gate("1.0.0")
    for name in CHECK_NAMES:
        gate = record(gate, name, CheckStatus.PASS, detail="ok")
    gate = record(gate, "SECURITY", CheckStatus.SKIPPED, detail="not applicable on this host")
    assert not gate.approved

    gate.policy = GatePolicy(allow_skip=frozenset({"SECURITY"}))
    assert gate.approved
    assert "SECURITY" in gate.policy.to_dict()["allow_skip"]


def test_policy_can_permit_warnings_when_configured() -> None:
    gate = new_gate("1.0.0")
    for name in CHECK_NAMES:
        gate = record(gate, name, CheckStatus.PASS, detail="ok")
    gate = record(gate, "DOCUMENTATION", CheckStatus.WARN, detail="one stale reference")
    assert not gate.approved
    gate.policy = GatePolicy(allow_warnings=True)
    assert gate.approved


def test_gate_record_accepts_a_status_string() -> None:
    gate = record(new_gate("1.0.0"), "BUILD", "pass", detail="wheel built")
    assert gate.get("BUILD").status is CheckStatus.PASS


def test_publish_permitted_requires_approval() -> None:
    gate = new_gate("1.0.0")
    permitted, reason = gate.publish_permitted()
    assert not permitted
    assert "NOT_RUN" in reason
    for name in CHECK_NAMES:
        gate = record(gate, name, CheckStatus.PASS, detail="ok")
    assert gate.publish_permitted() == (True, "release gate approved")


def test_gate_serialisation_roundtrip() -> None:
    gate = record(new_gate("1.0.0", commit="abc"), "BUILD", CheckStatus.PASS, detail="built")
    restored = GateResult.from_dict(json.loads(json.dumps(gate.to_dict())))
    assert restored.version == "1.0.0"
    assert restored.commit == "abc"
    assert restored.get("BUILD").status is CheckStatus.PASS


def test_gate_rejects_a_foreign_document() -> None:
    with pytest.raises(StateError):
        GateResult.from_dict({"kind": "something-else"})


def test_gate_rejects_an_unknown_status() -> None:
    with pytest.raises(StateError):
        GateResult.from_dict(
            {
                "kind": "opencode-toolkit/release-gate",
                "schema": 1,
                "checks": {"BUILD": {"name": "BUILD", "status": "MAYBE"}},
            }
        )


# -- sbom and artefacts ----------------------------------------------------


def test_sbom_reports_an_empty_runtime_closure() -> None:
    root = Path(__file__).resolve().parents[2]
    document = sbom_document(root)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["components"] == []
    summary = sbom_summary(root)
    assert summary["runtime_dependencies"] == 0
    assert summary["development_dependencies"] > 0


def test_the_module_entry_point_returns_the_cli_exit_code() -> None:
    """``python -m opencode_toolkit`` must forward ``main()``'s status.

    Without ``sys.exit(main())`` the module always reports success, so a failing
    command would look successful to a shell script, to CI, and to the release
    pipeline that shells out to it.
    """
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [sys.executable, "-m", "opencode_toolkit", "--version"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root / "src")},
    )
    assert completed.returncode == 0
    assert "opencode-toolkit" in completed.stdout


def test_the_module_entry_point_propagates_a_failure() -> None:
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[2]
    # An unknown command exits USAGE (2); a zero here would mean the entry point
    # is swallowing the status.
    completed = subprocess.run(
        [sys.executable, "-m", "opencode_toolkit", "not-a-command"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root / "src")},
    )
    assert completed.returncode == 2


def test_sbom_reads_a_runtime_closure_when_one_exists(tmp_path: Path) -> None:
    """The runtime closure is empty here, so the reader needs its own fixture.

    An empty list is only a meaningful result if the code would populate it when
    there were something to populate.
    """
    from opencode_toolkit.release.sbom import development_components, runtime_components

    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0.1.0"\n'
        'dependencies = ["requests>=2.31", "urllib3"]\n'
        '\n[project.optional-dependencies]\ndev = ["pytest>=8.0"]\n',
        encoding="utf-8",
    )
    runtime = runtime_components(root)
    assert [item["name"] for item in runtime] == ["requests", "urllib3"]
    assert runtime[0]["version"] == "2.31", "the version field carries the pin, not the operator"
    assert "version" not in runtime[1], "an unpinned requirement has no version"
    assert runtime[0]["purl"] == "pkg:pypi/requests"
    assert "properties" not in runtime[0], "a runtime component is not dev-only"

    development = development_components(root)
    assert [item["name"] for item in development] == ["pytest"]
    assert development[0]["properties"] == [{"name": "opencode:scope", "value": "development-only"}]
    assert development[0]["scope"] == "optional"


def test_sbom_skips_a_project_without_a_pyproject(tmp_path: Path) -> None:
    assert sbom_summary(tmp_path)["runtime_dependencies"] == 0


def test_requirement_parsing_keeps_an_unparseable_specifier_whole() -> None:
    from opencode_toolkit.release.sbom import _parse_requirement

    assert _parse_requirement("name>=1.2") == ("name", ">=1.2")
    assert _parse_requirement("  name[extra]>=1 ") == ("name", "[extra]>=1")
    assert _parse_requirement("!!!") == ("!!!", "")


def test_sbom_is_deterministic() -> None:
    project = Path(__file__).resolve().parents[2]
    assert json.dumps(sbom_document(project)) == json.dumps(sbom_document(project))


def test_sbom_serial_number_is_derived_from_content() -> None:
    project = Path(__file__).resolve().parents[2]
    first = sbom_document(project)["serialNumber"]
    assert first.startswith("urn:uuid:")
    assert first == sbom_document(project)["serialNumber"]


def test_artifacts_have_real_checksums(tmp_path: Path) -> None:
    artifacts = build_artifacts(
        Path(__file__).resolve().parents[2],
        tmp_path / "dist",
        skip_python_build=True,
        include_pack=False,
    )
    assert artifacts.artifacts
    from opencode_toolkit.core.fsio import sha256_file

    for artifact in artifacts.artifacts:
        assert artifact.path.is_file()
        assert artifact.sha256 == sha256_file(artifact.path)
        assert artifact.size == artifact.path.stat().st_size


def test_artifact_checksums_file_is_written(tmp_path: Path) -> None:
    build_artifacts(
        Path(__file__).resolve().parents[2],
        tmp_path / "dist",
        skip_python_build=True,
        include_pack=False,
    )
    body = (tmp_path / "dist" / "SHA256SUMS").read_text()
    assert body.count("\n") >= 3


@pytest.mark.regression
def test_sdist_is_reproducible(tmp_path: Path) -> None:
    """Two builds a second apart must produce byte-identical archives.

    The delay matters: a gzip header stamped with the build time would make two
    immediate builds agree and hide the defect this test exists to catch.
    """
    project = Path(__file__).resolve().parents[2]
    first = build_artifacts(project, tmp_path / "a", skip_python_build=True, include_pack=False)
    time.sleep(1.1)
    second = build_artifacts(project, tmp_path / "b", skip_python_build=True, include_pack=False)
    one = next(a for a in first.artifacts if a.kind == "source-archive")
    two = next(a for a in second.artifacts if a.kind == "source-archive")
    assert one.sha256 == two.sha256, "the source archive is not reproducible"


def test_artifact_verification_detects_tampering(tmp_path: Path) -> None:
    from opencode_toolkit.core.fsio import sha256_file
    from opencode_toolkit.release.artifacts import verify_artifacts

    artifacts = build_artifacts(
        Path(__file__).resolve().parents[2],
        tmp_path / "dist",
        skip_python_build=True,
        include_pack=False,
    )
    assert verify_artifacts(artifacts)["ok"]
    target = artifacts.artifacts[0].path
    target.write_bytes(target.read_bytes() + b"\n# tampered\n")
    result = verify_artifacts(artifacts)
    assert not result["ok"]
    assert result["mismatched"]
    del sha256_file


def test_every_repository_changelog_fragment_is_valid() -> None:
    """The release step renders CHANGELOG.md from these, and it must not fail.

    A fragment written by hand instead of `write_fragment` is missing the
    `kind: opencode-toolkit/changelog-fragment` discriminator, and the loader
    rejects it. Six of them did, which 619 green tests did not notice: nothing
    loaded the repository's own fragments, so the release failed at
    "Generate the changelog" after the gate had approved and the artefacts were
    already built.
    """
    from opencode_toolkit.release.changelog import changelog_release, load_fragments

    root = Path(__file__).resolve().parents[2]
    fragments = load_fragments(root)

    assert fragments, "the pending release has recorded fragments"
    for fragment in fragments:
        assert fragment.kind in {"added", "changed", "deprecated", "removed", "fixed", "security"}
        assert fragment.description.strip(), fragment.id
        assert fragment.area.strip(), fragment.id

    # And the rendering the release step performs must actually work.
    rendered = changelog_release(fragments, "9.9.9")
    assert "## 9.9.9" in rendered
