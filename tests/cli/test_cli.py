"""CLI tests: commands, arguments, output shape and exit codes.

The CLI is invoked in-process through :func:`main`, so a failure surfaces with
the real traceback rather than a subprocess exit code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.paths import resolve_state_dir
from opencode_toolkit.release.gate import CHECK_NAMES

pytestmark = pytest.mark.cli


# -- global behaviour ------------------------------------------------------


def test_no_command_prints_help_and_fails(cli_invoke) -> None:
    result = cli_invoke()
    assert result.code == exit_codes.USAGE
    assert "usage: opencode" in result.err


def test_help_exits_zero(cli_invoke) -> None:
    result = cli_invoke("--help")
    assert result.code == 0
    assert "security-audit" in result.out


def test_unknown_command_is_a_usage_error(cli_invoke) -> None:
    result = cli_invoke("teleport")
    assert result.code == exit_codes.USAGE


def test_version_flag(cli_invoke) -> None:
    result = cli_invoke("--version")
    assert result.code == 0
    assert "opencode-toolkit" in result.out


def test_version_command_text_and_json(cli_invoke) -> None:
    text = cli_invoke("version")
    assert text.code == 0
    assert "components" in text.out

    payload = cli_invoke("--format", "json", "version").json()
    assert payload["toolkit"]["imported"]
    assert len(payload["components"]) == 6


def test_version_check_detects_parity(cli_invoke) -> None:
    assert cli_invoke("version", "--check").code == exit_codes.FAILURE


def test_unknown_global_option_is_rejected(cli_invoke) -> None:
    assert cli_invoke("--not-an-option").code == exit_codes.USAGE


# -- security-audit --------------------------------------------------------


@pytest.fixture
def vulnerable_tree(tmp_path: Path) -> Path:
    root = tmp_path / "vuln"
    root.mkdir()
    (root / "bad.py").write_text(
        'import os\nPASSWORD = "hunter2secret"\ndef run(c):\n    return os.system(c)\n',
        encoding="utf-8",
    )
    (root / "ok.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def test_audit_text_output_and_exit_code(cli_invoke, vulnerable_tree: Path) -> None:
    result = cli_invoke("security-audit", str(vulnerable_tree))
    assert result.code == exit_codes.FAILURE
    assert "OCSA-CRED-001" in result.out
    assert "OCSA-EXEC-004" in result.out
    assert "hunter2secret" not in result.out, "the secret value must never be printed"


def test_audit_json_output(cli_invoke, vulnerable_tree: Path) -> None:
    result = cli_invoke("--format", "json", "security-audit", str(vulnerable_tree))
    payload = result.json()
    assert payload["summary"]["findings"] >= 2
    assert payload["summary"]["files_scanned"] == 2
    assert {item["rule_id"] for item in payload["findings"]} >= {"OCSA-CRED-001", "OCSA-EXEC-004"}


def test_audit_json_flag_after_the_subcommand(cli_invoke, vulnerable_tree: Path) -> None:
    """The documented invocation puts global options last; it must work."""
    result = cli_invoke("security-audit", str(vulnerable_tree), "--format", "json")
    assert result.code == exit_codes.FAILURE
    payload = result.json()
    assert payload["summary"]["findings"] >= 2


def test_audit_sarif_output(cli_invoke, vulnerable_tree: Path) -> None:
    result = cli_invoke("--format", "sarif", "security-audit", str(vulnerable_tree))
    payload = json.loads(result.out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "opencode-security-audit"
    assert payload["runs"][0]["results"]


def test_audit_clean_tree_exits_zero(cli_invoke, tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.py").write_text("VALUE = 1\n", encoding="utf-8")
    result = cli_invoke("security-audit", str(clean))
    assert result.code == exit_codes.OK
    assert "No findings." in result.out


def test_audit_strict_raises_the_threshold(cli_invoke, tmp_path: Path) -> None:
    tree = tmp_path / "low"
    tree.mkdir()
    (tree / "m.py").write_text("assert is_valid(x)\n", encoding="utf-8")
    assert cli_invoke("security-audit", str(tree)).code == exit_codes.OK
    assert cli_invoke("security-audit", str(tree), "--strict").code == exit_codes.FAILURE


def test_audit_fail_on_overrides_the_threshold(cli_invoke, vulnerable_tree: Path) -> None:
    result = cli_invoke("security-audit", str(vulnerable_tree), "--fail-on", "informational")
    assert result.code == exit_codes.FAILURE


def test_audit_ignore_suppresses_a_rule(cli_invoke, vulnerable_tree: Path) -> None:
    result = cli_invoke(
        "security-audit",
        str(vulnerable_tree),
        "--ignore",
        "OCSA-CRED-001",
        "--ignore",
        "OCSA-EXEC-004",
    )
    assert result.code == exit_codes.OK


def test_audit_rule_filter_runs_only_the_named_rules(cli_invoke, vulnerable_tree: Path) -> None:
    payload = cli_invoke(
        "--format", "json", "security-audit", str(vulnerable_tree), "--rule", "OCSA-CRED-001"
    ).json()
    assert {item["rule_id"] for item in payload["findings"]} == {"OCSA-CRED-001"}


def test_audit_min_severity_filters_the_report(cli_invoke, vulnerable_tree: Path) -> None:
    payload = cli_invoke(
        "--format", "json", "security-audit", str(vulnerable_tree), "--min-severity", "critical"
    ).json()
    assert all(item["severity"] == "critical" for item in payload["findings"])


def test_audit_missing_path_is_a_usage_error(cli_invoke, tmp_path: Path) -> None:
    result = cli_invoke("security-audit", str(tmp_path / "nope"))
    assert result.code == exit_codes.USAGE
    assert "does not exist" in result.err


def test_audit_include_and_exclude_filters(cli_invoke, tmp_path: Path) -> None:
    tree = tmp_path / "many"
    (tree / "keep").mkdir(parents=True)
    (tree / "skip").mkdir(parents=True)
    (tree / "keep" / "a.py").write_text('TOKEN = "abcdefgh1234"\n', encoding="utf-8")
    (tree / "skip" / "b.py").write_text('TOKEN = "abcdefgh1234"\n', encoding="utf-8")
    payload = cli_invoke(
        "--format", "json", "security-audit", str(tree), "--include", "keep/*"
    ).json()
    assert {item["file"] for item in payload["findings"]} == {"keep/a.py"}


def test_audit_list_rules_emits_the_catalogue(cli_invoke) -> None:
    payload = cli_invoke("security-audit", "--list-rules").json()
    assert len(payload) > 30
    assert {item["rule_id"] for item in payload} >= {"OCSA-CRED-001", "OCSA-EXEC-001"}


def test_audit_invalid_severity_is_rejected(cli_invoke) -> None:
    assert cli_invoke("security-audit", "--fail-on", "apocalyptic").code == exit_codes.USAGE


# -- snippet ---------------------------------------------------------------


def test_snippet_list(cli_invoke) -> None:
    result = cli_invoke("snippet", "list")
    assert result.code == 0
    assert "python-password-hashing-argon2" in result.out


def test_snippet_list_filters(cli_invoke) -> None:
    payload = cli_invoke("--format", "json", "snippet", "list", "--language", "go").json()
    assert payload["snippets"]
    assert all(item["language"] == "go" for item in payload["snippets"])


def test_snippet_list_markdown(cli_invoke) -> None:
    result = cli_invoke("snippet", "list", "--markdown")
    assert "| id | language | status | version | summary |" in result.out


def test_snippet_search(cli_invoke) -> None:
    result = cli_invoke("snippet", "search", "password")
    assert result.code == 0
    assert "python-password-hashing-argon2" in result.out


def test_snippet_search_no_match_exits_one(cli_invoke) -> None:
    assert cli_invoke("snippet", "search", "zzzznotasnippet").code == exit_codes.FAILURE


def test_snippet_inspect(cli_invoke) -> None:
    result = cli_invoke("snippet", "inspect", "python-password-hashing-argon2")
    assert "Security notes" in result.out
    assert "Edge cases handled" in result.out
    assert "Maintenance" in result.out


def test_snippet_inspect_unknown_id(cli_invoke) -> None:
    result = cli_invoke("snippet", "inspect", "no-such-snippet")
    assert result.code == exit_codes.FAILURE
    assert "suggestions" in result.err or "snippet list" in result.err


def test_snippet_add_and_conflict(cli_invoke, tmp_path: Path) -> None:
    target = tmp_path / "generated.py"
    first = cli_invoke("snippet", "add", "python-constant-time-compare", str(target))
    assert first.code == 0
    assert "opencode-verified-snippet" in target.read_text()

    second = cli_invoke("snippet", "add", "python-constant-time-compare", str(target))
    assert second.code == exit_codes.CONFLICT
    assert "opencode-verified-snippet" in target.read_text(), "the file must be untouched"


def test_snippet_add_force(cli_invoke, tmp_path: Path) -> None:
    target = tmp_path / "generated.py"
    target.write_text("# mine\n", encoding="utf-8")
    assert (
        cli_invoke("snippet", "add", "python-constant-time-compare", str(target), "--force").code
        == 0
    )
    assert "opencode-verified-snippet" in target.read_text()


def test_snippet_add_dry_run_writes_nothing(cli_invoke, tmp_path: Path) -> None:
    target = tmp_path / "generated.py"
    assert (
        cli_invoke("snippet", "add", "python-constant-time-compare", str(target), "--dry-run").code
        == 0
    )
    assert not target.exists()


def test_snippet_verify(cli_invoke, tmp_path: Path) -> None:
    target = tmp_path / "generated.py"
    cli_invoke("snippet", "add", "python-constant-time-compare", str(target))
    assert cli_invoke("snippet", "verify", "python-constant-time-compare", str(target)).code == 0
    target.write_text("nothing to see\n", encoding="utf-8")
    assert cli_invoke("snippet", "verify", "python-constant-time-compare", str(target)).code == 1


def test_snippet_requires_a_subcommand(cli_invoke) -> None:
    assert cli_invoke("snippet").code == exit_codes.USAGE


# -- doctor ----------------------------------------------------------------


def test_doctor_text(cli_invoke) -> None:
    result = cli_invoke("doctor")
    assert result.code in {exit_codes.OK, exit_codes.FAILURE}
    assert "python.version" in result.out
    assert "RESULT:" in result.out


def test_doctor_json_is_machine_readable(cli_invoke) -> None:
    payload = cli_invoke("--format", "json", "doctor").json()
    assert payload["summary"]["total"] > 5
    names = {check["name"] for check in payload["checks"]}
    assert {
        "python.version",
        "workspace.layout",
        "state.writable",
        "component.security-audit",
        "component.snippets",
        "component.sync-crypto",
        "git.repository",
        "credentials.huggingface",
        "credentials.kaggle",
    } <= names


def test_doctor_reports_missing_credentials_as_skipped(cli_invoke) -> None:
    payload = cli_invoke("--format", "json", "doctor").json()
    credentials = {
        check["name"]: check for check in payload["checks"] if check["category"] == "credentials"
    }
    assert credentials["credentials.huggingface"]["status"] == "SKIP"
    assert "HUGGINGFACE_TOKEN" in credentials["credentials.huggingface"]["detail"]


def test_doctor_reports_an_invalid_configuration(cli_invoke, workspace: Path) -> None:
    config = workspace / ".opencode" / "toolkit" / "config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        json.dumps({"config_version": 1, "security_audit": {"max_file_bytes": "big"}}),
        encoding="utf-8",
    )
    result = cli_invoke("--format", "json", "doctor")
    assert result.code == exit_codes.CONFIG
    payload = json.loads(result.out)
    problems = payload["details"]["problems"]
    assert any("max_file_bytes" in problem for problem in problems)


def test_doctor_json_error_shape(cli_invoke, workspace: Path) -> None:
    config = workspace / ".opencode" / "toolkit" / "config.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"config_version": 1, "typo_key": 1}), encoding="utf-8")
    result = cli_invoke("--format", "json", "doctor")
    assert result.code == exit_codes.CONFIG
    payload = result.json()
    assert payload["status"] == "error"
    assert payload["error"] == "config.invalid"
    assert payload["exit_code"] == exit_codes.CONFIG


# -- pack ------------------------------------------------------------------


def test_pack_build_verify_inspect(cli_invoke, tmp_path: Path, workspace: Path) -> None:
    (workspace / "src" / "opencode_toolkit").mkdir(exist_ok=True)
    (workspace / "src" / "opencode_toolkit" / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (workspace / "README.md").write_text("# mini\n", encoding="utf-8")
    archive = tmp_path / "pack.zip"

    built = cli_invoke("pack", "build", "--output", str(archive))
    assert built.code == 0, built.err
    assert archive.is_file()

    verified = cli_invoke("pack", "verify", str(archive))
    assert verified.code == 0
    assert "VERIFIED" in verified.out

    inspected = cli_invoke("--format", "json", "pack", "inspect", str(archive)).json()
    assert inspected["version"] == "9.9.9"
    assert inspected["licenses"][0]["spdx"] == "Apache-2.0"


def test_pack_verify_detects_tampering(cli_invoke, tmp_path: Path, workspace: Path) -> None:
    import zipfile

    (workspace / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (workspace / "README.md").write_text("# mini\n", encoding="utf-8")
    archive = tmp_path / "pack.zip"
    cli_invoke("pack", "build", "--output", str(archive))

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(tampered, "w") as sink:
        for name in source.namelist():
            data = source.read(name)
            if name.endswith(".md"):
                data = b"tampered\n"
            sink.writestr(name, data)
    result = cli_invoke("pack", "verify", str(tampered))
    assert result.code == exit_codes.INTEGRITY
    assert "FAILED" in result.out


def test_pack_verify_missing_archive(cli_invoke, tmp_path: Path) -> None:
    result = cli_invoke("pack", "verify", str(tmp_path / "absent.zip"))
    assert result.code == exit_codes.USAGE
    assert "not found" in result.err


def test_pack_dry_run(cli_invoke, workspace: Path) -> None:
    result = cli_invoke("pack", "build", "--dry-run")
    assert result.code == 0
    assert "dry run" in result.out
    assert not (workspace / "dist").exists()


def test_pack_unknown_component(cli_invoke) -> None:
    assert cli_invoke("pack", "build", "--component", "nope").code == exit_codes.USAGE


def test_pack_licenses(cli_invoke) -> None:
    payload = cli_invoke("--format", "json", "pack", "licenses").json()
    assert payload["runtime_dependencies"] == 0
    assert all(entry["reference"] for entry in payload["policy"])


def test_pack_requires_a_subcommand(cli_invoke) -> None:
    assert cli_invoke("pack").code == exit_codes.USAGE


# -- docs ------------------------------------------------------------------


def test_docs_scan_and_check(cli_invoke, workspace: Path) -> None:
    (workspace / "src" / "opencode_toolkit").mkdir(exist_ok=True)
    (workspace / "src" / "opencode_toolkit" / "m.py").write_text(
        'def handler(request):\n    """Handle a request.\n\n    Args:\n        request: the request.\n    """\n    return request\n',
        encoding="utf-8",
    )
    scanned = cli_invoke("--format", "json", "docs", "scan", "--path", str(workspace / "src"))
    assert scanned.code == 0
    payload = scanned.json()
    assert payload["counts"]["function"] == 1

    baseline = workspace / "baseline.json"
    written = cli_invoke(
        "--format",
        "json",
        "docs",
        "scan",
        "--path",
        str(workspace / "src"),
        "--baseline",
        str(baseline),
        "--write-baseline",
    )
    assert written.code == 0
    assert baseline.is_file()

    checked = cli_invoke(
        "docs", "check", "--path", str(workspace / "src"), "--baseline", str(baseline)
    )
    assert checked.code == exit_codes.OK
    assert "No drift" in checked.out


def test_docs_check_fails_on_drift(cli_invoke, workspace: Path) -> None:
    source = workspace / "src" / "opencode_toolkit" / "m.py"
    source.write_text(
        'def handler(request):\n    """Handle a request.\n\n    Args:\n        request: the request.\n    """\n    return request\n',
        encoding="utf-8",
    )
    baseline = workspace / "baseline.json"
    cli_invoke(
        "docs",
        "scan",
        "--path",
        str(workspace / "src"),
        "--baseline",
        str(baseline),
        "--write-baseline",
    )
    source.write_text(
        'def handler(request, retries=3):\n    """Handle a request.\n\n    Args:\n        request: the request.\n    """\n    return request\n',
        encoding="utf-8",
    )
    result = cli_invoke(
        "docs", "check", "--path", str(workspace / "src"), "--baseline", str(baseline)
    )
    assert result.code == exit_codes.FAILURE


def test_docs_update_check_mode(cli_invoke, workspace: Path) -> None:
    source = workspace / "src" / "opencode_toolkit" / "m.py"
    original = (
        "def handler(request, retries=3):\n"
        '    """Handle a request.\n\n'
        "    Prose that must survive.\n\n"
        "    Args:\n        request: the request.\n\n"
        "    Returns:\n        The response.\n"
        '    """\n    return request\n'
    )
    source.write_text(original, encoding="utf-8")
    result = cli_invoke("docs", "update", "--path", str(workspace / "src"), "--check")
    assert result.code == 0
    assert source.read_text() == original, "--check must not write"
    payload = json.loads(result.out) if result.out.strip().startswith("{") else None
    assert payload is None or payload["applied"] is False


def test_docs_update_writes_only_owned_sections(cli_invoke, workspace: Path) -> None:
    source = workspace / "src" / "opencode_toolkit" / "m.py"
    source.write_text(
        "def handler(request, retries=3):\n"
        '    """Handle a request.\n\n'
        "    Prose that must survive.\n\n"
        "    Args:\n        request: the request.\n\n"
        "    Returns:\n        The response.\n"
        '    """\n    return request\n',
        encoding="utf-8",
    )
    result = cli_invoke("docs", "update", "--path", str(workspace / "src"))
    assert result.code == 0
    after = source.read_text()
    assert "retries" in after
    assert "Prose that must survive." in after
    assert "Returns:\n        The response." in after


def test_docs_diff(cli_invoke, workspace: Path) -> None:
    source = workspace / "src" / "opencode_toolkit" / "m.py"
    source.write_text(
        'def handler(request, retries=3):\n    """H.\n\n    Args:\n        request: r.\n    """\n    return request\n',
        encoding="utf-8",
    )
    result = cli_invoke("docs", "diff", "--path", str(workspace / "src"))
    assert result.code == 0
    assert "--- a/" in result.out or "No docstring changes" in result.out


def test_docs_requires_a_subcommand(cli_invoke) -> None:
    assert cli_invoke("docs").code == exit_codes.USAGE


# -- orchestrator ----------------------------------------------------------


def test_orchestrator_plan_example_is_valid(cli_invoke, workspace: Path) -> None:
    plan_file = workspace / "plan.json"
    result = cli_invoke("orchestrator", "plan-example", "--output", str(plan_file))
    assert result.code == 0
    document = json.loads(plan_file.read_text())
    assert document["kind"] == "opencode-toolkit/plan"
    assert len(document["tasks"]) == 5

    from opencode_toolkit.orchestrator.graph import DependencyGraph
    from opencode_toolkit.orchestrator.models import Plan

    graph = DependencyGraph.build(Plan.from_dict(document).tasks)
    assert graph.depth >= 3


def test_orchestrator_run_and_status(cli_invoke, workspace: Path) -> None:
    plan_file = workspace / "plan.json"
    cli_invoke("orchestrator", "plan-example", "--output", str(plan_file))
    result = cli_invoke("orchestrator", "run", "--plan", str(plan_file), "--executor", "null")
    assert result.code == 0
    assert "completed  5" in result.out

    status = cli_invoke("--format", "json", "orchestrator", "status").json()
    assert status["checkpoint_count"] >= 1
    assert status["journal_records"] >= 1

    tasks = cli_invoke("--format", "json", "orchestrator", "tasks").json()
    assert tasks["count"] == 5


def test_orchestrator_reports_a_failing_run(cli_invoke, workspace: Path) -> None:
    plan_file = workspace / "plan.json"
    written = cli_invoke("orchestrator", "plan-example", "--output", str(plan_file))
    assert written.code == 0, written.err
    plan = json.loads(plan_file.read_text())
    plan["tasks"] = [
        {
            "id": "boom",
            "title": "Fail",
            "role": "tester",
            "command": [sys.executable, "-c", "raise SystemExit(2)"],
        }
    ]
    plan_file.write_text(json.dumps(plan), encoding="utf-8")
    result = cli_invoke("orchestrator", "run", "--plan", str(plan_file), "--executor", "command")
    assert result.code == exit_codes.FAILURE
    assert "outcome    FAILED" in result.out


def test_orchestrator_dry_run_validates_without_executing(cli_invoke, workspace: Path) -> None:
    plan_file = workspace / "plan.json"
    cli_invoke("orchestrator", "plan-example", "--output", str(plan_file))
    result = cli_invoke(
        "orchestrator", "run", "--plan", str(plan_file), "--dry-run", "--executor", "command"
    )
    assert result.code == 0
    assert "level 0: plan" in result.out


def test_orchestrator_rejects_a_malformed_plan(cli_invoke, workspace: Path) -> None:
    plan_file = workspace / "bad.json"
    plan_file.write_text("{not json", encoding="utf-8")
    result = cli_invoke("orchestrator", "run", "--plan", str(plan_file))
    assert result.code == exit_codes.USAGE
    assert "cannot load plan" in result.err


def test_orchestrator_missing_plan(cli_invoke, workspace: Path) -> None:
    assert cli_invoke("orchestrator", "run", "--plan", "absent.json").code == exit_codes.USAGE


def test_orchestrator_roles(cli_invoke) -> None:
    payload = cli_invoke("--format", "json", "orchestrator", "roles").json()
    assert set(payload) == {
        "planner",
        "code_author",
        "tester",
        "documentation_maintainer",
        "security_reviewer",
    }


def test_orchestrator_checkpoint_and_resume(cli_invoke, workspace: Path) -> None:
    plan_file = workspace / "plan.json"
    cli_invoke("orchestrator", "plan-example", "--output", str(plan_file))
    cli_invoke("orchestrator", "run", "--plan", str(plan_file), "--executor", "null")

    listing = cli_invoke("--format", "json", "orchestrator", "checkpoint").json()
    assert listing["count"] >= 1

    saved = cli_invoke("orchestrator", "checkpoint", "--save")
    assert saved.code == 0

    resumed = cli_invoke("orchestrator", "resume", "--executor", "null")
    assert resumed.code == 0
    assert "resumed run" in resumed.out


def test_orchestrator_resume_without_a_checkpoint(cli_invoke) -> None:
    result = cli_invoke("orchestrator", "resume")
    assert result.code == exit_codes.USAGE


def test_orchestrator_requires_a_subcommand(cli_invoke) -> None:
    assert cli_invoke("orchestrator").code == exit_codes.USAGE


# -- sync ------------------------------------------------------------------


def _prepare_tree(workspace: Path) -> None:
    (workspace / "docs").mkdir(exist_ok=True)
    (workspace / "docs" / "a.md").write_text("original", encoding="utf-8")
    (workspace / "docs" / "b.md").write_text("untouched", encoding="utf-8")


def test_sync_save_list_status(
    cli_invoke, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYNC_PW", "a-test-passphrase")
    _prepare_tree(workspace)

    saved = cli_invoke(
        "--format",
        "json",
        "sync",
        "save",
        "--tag",
        "t1",
        "--track",
        "docs",
        "--passphrase-env",
        "SYNC_PW",
    )
    assert saved.code == 0, saved.err
    assert saved.json()["encrypted"] is True

    listing = cli_invoke("--format", "json", "sync", "list").json()
    assert listing["snapshots"][0]["tag"] == "t1"

    status = cli_invoke("--format", "json", "sync", "status").json()
    assert status["snapshot_count"] == 1
    assert status["queued_operations"] == 0
    assert status["encryption_available"] is True


def test_sync_save_without_a_passphrase_is_refused(cli_invoke, workspace: Path) -> None:
    _prepare_tree(workspace)
    result = cli_invoke("sync", "save", "--tag", "t1", "--track", "docs")
    assert result.code == exit_codes.IO_ERROR
    assert "passphrase" in result.err


def test_sync_save_with_no_encryption(cli_invoke, workspace: Path) -> None:
    _prepare_tree(workspace)
    result = cli_invoke(
        "--format", "json", "sync", "save", "--tag", "t1", "--track", "docs", "--no-encrypt"
    )
    assert result.code == 0
    assert result.json()["encrypted"] is False


def test_sync_restore_conflict_exits_with_the_conflict_code(
    cli_invoke, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYNC_PW", "a-test-passphrase")
    _prepare_tree(workspace)
    cli_invoke("sync", "save", "--tag", "base", "--track", "docs", "--passphrase-env", "SYNC_PW")
    (workspace / "docs" / "a.md").write_text("local edit", encoding="utf-8")
    cli_invoke("sync", "save", "--tag", "head", "--track", "docs", "--passphrase-env", "SYNC_PW")
    # A *third* edit, after the head snapshot: this is what makes the three-way
    # comparison see both sides move away from the base.
    (workspace / "docs" / "a.md").write_text("second local edit", encoding="utf-8")

    result = cli_invoke(
        "--format",
        "json",
        "sync",
        "restore",
        "base",
        "--base",
        "head",
        "--passphrase-env",
        "SYNC_PW",
    )
    assert result.code == exit_codes.CONFLICT
    payload = result.json()
    assert payload["conflicts"]["summary"]["conflicts"] == ["docs/a.md"]
    assert (workspace / "docs" / "a.md").read_text() == "second local edit"


def test_sync_restore_force(cli_invoke, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYNC_PW", "a-test-passphrase")
    _prepare_tree(workspace)
    cli_invoke("sync", "save", "--tag", "base", "--track", "docs", "--passphrase-env", "SYNC_PW")
    (workspace / "docs" / "a.md").write_text("local edit", encoding="utf-8")
    cli_invoke("sync", "save", "--tag", "head", "--track", "docs", "--passphrase-env", "SYNC_PW")
    (workspace / "docs" / "a.md").write_text("second local edit", encoding="utf-8")
    result = cli_invoke(
        "sync", "restore", "base", "--base", "head", "--passphrase-env", "SYNC_PW", "--force"
    )
    assert result.code == 0, "a forced restore that applied must not still exit CONFLICT"
    assert (workspace / "docs" / "a.md").read_text() == "original"


def test_sync_restore_of_an_unknown_tag(cli_invoke, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYNC_PW", "a-test-passphrase")
    result = cli_invoke("sync", "restore", "nope", "--passphrase-env", "SYNC_PW")
    assert result.code == exit_codes.FAILURE
    assert "sync list" in result.err


def test_sync_conflict_command(
    cli_invoke, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYNC_PW", "a-test-passphrase")
    _prepare_tree(workspace)
    cli_invoke("sync", "save", "--tag", "base", "--track", "docs", "--passphrase-env", "SYNC_PW")
    (workspace / "docs" / "a.md").write_text("local edit", encoding="utf-8")
    cli_invoke("sync", "save", "--tag", "head", "--track", "docs", "--passphrase-env", "SYNC_PW")
    (workspace / "docs" / "a.md").write_text("second local edit", encoding="utf-8")
    result = cli_invoke(
        "--format",
        "json",
        "sync",
        "conflict",
        "base",
        "--base",
        "head",
        "--passphrase-env",
        "SYNC_PW",
    )
    assert result.code == exit_codes.CONFLICT
    assert result.json()["summary"]["conflict_count"] == 1


def test_sync_push_and_pull(
    cli_invoke, workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYNC_PW", "a-test-passphrase")
    _prepare_tree(workspace)
    cli_invoke("sync", "save", "--tag", "t1", "--track", "docs", "--passphrase-env", "SYNC_PW")
    remote = tmp_path / "remote"

    # Push reads the sealed manifest to learn which blobs must travel, so it
    # needs the same passphrase the save did.
    pushed = cli_invoke(
        "sync", "push", "t1", "--remote", str(remote), "--passphrase-env", "SYNC_PW"
    )
    assert pushed.code == 0
    assert "transferred" in pushed.out

    again = cli_invoke("sync", "pull", "t1", "--remote", str(remote), "--passphrase-env", "SYNC_PW")
    assert again.code == 0


@pytest.mark.regression
def test_sync_push_requires_the_passphrase_for_an_encrypted_snapshot(
    cli_invoke, workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: push sent the document but not the blobs it references.

    A snapshot document is a manifest of content digests, so copying only the
    document produced a remote that existed but could not be restored from. The
    transport now reads the manifest, which means an encrypted snapshot needs
    the passphrase at push time as well as at save time.
    """
    monkeypatch.setenv("SYNC_PW", "a-test-passphrase")
    _prepare_tree(workspace)
    cli_invoke("sync", "save", "--tag", "t1", "--track", "docs", "--passphrase-env", "SYNC_PW")
    remote = tmp_path / "remote"

    refused = cli_invoke("sync", "push", "t1", "--remote", str(remote))
    assert refused.code != 0
    assert "passphrase" in refused.err.lower()

    cli_invoke("sync", "push", "t1", "--remote", str(remote), "--passphrase-env", "SYNC_PW")
    assert list((remote / "blobs").iterdir()), "the referenced blobs must travel too"


@pytest.mark.regression
def test_sync_push_carries_blobs_so_a_second_store_can_restore(
    cli_invoke, workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYNC_PW", "a-test-passphrase")
    _prepare_tree(workspace)
    cli_invoke("sync", "save", "--tag", "t1", "--track", "docs", "--passphrase-env", "SYNC_PW")
    remote = tmp_path / "remote"
    cli_invoke("sync", "push", "t1", "--remote", str(remote), "--passphrase-env", "SYNC_PW")

    pulled = cli_invoke(
        "sync", "pull", "t1", "--remote", str(remote), "--passphrase-env", "SYNC_PW"
    )
    assert pulled.code == 0
    restored = cli_invoke("sync", "restore", "t1", "--passphrase-env", "SYNC_PW", "--force")
    assert restored.code == 0, restored.err


def test_sync_push_creates_the_remote_directory(
    cli_invoke, tmp_path: Path, workspace: Path
) -> None:
    _prepare_tree(workspace)
    cli_invoke("sync", "save", "--tag", "t1", "--track", "docs", "--no-encrypt")
    remote = tmp_path / "created-by-push"
    result = cli_invoke("sync", "push", "t1", "--remote", str(remote))
    assert remote.is_dir(), "push is allowed to create the destination"
    assert result.code == 0, result.err


def test_sync_pull_from_a_missing_remote_is_a_usage_error(cli_invoke, tmp_path: Path) -> None:
    result = cli_invoke("sync", "pull", "t1", "--remote", str(tmp_path / "absent"))
    assert result.code == exit_codes.USAGE
    assert "does not exist" in result.err


def test_sync_requires_a_subcommand(cli_invoke) -> None:
    assert cli_invoke("sync").code == exit_codes.USAGE


def test_sync_dry_run_writes_nothing(cli_invoke, workspace: Path) -> None:
    _prepare_tree(workspace)
    result = cli_invoke(
        "sync", "save", "--tag", "t1", "--track", "docs", "--no-encrypt", "--dry-run"
    )
    assert result.code == 0
    assert "dry run" in result.out + result.err
    assert cli_invoke("--format", "json", "sync", "list").json()["count"] == 0


# -- release ---------------------------------------------------------------


@pytest.mark.regression
def test_release_gate_is_not_written_to_a_nested_state_path(cli_invoke, workspace: Path) -> None:
    """Regression: the gate landed in ``.opencode/toolkit/.opencode/toolkit/``.

    ``layout.state_dir`` already resolves to ``<workspace>/.opencode/toolkit``,
    so joining ``.opencode/toolkit/release-gate.json`` onto it nested the path
    twice and the gate the pipeline wrote was not the gate the CLI read.
    """
    (workspace / ".opencode").mkdir()
    cli_invoke("--format", "json", "release", "gate", "--init")
    # Resolved the same way the CLI resolves it, so the assertion follows the
    # implementation rather than duplicating the path arithmetic.
    state = resolve_state_dir(workspace)[0]
    assert (state / "release-gate.json").is_file()
    assert not (state / ".opencode").exists()


def test_release_gate_init_and_report(cli_invoke, workspace: Path) -> None:
    inited = cli_invoke("--format", "json", "release", "gate", "--init").json()
    assert inited["decision"] == "BLOCKED"
    assert inited["checks"]["BUILD"]["status"] == "NOT_RUN"
    assert len(inited["required_checks"]) == len(CHECK_NAMES)

    shown = cli_invoke("release", "gate")
    assert "DECISION: BLOCKED" in shown.out
    assert "REASON:" in shown.out


def test_release_gate_record_and_preflight(cli_invoke) -> None:
    cli_invoke("release", "gate", "--init")
    for name in (
        "BUILD",
        "FORMAT",
        "LINT",
        "TYPECHECK",
        "UNIT_TEST",
        "INTEGRATION_TEST",
        "CLI_TEST",
        "SECURITY",
        "DEPENDENCY_AUDIT",
        "SECRET_SCAN",
        "DOCUMENTATION",
        "PACKAGE",
        "REPRODUCIBILITY",
    ):
        cli_invoke("release", "gate", "--set", f"{name}=PASS:recorded by a test")

    preflight = cli_invoke("--format", "json", "release", "preflight")
    assert preflight.code == 0
    payload = preflight.json()
    assert payload["permitted"] is True


def test_release_gate_preflight_without_a_gate(cli_invoke) -> None:
    result = cli_invoke("release", "preflight")
    assert result.code == exit_codes.CONFIG
    assert "quality-check" in result.err


def test_release_gate_rejects_an_unknown_check(cli_invoke) -> None:
    result = cli_invoke("release", "gate", "--set", "NOT_A_CHECK=PASS:x")
    assert result.code == exit_codes.USAGE
    assert "unknown check" in result.err


def test_release_gate_rejects_an_unknown_status(cli_invoke) -> None:
    result = cli_invoke("release", "gate", "--set", "BUILD=MAYBE")
    assert result.code == exit_codes.USAGE


def test_release_gate_rejects_a_malformed_assignment(cli_invoke) -> None:
    assert cli_invoke("release", "gate", "--set", "BUILD").code == exit_codes.USAGE


def test_release_bump_dry_run(cli_invoke, workspace: Path) -> None:
    before = (workspace / "pyproject.toml").read_text()
    result = cli_invoke("release", "bump", "minor", "--dry-run")
    assert result.code == 0
    assert "9.9.9 -> 9.10.0" in result.out
    assert (workspace / "pyproject.toml").read_text() == before


def test_release_bump_writes_and_is_verifiable(cli_invoke, workspace: Path) -> None:
    result = cli_invoke("release", "bump", "patch")
    assert result.code == 0
    assert "9.9.9 -> 9.9.10" in result.out
    # The imported version is still the one baked in at install time, so the
    # parity check correctly reports a mismatch until the package is reinstalled.
    parity = cli_invoke("version", "--check")
    assert parity.code == exit_codes.FAILURE
    assert "differ" in parity.out or "reinstall" in parity.out


def test_release_sbom(cli_invoke) -> None:
    summary = cli_invoke("--format", "json", "release", "sbom", "--summary").json()
    assert summary["runtime_dependencies"] == 0
    full = cli_invoke("--format", "json", "release", "sbom").json()
    assert full["bomFormat"] == "CycloneDX"
    assert full["specVersion"] == "1.5"
    assert full["serialNumber"].startswith("urn:uuid:")


def test_release_fragment_and_changelog(cli_invoke) -> None:
    fragment = cli_invoke("release", "fragment", "fixed", "Fix the thing.", "--area", "sync")
    assert fragment.code == 0
    assert any((Path(fragment.out.split("  ")[-1].strip())).exists() for _ in [0])

    rendered = cli_invoke("release", "changelog")
    assert rendered.code == 0
    assert (Path(fragment.out.splitlines()[-1].strip())).is_file()


def test_release_artifacts_and_verify(cli_invoke, workspace: Path) -> None:
    (workspace / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (workspace / "README.md").write_text("# mini\n", encoding="utf-8")
    output = workspace / "dist"
    built = cli_invoke(
        "--format", "json", "release", "artifacts", "--output", str(output), "--no-wheel"
    )
    assert built.code == 0, built.err
    payload = built.json()
    assert payload["verification"]["ok"] is True
    assert payload["artifact_count"] >= 3

    verified = cli_invoke(
        "--format", "json", "release", "verify-artifacts", "--output", str(output)
    )
    assert verified.code == 0
    assert verified.json()["ok"] is True


def test_release_verify_artifacts_detects_tampering(cli_invoke, workspace: Path) -> None:
    (workspace / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    (workspace / "README.md").write_text("# mini\n", encoding="utf-8")
    output = workspace / "dist"
    cli_invoke("release", "artifacts", "--output", str(output), "--no-wheel")
    (output / "sbom.cdx.json").write_text("{}\n", encoding="utf-8")
    result = cli_invoke("release", "verify-artifacts", "--output", str(output))
    assert result.code == exit_codes.INTEGRITY


def test_release_requires_a_subcommand(cli_invoke) -> None:
    assert cli_invoke("release").code == exit_codes.USAGE


# -- publish ---------------------------------------------------------------


def test_publish_classify(cli_invoke) -> None:
    payload = cli_invoke("--format", "json", "publish", "classify").json()
    assert payload["project_kind"] == "code-repository"
    assert payload["huggingface"]["applicable"] is False
    assert payload["kaggle"]["applicable"] is True
    assert payload["rationale"]


def test_publish_huggingface_is_blocked_as_not_applicable(cli_invoke) -> None:
    result = cli_invoke("--format", "json", "publish", "huggingface", "--namespace", "someone")
    assert result.code == exit_codes.CONFLICT
    payload = result.json()
    assert payload["status"] == "BLOCKED"
    assert payload["missing_configuration"]


def test_publish_requires_a_gate_before_anything_else(
    cli_invoke, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With credentials present but no gate, the gate is what stops the upload."""
    monkeypatch.setenv("HUGGINGFACE_TOKEN", "hf_fake_token_for_testing_only")
    monkeypatch.setenv("KAGGLE_USERNAME", "someone")
    monkeypatch.setenv("KAGGLE_KEY", "kaggle-fake-key")
    result = cli_invoke("publish", "kaggle")
    assert result.code == exit_codes.CONFIG
    assert "quality-check" in result.err


def test_publish_requires_a_platform(cli_invoke) -> None:
    assert cli_invoke("publish").code == exit_codes.USAGE


def test_publish_kaggle_skips_without_credentials(
    cli_invoke, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KAGGLE_USERNAME", "someone")
    monkeypatch.setenv("KAGGLE_KEY", "kaggle-fake-key")
    result = cli_invoke("publish", "kaggle", "--dry-run")
    assert result.code in {exit_codes.OK, exit_codes.CONFIG}


def test_publish_verify_without_credentials_skips(cli_invoke) -> None:
    result = cli_invoke("--format", "json", "publish", "verify", "--platform", "kaggle")
    assert result.code == exit_codes.OK
    payload = result.json()
    assert payload["status"] == "SKIPPED"
    assert payload["missing_configuration"]


def test_publish_huggingface_verify_requires_a_namespace(
    cli_invoke, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUGGINGFACE_TOKEN", "hf_fake_token_for_testing_only")
    assert cli_invoke("publish", "verify", "--platform", "huggingface").code == exit_codes.USAGE


# -- test command ----------------------------------------------------------


def test_test_command_builds_the_right_pytest_argv(cli_invoke) -> None:
    from opencode_toolkit.cli.commands.testing import build_pytest_argv

    class Args:
        suite = "security"
        coverage = False
        verbose = False
        failfast = False
        expression = None
        path = None

    argv = build_pytest_argv("security", Args())
    assert argv[-2:] == ["-m", "security"]

    Args.suite = "unit"
    Args.coverage = True
    argv = build_pytest_argv("unit", Args())
    assert "--cov=opencode_toolkit" in argv
    assert argv[argv.index("-m", 2) : argv.index("-m", 2) + 2] == ["-m", "unit"]


def test_test_command_dry_run(cli_invoke) -> None:
    result = cli_invoke("test", "unit", "--dry-run")
    assert result.code == 0
    assert "pytest" in result.out
    assert "-m unit" in result.out


def test_test_command_rejects_an_unknown_suite(cli_invoke) -> None:
    assert cli_invoke("test", "nonsense").code == exit_codes.USAGE


def test_orchestrator_example_plan_uses_the_running_interpreter(
    cli_invoke, workspace: Path
) -> None:
    """The generated plan must run on the machine that generated it.

    The example shipped a literal `python3`, which is not on PATH on Windows, so
    a user who ran it there got "command not found" for every task. `python3` is
    also the wrong interpreter on any machine where it points somewhere else.
    """
    plan_file = workspace / "plan.json"
    assert cli_invoke("orchestrator", "plan-example", "--output", str(plan_file)).code == 0
    document = json.loads(plan_file.read_text())

    with_commands = [task for task in document["tasks"] if task.get("command")]
    assert with_commands, "the example plan is supposed to contain runnable tasks"
    for task in with_commands:
        assert task["command"][0] == sys.executable, task["id"]
