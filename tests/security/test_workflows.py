"""Workflow files must survive GitHub's job-graph validation.

GitHub parses every workflow and resolves the job graph *before* it runs a
single step. A structural mistake there produces ``startup_failure``: zero jobs,
no step output, and a conclusion that says nothing about the cause. Two such
bugs shipped in this repository and each one was only visible on a real runner,
after a push.
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

import pytest

pytestmark = pytest.mark.security

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CHECKER = REPO_ROOT / "scripts" / "security" / "workflow-permissions.py"


def _load_checker():
    """Import the checker by path; scripts/ is not an importable package."""
    spec = importlib.util.spec_from_file_location("workflow_permissions", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.regression
def test_reusable_workflow_calls_grant_what_they_request() -> None:
    """`release.yml` pinned `contents: read` and called `security.yml`.

    The nested `audit` and `codeql` jobs request `security-events: write`, which
    the caller never granted. Every tag push produced a release with zero jobs,
    so the gate, the artefacts and the release notes all silently stopped
    existing while the repository looked healthy.
    """
    problems = _load_checker().analyse(WORKFLOWS)
    assert not problems, "\n".join(problems)


@pytest.mark.regression
def test_checker_reports_a_permission_shortfall(tmp_path: pathlib.Path) -> None:
    """The checker must fail on the shape it exists to catch."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "callee.yml").write_text(
        "on:\n  workflow_call:\n"
        "permissions:\n  contents: read\n"
        "jobs:\n"
        "  scan:\n"
        "    permissions:\n      security-events: write\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hi\n",
        encoding="utf-8",
    )
    (workflows / "caller.yml").write_text(
        "on: push\npermissions:\n  contents: read\njobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n",
        encoding="utf-8",
    )
    problems = _load_checker().analyse(workflows)
    assert len(problems) == 1, problems
    assert "security-events" in problems[0]


@pytest.mark.regression
def test_checker_accepts_a_sufficient_grant(tmp_path: pathlib.Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "callee.yml").write_text(
        "on:\n  workflow_call:\n"
        "permissions:\n  contents: read\n"
        "jobs:\n"
        "  scan:\n"
        "    permissions:\n      security-events: write\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hi\n",
        encoding="utf-8",
    )
    (workflows / "caller.yml").write_text(
        "on: push\npermissions:\n  contents: read\n"
        "jobs:\n"
        "  call:\n"
        "    permissions:\n      contents: read\n      security-events: write\n"
        "    uses: ./.github/workflows/callee.yml\n",
        encoding="utf-8",
    )
    assert _load_checker().analyse(workflows) == []


@pytest.mark.regression
def test_checker_exits_non_zero_from_the_command_line(tmp_path: pathlib.Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "caller.yml").write_text(
        "on: push\npermissions:\n  contents: read\n"
        "jobs:\n  call:\n    uses: ./.github/workflows/absent.yml\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, str(CHECKER), "--workflows", str(workflows)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "missing workflow" in completed.stdout


def _write_neighbour_workflow(directory: pathlib.Path, *, opt_in: bool) -> None:
    """A gate, an explain-only-on-failure job, and a release that expects it skipped."""
    directory.mkdir(parents=True, exist_ok=True)
    opt = "always() && " if opt_in else ""
    (directory / "release.yml").write_text(
        "on: push\npermissions:\n  contents: read\n"
        "jobs:\n"
        "  gate:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo gate\n"
        "  explain-blocked:\n"
        "    runs-on: ubuntu-latest\n"
        "    needs: [gate]\n"
        "    if: always() && needs.gate.result != 'success'\n"
        "    steps:\n      - run: echo blocked\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    needs: [gate, explain-blocked]\n"
        f"    if: {opt}needs.gate.outputs.approved == 'true' "
        "&& needs.explain-blocked.result == 'skipped'\n"
        "    steps:\n      - run: echo release\n",
        encoding="utf-8",
    )


@pytest.mark.regression
def test_checker_flags_a_condition_that_can_never_hold(tmp_path: pathlib.Path) -> None:
    """The gate approved, the run went green, and no release was ever cut.

    `explain-blocked` only runs when the gate refuses, so on success it is
    skipped -- and `release` required exactly that. Without `always()` GitHub
    skips `release` the moment `explain-blocked` is skipped, so the condition
    could never be true. The repository shipped with zero releases and nothing
    to indicate why.
    """
    workflows = tmp_path / ".github" / "workflows"
    _write_neighbour_workflow(workflows, opt_in=False)

    problems = _load_checker().analyse(workflows)
    assert len(problems) == 1, problems
    assert "'release'" in problems[0] and "explain-blocked" in problems[0]


@pytest.mark.regression
def test_checker_accepts_an_opted_in_condition(tmp_path: pathlib.Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    _write_neighbour_workflow(workflows, opt_in=True)

    assert _load_checker().analyse(workflows) == []


@pytest.mark.regression
def test_checker_leaves_ordinary_conditional_dependencies_alone(tmp_path: pathlib.Path) -> None:
    """A job that should not run because a need was skipped is correct as written.

    Only a condition that asserts a need *was* skipped is a contradiction; the
    publish jobs gate on `result == 'success'` and must stay untouched.
    """
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "publish.yml").write_text(
        "on: push\npermissions:\n  contents: read\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    if: startsWith(github.ref, 'refs/tags/v')\n"
        "    steps:\n      - run: echo release\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        "    needs: [release]\n"
        "    if: needs.release.result == 'success'\n"
        "    steps:\n      - run: echo publish\n",
        encoding="utf-8",
    )

    assert _load_checker().analyse(workflows) == []
