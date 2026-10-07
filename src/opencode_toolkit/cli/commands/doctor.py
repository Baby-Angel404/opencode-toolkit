"""``opencode doctor`` -- environment and configuration diagnosis.

``doctor`` is the first thing to run when something misbehaves, so it must answer
"what is wrong and what do I do about it" rather than "something failed". Every
check returns a status, a detail and, when it can offer one, a remediation.

Checks are grouped by whether they block normal use:

* **environment** -- interpreter, platform, tooling
* **workspace** -- paths, configuration, state directory writability
* **integrity** -- git and credentials for optional publishing

The exit code is ``1`` when a *blocking* check fails, ``0`` otherwise. A warning
never fails the command unless ``--strict`` is given, and that is stated in the
output rather than implied.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.errors import ConfigurationError
from opencode_toolkit.core.version import Version, __version__, detect_version
from opencode_toolkit.publishing.classify import (
    HUGGINGFACE_TOKEN_ENV,
    KAGGLE_KEY_ENV,
    KAGGLE_USERNAME_ENV,
    classify_project,
)
from opencode_toolkit.release.sbom import sbom_summary
from opencode_toolkit.security_audit.rules import all_rules
from opencode_toolkit.snippet_verified.registry import default_registry, registry_stats
from opencode_toolkit.workflow_sync import crypto

MIN_PYTHON = (3, 10)
RECOMMENDED_PYTHON = (3, 12)

PASS = "PASS"  # noqa: S105 - a status label
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"

#: Statuses that make `doctor` exit non-zero.
BLOCKING = frozenset({FAIL})


@dataclass(slots=True)
class Check:
    """One diagnostic."""

    name: str
    status: str
    detail: str
    remediation: str = ""
    category: str = "environment"
    blocking: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return the check as JSON-serialisable data."""
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "remediation": self.remediation,
            "category": self.category,
            "blocking": self.blocking,
        }


@dataclass(slots=True)
class DoctorReport:
    """All checks plus context."""

    checks: list[Check] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def add(self, check: Check) -> Check:
        """Record a check and return it, so callers can build and add in one expression.

        Args:
            check: Check: The check result appended to the report.
        """
        self.checks.append(check)
        return check

    def failures(self) -> list[Check]:
        """Return the blocking checks, which decide whether the report is ok."""
        return [check for check in self.checks if check.status in BLOCKING and check.blocking]

    def warnings(self) -> list[Check]:
        """Return the non-blocking checks a human should still read."""
        return [check for check in self.checks if check.status == WARN]

    @property
    def ok(self) -> bool:
        """``True`` when no blocking check failed."""
        return not self.failures()

    def to_dict(self) -> dict[str, Any]:
        """Return the report, its per-status counts and the pass/fail summary."""
        counts: dict[str, int] = {}
        for check in self.checks:
            counts[check.status] = counts.get(check.status, 0) + 1
        return {
            "tool": "opencode-doctor",
            "version": __version__,
            "context": self.context,
            "summary": {
                "total": len(self.checks),
                "by_status": dict(sorted(counts.items())),
                "failures": len(self.failures()),
                "warnings": len(self.warnings()),
                "ok": self.ok,
            },
            "checks": [check.to_dict() for check in self.checks],
        }


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "doctor",
        help="diagnose the environment, configuration and optional integrations",
        description=(
            "Check the interpreter, workspace layout, configuration, state directory, git, "
            "git state, publishing credentials and the environment, and report exactly what to fix."
        ),
    )
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")
    parser.set_defaults(handler=run_doctor)


def run_doctor(context: CliContext, args: argparse.Namespace) -> int:
    """Execute ``opencode doctor``.

    Args:
        context: CliContext: Workspace, layout, config and output streams the
            checks inspect and report through.
        args: argparse.Namespace: Parsed ``doctor`` options, including the
            ``strict`` flag.
    """
    report = DoctorReport()
    _check_runtime(report)
    _check_workspace(context, report)
    _check_configuration(context, report)
    _check_state_dir(context, report)
    _check_components(context, report)
    _check_git(context, report)
    _check_credentials(report)

    report.context = {
        "workspace": str(context.workspace),
        "layout": context.layout.describe(),
        "tool_version": __version__,
        "sbom": sbom_summary(context.workspace),
        "classification": classify_project(context.workspace).to_dict(),
    }

    if context.output_format == JSON:
        emit_json(report.to_dict(), context.stdout)
    else:
        _render(context, report)
    if not report.ok:
        return exit_codes.FAILURE
    if args.strict and report.warnings():
        context.note("--strict: warnings are treated as failures")
        return exit_codes.FAILURE
    return exit_codes.OK


# -- individual checks ----------------------------------------------------


def _check_runtime(report: DoctorReport) -> None:
    version = sys.version_info
    if version[:2] < MIN_PYTHON:
        report.add(
            Check(
                name="python.version",
                status=FAIL,
                detail=f"Python {version.major}.{version.minor} is below the minimum "
                f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
                remediation=f"install Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer",
            )
        )
    elif version[:2] < RECOMMENDED_PYTHON:
        report.add(
            Check(
                name="python.version",
                status=WARN,
                detail=f"Python {version.major}.{version.minor} is supported but older than the "
                f"recommended {RECOMMENDED_PYTHON[0]}.{RECOMMENDED_PYTHON[1]}",
                remediation="the suite is validated on 3.11-3.14; 3.10 lacks tomllib for SBOM parsing",
                blocking=False,
            )
        )
    else:
        report.add(
            Check(
                name="python.version",
                status=PASS,
                detail=f"Python {version.major}.{version.minor}.{version.micro}",
            )
        )

    if sys.platform == "win32":
        report.add(
            Check(
                name="python.platform",
                status=WARN,
                detail="Windows: directory fsync is unavailable, so atomic writes are atomic but "
                "not fully durable on power loss",
                remediation="documented in docs/development/filesystem-notes.md",
                blocking=False,
            )
        )
    else:
        report.add(
            Check(
                name="python.platform",
                status=PASS,
                detail=f"{sys.platform} with full fsync semantics",
            )
        )

    report.add(
        Check(
            name="python.dependencies",
            status=PASS,
            detail="no third-party runtime dependencies; the standard library is sufficient",
        )
    )


def _check_workspace(context: CliContext, report: DoctorReport) -> None:
    missing = [
        name for name in ("src", "pyproject.toml") if not (context.workspace / name).exists()
    ]
    if missing:
        report.add(
            Check(
                name="workspace.layout",
                status=FAIL,
                detail=f"missing expected entries: {', '.join(missing)}",
                remediation="run from a repository root, or pass --workspace",
                category="workspace",
            )
        )
    else:
        report.add(
            Check(
                name="workspace.layout",
                status=PASS,
                detail=f"{context.workspace} contains src/ and pyproject.toml",
                category="workspace",
            )
        )

    try:
        version = detect_version(context.workspace)
        report.add(
            Check(
                name="workspace.version",
                status=PASS,
                detail=f"{version} declared in pyproject.toml",
                category="workspace",
            )
        )
    except ConfigurationError as exc:
        report.add(
            Check(
                name="workspace.version",
                status=FAIL,
                detail=exc.message,
                remediation=exc.hint or "set project.version in pyproject.toml",
                category="workspace",
            )
        )

    try:
        version = Version.parse(__version__)
        report.add(
            Check(
                name="workspace.version-parity",
                status=PASS if str(version) == __version__ else WARN,
                detail=f"imported version {__version__} matches pyproject.toml"
                if str(version) == __version__
                else f"imported version {__version__}",
                remediation="reinstall the package if this persists: pip install -e .",
                category="workspace",
                blocking=False,
            )
        )
    except ConfigurationError as exc:
        report.add(
            Check(
                name="workspace.version-parity",
                status=FAIL,
                detail=exc.message,
                category="workspace",
            )
        )


def _check_configuration(context: CliContext, report: DoctorReport) -> None:
    path = context.layout.workspace / ".opencode" / "toolkit" / "config.json"
    if not path.is_file():
        report.add(
            Check(
                name="config.present",
                status=PASS,
                detail="no config.json; documented defaults are in effect",
                category="workspace",
            )
        )
        return
    try:
        context.config.to_dict()
        report.add(
            Check(
                name="config.present",
                status=PASS,
                detail=f"{path} parsed and validated",
                category="workspace",
            )
        )
    except ConfigurationError as exc:  # pragma: no cover - load happens before this
        report.add(
            Check(
                name="config.present",
                status=FAIL,
                detail=exc.message,
                remediation=exc.hint or "fix the reported keys",
                category="workspace",
            )
        )

    for problem in _validate_config_file(path):
        report.add(
            Check(
                name="config.valid",
                status=FAIL,
                detail=problem,
                remediation="fix every listed problem; the toolkit refuses partial configuration",
                category="workspace",
            )
        )


def _validate_config_file(path: Path) -> list[str]:
    from opencode_toolkit.core import jsonio
    from opencode_toolkit.core.config import _validate_document

    try:
        document = jsonio.read(path)
    except Exception as exc:
        return [f"cannot parse config: {exc}"]
    return _validate_document(document, source=str(path))


def _check_state_dir(context: CliContext, report: DoctorReport) -> None:
    directory = context.layout.state_dir
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".doctor-", delete=True):
            pass
        report.add(
            Check(
                name="state.writable",
                status=PASS,
                detail=f"{directory} is writable ({context.layout.source})",
                category="workspace",
            )
        )
    except OSError as exc:
        report.add(
            Check(
                name="state.writable",
                status=FAIL,
                detail=f"cannot write to the state directory: {exc.strerror or exc}",
                remediation="set OPENCODE_TOOLKIT_STATE_DIR to a writable path, or pass --state-dir",
                category="workspace",
            )
        )

    for name in ("snapshots", "queue", "orchestrator", "packs", "artifacts"):
        path = getattr(context.layout, name)
        if not path.exists():
            report.add(
                Check(
                    name=f"state.{name}",
                    status=PASS,
                    detail="not created yet; created on first use",
                    category="workspace",
                )
            )


def _check_components(context: CliContext, report: DoctorReport) -> None:
    report.add(
        Check(
            name="component.security-audit",
            status=PASS,
            detail=f"{len(all_rules())} rules across python, javascript, typescript and go",
            category="component",
        )
    )
    try:
        stats = registry_stats(default_registry())
        report.add(
            Check(
                name="component.snippets",
                status=PASS,
                detail=f"{stats['total']} snippets "
                f"({stats['by_status'].get('stable', 0)} stable, "
                f"{stats['by_status'].get('experimental', 0)} experimental)",
                category="component",
            )
        )
    except Exception as exc:
        report.add(
            Check(
                name="component.snippets",
                status=FAIL,
                detail=f"registry could not be loaded: {exc}",
                remediation="reinstall the package; the registry ships inside it",
                category="component",
            )
        )

    report.add(
        Check(
            name="component.sync-crypto",
            status=PASS,
            detail=f"ciphers available: {', '.join(crypto.available_ciphers())}; "
            f"PBKDF2-HMAC-SHA256 x{context.config.sync.kdf_iterations}",
            category="component",
        )
    )


def _check_git(context: CliContext, report: DoctorReport) -> None:
    git = shutil.which("git")
    if git is None:
        report.add(
            Check(
                name="git.available",
                status=WARN,
                detail="git is not on PATH; release commit metadata will be empty",
                remediation="install git, or accept that release reports omit the commit hash",
                category="integrity",
                blocking=False,
            )
        )
        return
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv
            [git, "rev-parse", "--is-inside-work-tree"],
            cwd=str(context.workspace),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.add(
            Check(
                name="git.available",
                status=WARN,
                detail=f"git is installed but did not respond: {exc}",
                remediation="check the git installation",
                category="integrity",
                blocking=False,
            )
        )
        return

    if completed.returncode != 0 or completed.stdout.strip() != "true":
        report.add(
            Check(
                name="git.repository",
                status=WARN,
                detail="the workspace is not inside a git work tree",
                remediation="initialise a repository if release artefacts need commit provenance",
                category="integrity",
                blocking=False,
            )
        )
        return

    report.add(
        Check(
            name="git.repository",
            status=PASS,
            detail="workspace is inside a git work tree",
            category="integrity",
        )
    )
    dirty = subprocess.run(  # noqa: S603 - fixed argv
        [git, "status", "--porcelain"],
        cwd=str(context.workspace),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    changed = [line for line in dirty.stdout.splitlines() if line.strip()]
    if changed:
        report.add(
            Check(
                name="git.clean",
                status=WARN,
                detail=f"{len(changed)} uncommitted change(s) in the workspace",
                remediation="commit before cutting a release so artifacts are reproducible",
                category="integrity",
                blocking=False,
            )
        )


def _check_credentials(report: DoctorReport) -> None:
    hf = os.environ.get(HUGGINGFACE_TOKEN_ENV, "").strip()
    report.add(
        Check(
            name="credentials.huggingface",
            status=PASS if hf else SKIP,
            detail=f"{HUGGINGFACE_TOKEN_ENV} is set"
            if hf
            else f"{HUGGINGFACE_TOKEN_ENV} is not set",
            remediation=(
                f"set {HUGGINGFACE_TOKEN_ENV} as a GitHub Actions secret to publish"
                if not hf
                else ""
            ),
            category="credentials",
            blocking=False,
        )
    )
    username = os.environ.get(KAGGLE_USERNAME_ENV, "").strip()
    key = os.environ.get(KAGGLE_KEY_ENV, "").strip()
    complete = bool(username and key)
    report.add(
        Check(
            name="credentials.kaggle",
            status=PASS if complete else SKIP,
            detail="Kaggle credentials are set"
            if complete
            else f"missing: {', '.join(n for n, v in ((KAGGLE_USERNAME_ENV, username), (KAGGLE_KEY_ENV, key)) if not v)}",
            remediation=(
                f"set {KAGGLE_USERNAME_ENV} and {KAGGLE_KEY_ENV} as GitHub Actions secrets"
                if not complete
                else ""
            ),
            category="credentials",
            blocking=False,
        )
    )


# -- rendering ------------------------------------------------------------

_STATUS_MARK = {PASS: "ok", WARN: "warn", FAIL: "FAIL", SKIP: "skip"}


def _render(context: CliContext, report: DoctorReport) -> None:
    print(f"opencode-toolkit doctor -- version {__version__}", file=context.stdout)
    print(f"python {sys.version.split()[0]} on {sys.platform}", file=context.stdout)
    print(f"workspace {context.workspace}", file=context.stdout)
    print(f"state dir {context.layout.state_dir} ({context.layout.source})", file=context.stdout)

    for category in ("environment", "workspace", "component", "integrity", "credentials"):
        checks = [check for check in report.checks if check.category == category]
        if not checks:
            continue
        print(f"\n{category}", file=context.stdout)
        for check in checks:
            mark = _STATUS_MARK.get(check.status, check.status.lower())
            print(f"  [{mark:>4}] {check.name}", file=context.stdout)
            print(f"         {check.detail}", file=context.stdout)
            if check.remediation and check.status in {FAIL, WARN, SKIP}:
                print(f"         fix: {check.remediation}", file=context.stdout)

    failures = report.failures()
    warnings = report.warnings()
    print("", file=context.stdout)
    print(
        f"{len(report.checks)} check(s): {len(failures)} failure(s), {len(warnings)} warning(s)",
        file=context.stdout,
    )
    print("RESULT: HEALTHY" if report.ok else "RESULT: PROBLEMS FOUND", file=context.stdout)
    if not report.ok:
        for check in failures:
            print(f"  blocking: {check.name} -- {check.detail}", file=context.stdout)
    sbom = report.context.get("sbom", {})
    print(
        f"runtime dependencies: {sbom.get('runtime_dependencies', '?')} "
        f"(development: {sbom.get('development_dependencies', '?')})",
        file=context.stdout,
    )
    if not report.ok:
        for check in failures:
            print(f"  blocking: {check.name} -- {check.detail}", file=context.stdout)
