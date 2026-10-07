"""``opencode test`` -- run the project's own test suite.

A convenience wrapper, not a second test framework: it shells out to ``pytest``
with the project's own configuration so what a developer runs and what CI runs
are the same thing. When ``pytest`` is absent the command says so precisely
instead of silently passing.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from typing import Any

from opencode_toolkit.cli.context import CliContext
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.errors import UsageError

#: Marker expression per named suite, matching tests/conftest.py.
SUITES: dict[str, str] = {
    "all": "",
    "unit": "unit",
    "integration": "integration",
    "cli": "cli",
    "security": "security",
    "regression": "regression",
}


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "test",
        help="run the project's test suites",
        description=(
            "Run pytest with the repository's own configuration. Named suites map to pytest "
            "markers, so `opencode test security` runs exactly what CI runs for that stage."
        ),
    )
    parser.add_argument(
        "suite",
        nargs="?",
        default="all",
        choices=sorted(SUITES),
        help="suite to run (default: all)",
    )
    parser.add_argument("--coverage", action="store_true", help="collect coverage")
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose pytest output")
    parser.add_argument("--failfast", "-x", action="store_true", help="stop at the first failure")
    parser.add_argument("--path", default=None, metavar="PATH", help="restrict to a path")
    parser.add_argument(
        "-k", dest="expression", default=None, metavar="EXPR", help="pytest -k expression"
    )
    parser.set_defaults(handler=run_test)


def build_pytest_argv(suite: str, args: argparse.Namespace) -> list[str]:
    """Return the exact pytest argument vector for a request.

    Args:
        suite: str: Suite name mapped to a pytest marker expression.
        args: argparse.Namespace: Parsed options supplying ``coverage``,
            ``verbose``, ``failfast``, ``expression`` and ``path``.
    """
    argv = [sys.executable, "-m", "pytest"]
    marker = SUITES.get(suite, "")
    if marker:
        argv.extend(["-m", marker])
    if args.coverage:
        argv.extend(["--cov=opencode_toolkit", "--cov-report=term-missing"])
    if args.verbose:
        argv.append("-vv")
    if args.failfast:
        argv.append("-x")
    if args.expression:
        argv.extend(["-k", args.expression])
    if args.path:
        argv.append(str(args.path))
    return argv


def run_test(context: CliContext, args: argparse.Namespace) -> int:
    """Execute ``opencode test``.

    Args:
        context: CliContext: Workspace, dry-run flag and streams the pytest run
            is launched from.
        args: argparse.Namespace: Parsed ``test`` options, including the suite
            name and pytest flags.
    """
    pytest_module = shutil.which("pytest") or _module_available("pytest")
    if pytest_module is None:
        raise UsageError(
            "pytest is not installed",
            code="test.pytest_missing",
            details={"required": "pytest>=8"},
            hint="install the development extra: pip install -e '.[dev]'",
        )

    argv = build_pytest_argv(args.suite, args)
    if context.dry_run:
        print(f"dry run: {' '.join(argv)}", file=context.stdout)
        return exit_codes.OK

    context.note(f"running: {' '.join(argv)}")
    completed = subprocess.run(  # noqa: S603 - argv list, no shell
        argv,
        cwd=str(context.workspace),
        check=False,
    )
    return completed.returncode


def _module_available(name: str) -> str | None:
    import importlib.util

    return name if importlib.util.find_spec(name) is not None else None


def suite_report(results: dict[str, Any]) -> dict[str, Any]:
    """Format a suite result map for JSON output (used by CI).

    Args:
        results: dict[str, Any]: Mapping of suite name to its result payload.
    """
    return {"suites": results}
