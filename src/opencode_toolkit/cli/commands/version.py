"""``opencode version`` -- version reporting across every source."""

from __future__ import annotations

import argparse
import platform
import sys
from typing import Any

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.version import __version__, detect_version


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "version",
        help="show the toolkit, runtime and component versions",
        description=(
            "Report the version from every source it can be read from, and flag any "
            "disagreement rather than picking one silently."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when the declared and imported versions disagree",
    )
    parser.set_defaults(handler=run_version)


def run_version(context: CliContext, args: argparse.Namespace) -> int:
    """Execute ``opencode version``.

    Args:
        context: CliContext: Workspace, layout, config and output streams to
            report through.
        args: argparse.Namespace: Parsed ``version`` options, including the
            ``check`` flag.
    """
    try:
        declared = str(detect_version(context.workspace))
        source = str(context.workspace / "pyproject.toml")
    except Exception as exc:
        declared, source = "unknown", str(exc)

    payload: dict[str, Any] = {
        "toolkit": {
            "imported": __version__,
            "declared": declared,
            "declared_source": source,
            "in_sync": declared == __version__,
        },
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "executable": sys.executable,
        },
        "components": [
            "security-audit",
            "workflow-sync",
            "snippet-verified",
            "orchestrator",
            "offline-pack",
            "live-docs",
        ],
    }

    if context.output_format == JSON:
        emit_json(payload, context.stdout)
    else:
        print(f"opencode-toolkit {__version__}", file=context.stdout)
        print(f"  declared   {declared} ({source})", file=context.stdout)
        if declared != __version__:
            print(
                "  WARNING    declared and imported versions differ; reinstall with `pip install -e .`",
                file=context.stdout,
            )
        print(
            f"  runtime    {payload['runtime']['implementation']} "
            f"{payload['runtime']['python']} on {payload['runtime']['system']} "
            f"{payload['runtime']['machine']}",
            file=context.stdout,
        )
        print("\n  components (each evolves independently)", file=context.stdout)
        for name in payload["components"]:
            print(f"    - {name}", file=context.stdout)

    if args.check and not payload["toolkit"]["in_sync"]:
        return exit_codes.FAILURE
    return exit_codes.OK
