"""The ``opencode`` argument parser and dispatcher."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO, cast

from opencode_toolkit.cli import commands
from opencode_toolkit.cli.context import (
    FORMATS,
    JSON,
    TEXT,
    CliContext,
    configure_logging,
    render_error,
)
from opencode_toolkit.core import exit_codes, logging
from opencode_toolkit.core.config import Config, load_config
from opencode_toolkit.core.errors import ToolkitError
from opencode_toolkit.core.paths import Layout, resolve_layout, resolve_workspace
from opencode_toolkit.core.version import __version__

#: Command name to handler. Every name here appears in ``--help``.
HANDLERS: dict[str, Callable[[CliContext, argparse.Namespace], int]] = {
    "security-audit": commands.security.run_audit,
    "sync": commands.sync.run_sync,
    "snippet": commands.snippet.run_snippet,
    "orchestrator": commands.orchestrator.run_orchestrator,
    "pack": commands.pack.run_pack,
    "docs": commands.docs.run_docs,
    "doctor": commands.doctor.run_doctor,
    "version": commands.version.run_version,
    "test": commands.testing.run_test,
    "release": commands.release.run_release,
    "publish": commands.publish.run_publish,
}

EPILOG = """\
examples:
  opencode security-audit . --strict
  opencode security-audit ./src --format sarif > results.sarif
  opencode sync save --tag nightly --passphrase-env SYNC_PASSPHRASE
  opencode snippet search "constant time"
  opencode pack build --output dist/opencode-toolkit.tar.zip
  opencode docs check --baseline .opencode/toolkit/docs/baseline.json
  opencode release gate --json
  opencode doctor --format json

exit codes:
  0 ok            1 failure          2 usage           3 config
  4 io            5 conflict         6 integrity       7 network
"""


#: The global options are declared on the top-level parser *and* injected into
#: every leaf subparser, so `opencode --format json doctor` and
#: `opencode doctor --format json` behave identically. The injected copies use
#: ``SUPPRESS`` defaults so that omitting the option after the subcommand does not
#: overwrite a value given before it.
_GLOBAL_DEFAULTS = {
    "output_format": "text",
    "workspace": None,
    "state_dir": None,
    "log_level": None,
    "quiet": False,
    "verbose": False,
    "dry_run": False,
}


def _add_global_options(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    group = parser.add_argument_group("global options")
    group.add_argument(
        "--format",
        dest="output_format",
        choices=FORMATS,
        default=argparse.SUPPRESS if suppress else TEXT,
        help="output format (default: text)",
    )
    group.add_argument(
        "--workspace",
        metavar="PATH",
        default=argparse.SUPPRESS if suppress else None,
        help="workspace root to operate on (default: nearest ancestor with pyproject.toml or .git)",
    )
    group.add_argument(
        "--state-dir",
        metavar="PATH",
        default=argparse.SUPPRESS if suppress else None,
        help="override the state directory (default: $OPENCODE_TOOLKIT_STATE_DIR or <workspace>/.opencode/toolkit)",
    )
    group.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default=argparse.SUPPRESS if suppress else None,
        help="diagnostic verbosity on stderr (default: warning)",
    )
    group.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="suppress non-essential stderr output",
    )
    group.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="include extra detail in reports",
    )
    group.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="report what would happen without changing files",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the complete parser."""
    parser = argparse.ArgumentParser(
        prog="opencode",
        description=(
            "Unified OpenCode engineering toolkit: security auditing, encrypted workflow "
            "sync, verified snippets, multi-agent orchestration, offline packages, and "
            "documentation drift detection."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"opencode-toolkit {__version__} (Python {sys.version.split()[0]})",
    )
    _add_global_options(parser)

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    commands.security.register(subparsers)
    commands.sync.register(subparsers)
    commands.snippet.register(subparsers)
    commands.orchestrator.register(subparsers)
    commands.pack.register(subparsers)
    commands.docs.register(subparsers)
    commands.doctor.register(subparsers)
    commands.version.register(subparsers)
    commands.testing.register(subparsers)
    commands.release.register(subparsers)
    commands.publish.register(subparsers)

    _inject_global_options(parser)
    return parser


#: Declarative form of the global options, used to inject them into leaves.
_GLOBAL_OPTION_SPECS: tuple[tuple[tuple[str, ...], dict[str, object]], ...] = (
    (
        ("--format",),
        {
            "dest": "output_format",
            "choices": FORMATS,
            "default": argparse.SUPPRESS,
            "help": "output format (default: text)",
        },
    ),
    (
        ("--workspace",),
        {"metavar": "PATH", "default": argparse.SUPPRESS, "help": "workspace root to operate on"},
    ),
    (
        ("--state-dir",),
        {"metavar": "PATH", "default": argparse.SUPPRESS, "help": "override the state directory"},
    ),
    (
        ("--log-level",),
        {
            "choices": ["debug", "info", "warning", "error", "critical"],
            "default": argparse.SUPPRESS,
            "help": "diagnostic verbosity on stderr",
        },
    ),
    (
        ("--quiet", "-q"),
        {
            "action": "store_true",
            "default": argparse.SUPPRESS,
            "help": "suppress non-essential stderr output",
        },
    ),
    (
        ("--verbose", "-v"),
        {
            "action": "store_true",
            "default": argparse.SUPPRESS,
            "help": "include extra detail in reports",
        },
    ),
    (
        ("--dry-run",),
        {
            "action": "store_true",
            "default": argparse.SUPPRESS,
            "help": "report what would happen without changing files",
        },
    ),
)


def _leaf_parsers(parser: argparse.ArgumentParser) -> list[argparse.ArgumentParser]:
    """Return every parser reachable through nested subparsers."""
    leaves: list[argparse.ArgumentParser] = []
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for child in action.choices.values():
            if _has_subparsers(child):
                leaves.extend(_leaf_parsers(child))
            else:
                leaves.append(child)
    return leaves


def _has_subparsers(parser: argparse.ArgumentParser) -> bool:
    return any(isinstance(action, argparse._SubParsersAction) for action in parser._actions)


def _inject_global_options(parser: argparse.ArgumentParser) -> None:
    """Add the global options to every leaf subparser.

    This makes the documented invocation `opencode security-audit . --format
    json` work, which argparse would otherwise reject because it only accepts
    global options before the subcommand. A subcommand that already declares an
    option of the same name keeps its own; the conflict is skipped rather than
    raising.
    """
    for leaf in _leaf_parsers(parser):
        declared = _declared_options(leaf)
        for flags, kwargs in _GLOBAL_OPTION_SPECS:
            if declared & set(flags):
                continue
            # argparse's stubs type every keyword as its own concrete type, so a
            # spec table holding them together needs an explicit escape hatch.
            cast(Any, leaf).add_argument(*flags, **kwargs)


def _declared_options(parser: argparse.ArgumentParser) -> set[str]:
    """Return every option string *parser* already declares."""
    return {option for action in parser._actions for option in action.option_strings}


def _context_from_args(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> CliContext:
    for name, fallback in _GLOBAL_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, fallback)
    level = args.log_level or logging.level_from_env()
    configure_logging(level)
    workspace = resolve_workspace(args.workspace)
    layout = resolve_layout(workspace=workspace, state_dir=args.state_dir)
    config = load_config(layout)
    return CliContext(
        workspace=layout.workspace,
        layout=layout,
        config=config,
        output_format=args.output_format,
        quiet=bool(args.quiet),
        verbose=bool(args.verbose),
        dry_run=bool(args.dry_run),
        stdout=stdout,
        stderr=stderr,
    )


def _peek_output_format(argv: Sequence[str]) -> str:
    """Recover the requested output format without building a context.

    A configuration error is raised while the context is being constructed --
    before there is a context whose ``output_format`` could be read. Peeking at
    argv means ``--format json`` still produces machine-readable output for
    exactly the failures a script most needs to parse.
    """
    tokens = list(argv)
    for index, argument in enumerate(tokens):
        if argument == "--format" and index + 1 < len(tokens):
            candidate = tokens[index + 1]
            return candidate if candidate in FORMATS else TEXT
        if argument.startswith("--format="):
            candidate = argument.split("=", 1)[1]
            return candidate if candidate in FORMATS else TEXT
    return TEXT


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI and return a process exit code.

    Args:
        argv: Sequence[str] | None: Argument tokens to parse, defaulting to
            ``sys.argv[1:]``.
        stdout: TextIO | None: Stream commands write results to, defaulting to
            ``sys.stdout``.
        stderr: TextIO | None: Stream diagnostics and usage errors go to,
            defaulting to ``sys.stderr``.

    Returns:
        int: The process exit code for the invoked command.
    """
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = build_parser()
    tokens = list(argv) if argv is not None else sys.argv[1:]
    early_format = _peek_output_format(tokens)

    try:
        args = parser.parse_args(tokens)
    except SystemExit as exc:
        # argparse exits 0 for --help/--version and 2 for a bad command line.
        code = exc.code if isinstance(exc.code, int) else exit_codes.USAGE
        return int(code)

    if not args.command:
        parser.print_help(file=err)
        print("\nerror: no command given", file=err)
        return exit_codes.USAGE

    handler = HANDLERS.get(args.command)
    if handler is None:  # pragma: no cover - argparse rejects unknown commands first
        print(f"error: unknown command {args.command!r}", file=err)
        return exit_codes.USAGE

    context: CliContext | None = None
    try:
        context = _context_from_args(args, out, err)
        return handler(context, args)
    except ToolkitError as error:
        if context is None and early_format == JSON:
            # No context exists yet, so render against a minimal stand-in that
            # carries the requested format.
            context = CliContext(
                workspace=Path.cwd(),
                layout=Layout(
                    workspace=Path.cwd(),
                    state_dir=Path.cwd(),
                    source="unresolved",
                    package_root=Path.cwd(),
                ),
                config=Config(),
                output_format=JSON,
                stdout=out,
                stderr=err,
            )
        return render_error(context, error)
    except KeyboardInterrupt:
        print("\ninterrupted", file=err)
        return exit_codes.INTERRUPTED
    except BrokenPipeError:  # pragma: no cover - depends on the consumer
        return exit_codes.IO_ERROR
    except OSError as error:
        print(f"error: {error.strerror or error}", file=err)
        if error.filename:
            print(f"  path: {error.filename}", file=err)
        return exit_codes.IO_ERROR
    except Exception:
        # The traceback goes to stderr so the defect is debuggable, and the exit
        # code is non-zero so a pipeline cannot mistake it for a pass.
        import traceback

        traceback.print_exc(file=err)
        print("error: unhandled internal error; this is a defect in opencode-toolkit", file=err)
        return exit_codes.FAILURE
