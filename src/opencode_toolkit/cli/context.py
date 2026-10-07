"""Shared CLI context and output rendering.

Two invariants:

* **stdout is the answer.** Anything a machine will parse goes to stdout.
  Diagnostics, warnings and the security auditor's human report go to stderr
  unless the caller explicitly asked for them on stdout.
* **The same data renders two ways.** Every command builds a result object; the
  renderer turns it into text or JSON from that one object, so the two can never
  disagree.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from opencode_toolkit.core import logging
from opencode_toolkit.core.config import Config, load_config
from opencode_toolkit.core.errors import ToolkitError
from opencode_toolkit.core.paths import Layout

#: Output formats shared by every command.
TEXT = "text"
JSON = "json"
SARIF = "sarif"
FORMATS = (TEXT, JSON, SARIF)


@dataclass(slots=True)
class CliContext:
    """Everything a command handler needs."""

    workspace: Path
    layout: Layout
    config: Config
    output_format: str
    quiet: bool = False
    verbose: bool = False
    dry_run: bool = False
    stdout: TextIO = field(default=sys.stdout)
    stderr: TextIO = field(default=sys.stderr)
    _extra: dict[str, Any] = field(default_factory=dict)

    def with_overrides(self, overrides: dict[str, Any]) -> CliContext:
        """Return a context with configuration overrides applied.

        Args:
            overrides: dict[str, Any]: Config values merged over the ones already
                recorded on this context, with nested dicts merged key by key.
        """
        merged = dict(self._extra.get("config_overrides", {}))
        for key, value in overrides.items():
            merged.setdefault(key, {})
            if isinstance(value, dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
        config = load_config(self.layout, overrides=merged or None)
        clone = CliContext(
            workspace=self.workspace,
            layout=self.layout,
            config=config,
            output_format=self.output_format,
            quiet=self.quiet,
            verbose=self.verbose,
            dry_run=self.dry_run,
            stdout=self.stdout,
            stderr=self.stderr,
        )
        clone._extra = dict(self._extra)
        clone._extra["config_overrides"] = merged
        return clone

    def note(self, message: str) -> None:
        """Write a human diagnostic to stderr unless quiet.

        Args:
            message: str: The diagnostic text written verbatim to stderr.
        """
        if not self.quiet:
            print(message, file=self.stderr)

    def warn(self, message: str) -> None:
        """Write a warning to stderr. Never suppressed by ``--quiet``.

        Args:
            message: str: The warning text, prefixed with ``warning:``.
        """
        print(f"warning: {message}", file=self.stderr)

    def error(self, message: str) -> None:
        """Write an error to stderr. Never suppressed.

        Args:
            message: str: The error text, prefixed with ``error:``.
        """
        print(f"error: {message}", file=self.stderr)


def emit_json(payload: Any, stream: TextIO) -> None:
    """Write deterministic JSON to *stream*.

    Args:
        payload: Any: Object serialised with sorted keys and ``default=str``.
        stream: TextIO: Destination the JSON document and trailing newline go to.
    """
    stream.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=str))
    stream.write("\n")


def render_error(context: CliContext | None, error: ToolkitError) -> int:
    """Print *error* in the requested format and return its exit code.

    Args:
        context: CliContext | None: Context supplying the output format and
            streams, or ``None`` to fall back to the process stderr.
        error: ToolkitError: The error whose message, code, hint and details
            are rendered.

    Returns:
        int: The error's exit code.
    """
    if context is not None and context.output_format == JSON:
        emit_json({"status": "error", **error.to_dict()}, context.stdout)
    else:
        target = context.stderr if context is not None else sys.stderr
        print(f"error: {error.message}", file=target)
        if error.details:
            print(f"  code: {error.code}", file=target)
        if error.hint:
            print(f"  hint: {error.hint}", file=target)
        _print_details(error.details, target)
    return error.exit_code


def _print_details(details: dict[str, Any], stream: TextIO, *, indent: str = "        ") -> None:
    for key, value in sorted(details.items()):
        if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            print(f"  {key}:", file=stream)
            for item in value[:20]:
                print(f"{indent}{item}", file=stream)
            if len(value) > 20:
                print(f"{indent}... {len(value) - 20} more", file=stream)
        elif isinstance(value, dict):
            print(f"  {key}:", file=stream)
            for sub_key, sub_value in sorted(value.items()):
                print(f"{indent}{sub_key}: {sub_value}", file=stream)
        else:
            print(f"  {key}: {value}", file=stream)


def configure_logging(level: str) -> None:
    """Configure the redacting logger from the resolved level.

    Args:
        level: str: Resolved logging level name passed to the logging setup.
    """
    logging.configure(level)


def section(title: str, stream: TextIO) -> None:
    """Print a section heading to *stream*.

    Args:
        title: str: Heading text, underlined by a rule of matching width.
        stream: TextIO: Destination the heading and its underline go to.
    """
    print(f"\n{title}", file=stream)
    print("-" * len(title), file=stream)


def table(rows: list[tuple[str, str]], stream: TextIO, *, indent: str = "  ") -> None:
    """Print aligned ``key: value`` rows.

    Args:
        rows: list[tuple[str, str]]: Key/value pairs to align; nothing is
            printed when empty.
        stream: TextIO: Destination the aligned rows go to.
        indent: str: Prefix placed before every row, defaulting to two spaces.
    """
    if not rows:
        return
    width = max(len(key) for key, _ in rows)
    for key, value in rows:
        print(f"{indent}{key.ljust(width)}  {value}", file=stream)
