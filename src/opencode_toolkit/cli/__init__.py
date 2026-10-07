"""The single ``opencode`` command line.

One entry point, one argument grammar, one error contract. Every subcommand
shares:

* the same global options (``--format``, ``--workspace``, ``--state-dir``,
  ``--config``, ``--log-level``, ``--quiet``, ``--version``)
* the same exit codes (see :mod:`opencode_toolkit.core.exit_codes`)
* the same error rendering: human text by default, JSON with ``--format json``
* the same rule that stdout carries the answer and stderr carries diagnostics
"""

from __future__ import annotations

from opencode_toolkit.cli.main import build_parser, main

__all__ = ["build_parser", "main"]
