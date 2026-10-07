"""Command handlers, one module per command group.

Each module exposes ``register(subparsers)`` and a ``run_*`` function returning an
exit code. Handlers never call ``sys.exit``; they return the code so the CLI is
fully testable in-process.
"""

from __future__ import annotations

from opencode_toolkit.cli.commands import (
    docs,
    doctor,
    orchestrator,
    pack,
    publish,
    release,
    security,
    snippet,
    sync,
    testing,
    version,
)

__all__ = [
    "docs",
    "doctor",
    "orchestrator",
    "pack",
    "publish",
    "release",
    "security",
    "snippet",
    "sync",
    "testing",
    "version",
]
