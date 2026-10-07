"""Shared primitives: errors, exit codes, configuration, paths, IO, logging.

Every component depends on this package and nothing outside it. Keeping the
core dependency-free is what makes the offline pack and clean-environment
installs reproducible.
"""

from __future__ import annotations

__all__ = [
    "config",
    "errors",
    "exit_codes",
    "fsio",
    "jsonio",
    "logging",
    "paths",
    "redact",
    "version",
]
