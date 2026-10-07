"""Predictable process exit codes.

Exit codes are part of the public contract: scripts and CI depend on them. The
mapping is stable and documented in ``docs/development/exit-codes.md``.
"""

from __future__ import annotations

from typing import Final

#: Everything succeeded.
OK: Final = 0
#: A required check ran and reported at least one failure.
FAILURE: Final = 1
#: The command line itself was wrong (unknown command, bad arguments).
USAGE: Final = 2
#: The tool refused to run because of invalid configuration or environment.
CONFIG: Final = 3
#: An input/output error: missing file, permission denied, corrupt state.
IO_ERROR: Final = 4
#: A conflict was detected and the tool refused to overwrite anything.
CONFLICT: Final = 5
#: Integrity verification failed (checksum, signature, tamper detection).
INTEGRITY: Final = 6
#: A network operation failed while offline operation was not possible.
NETWORK: Final = 7
#: An operation was interrupted (SIGINT / KeyboardInterrupt).
INTERRUPTED: Final = 130

#: Human-readable names, used by ``opencode doctor`` and the release report.
NAMES: Final[dict[int, str]] = {
    OK: "ok",
    FAILURE: "failure",
    USAGE: "usage",
    CONFIG: "config-error",
    IO_ERROR: "io-error",
    CONFLICT: "conflict",
    INTEGRITY: "integrity-error",
    NETWORK: "network-error",
    INTERRUPTED: "interrupted",
}


def describe(code: int) -> str:
    """Return the stable name of *code* (``unknown`` when unregistered).

    Args:
        code: int: Process exit code to name, such as :data:`CONFLICT`. Codes
            absent from :data:`NAMES` yield ``"unknown"`` rather than raising.
    """
    return NAMES.get(code, "unknown")
