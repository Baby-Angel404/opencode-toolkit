"""Structured error types.

Every failure that crosses a component boundary is a :class:`ToolkitError`
carrying a machine-readable ``code``, a stable ``exit_code`` and a ``details``
mapping that is safe to serialise (no secrets -- see
:mod:`opencode_toolkit.core.redact`).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opencode_toolkit.core import exit_codes


class ToolkitError(Exception):
    """Base class for all toolkit errors."""

    #: Stable machine-readable identifier, e.g. ``config.invalid``.
    code: str = "toolkit.error"
    #: Exit code the CLI must return for this class of failure.
    exit_code: int = exit_codes.FAILURE

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        exit_code: int | None = None,
        details: Mapping[str, Any] | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        if exit_code is not None:
            self.exit_code = exit_code
        self.details: dict[str, Any] = dict(details or {})
        self.hint = hint

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        payload: dict[str, Any] = {
            "error": self.code,
            "message": self.message,
            "exit_code": self.exit_code,
        }
        if self.details:
            payload["details"] = self.details
        if self.hint:
            payload["hint"] = self.hint
        return payload

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.hint:
            return f"{self.message} (hint: {self.hint})"
        return self.message


class UsageError(ToolkitError):
    """The user asked for something the CLI cannot express."""

    code = "cli.usage"
    exit_code = exit_codes.USAGE


class ConfigurationError(ToolkitError):
    """Configuration is missing, unreadable, or internally inconsistent."""

    code = "config.invalid"
    exit_code = exit_codes.CONFIG


class StateError(ToolkitError):
    """Persistent state is missing, corrupt, or written by another version."""

    code = "state.invalid"
    exit_code = exit_codes.IO_ERROR


class StorageError(ToolkitError):
    """A filesystem operation failed."""

    code = "storage.io"
    exit_code = exit_codes.IO_ERROR


class IntegrityError(ToolkitError):
    """Checksums, signatures, or tamper detection failed."""

    code = "integrity.verification_failed"
    exit_code = exit_codes.INTEGRITY


class ConflictError(ToolkitError):
    """A destructive write would clobber an unrelated local modification.

    The toolkit never silently overwrites. This error is raised *before* any
    mutation so the caller can report exactly which paths are in conflict.
    """

    code = "sync.conflict"
    exit_code = exit_codes.CONFLICT

    def __init__(self, message: str, *, conflicts: list[str], **kwargs: Any) -> None:
        super().__init__(message, details={"conflicts": sorted(conflicts)}, **kwargs)
        self.conflicts = sorted(conflicts)


class EncryptionError(ToolkitError):
    """Authenticated decryption failed: wrong passphrase or tampered data."""

    code = "crypto.decrypt_failed"
    exit_code = exit_codes.INTEGRITY


class NetworkError(ToolkitError):
    """A network-only operation failed and offline operation was impossible."""

    code = "network.unavailable"
    exit_code = exit_codes.NETWORK


class NotFoundError(ToolkitError):
    """A requested entity does not exist."""

    code = "entity.not_found"
    exit_code = exit_codes.FAILURE
