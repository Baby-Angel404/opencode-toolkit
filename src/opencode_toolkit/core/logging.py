"""Structured logging with guaranteed secret redaction.

The toolkit logs to stderr and keeps stdout clean for machine-readable output.
Every message passes through :func:`opencode_toolkit.core.redact.redact_text`
before it is emitted, so a credential cannot reach a CI log even if a caller
accidentally formats one into a message.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Final, TextIO

from opencode_toolkit.core.redact import DEFAULT_POLICY, RedactionPolicy, redact_text

LOGGER_NAME: Final = "opencode"
_LEVELS: Final[dict[str, int]] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


class RedactingFormatter(logging.Formatter):
    """Formatter that redacts credential-shaped substrings."""

    def __init__(self, policy: RedactionPolicy = DEFAULT_POLICY) -> None:
        super().__init__(fmt="%(levelname)-8s %(name)s: %(message)s")
        self.policy = policy

    def format(self, record: logging.LogRecord) -> str:
        """Render *record* and redact credential-shaped substrings.

        Redaction runs on the fully formatted text, so it also covers values that
        reached the message through ``%`` interpolation or an exception.

        Args:
            record: logging.LogRecord: The record to render.

        Returns:
        """
        raw = super().format(record)
        return redact_text(raw, policy=self.policy)


def configure(
    level: str = "warning",
    *,
    stream: TextIO | None = None,
    policy: RedactionPolicy = DEFAULT_POLICY,
    force: bool = True,
) -> logging.Logger:
    """Configure and return the toolkit logger.

    Idempotent: repeated calls replace the handler rather than stacking them.

    Args:
        level: str: Level name, case-insensitive; one of ``debug``, ``info``,
            ``warning``, ``error``, ``critical``.
        stream: TextIO | None: Stream for log records; defaults to
            :data:`sys.stderr` so stdout stays clean for machine-readable
            output.
        policy: RedactionPolicy: Masking policy applied to every emitted
            message, defaulting to :data:`DEFAULT_POLICY`.
        force: bool: When ``True``, existing handlers are removed before the new
            one is attached, so repeated calls cannot stack handlers. When
            ``False``, another handler is appended and each record is emitted
            once per handler.

    Raises:
        ValueError: *level* is not a recognised level name.
    """
    logger = logging.getLogger(LOGGER_NAME)
    numeric = _LEVELS.get(level.lower())
    if numeric is None:
        raise ValueError(f"unknown log level: {level!r} (expected one of {sorted(_LEVELS)})")
    logger.setLevel(numeric)
    # Logs must never propagate to the root logger, otherwise a host application
    # could route them somewhere we do not redact.
    logger.propagate = False

    if force:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(RedactingFormatter(policy))
    logger.addHandler(handler)
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child of the toolkit logger.

    ``name`` is sanitised so a caller cannot create a logger outside the
    toolkit namespace and bypass the redaction handler.

    Args:
        name: str | None: Child name to nest under ``"opencode"``. A falsy name,
            or one that sanitises away to nothing, yields the toolkit logger
            itself so the caller still gets redaction.
    """
    if not name:
        return logging.getLogger(LOGGER_NAME)
    safe = name.replace("opencode_toolkit.", "").strip(".")
    if not safe:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(f"{LOGGER_NAME}.{safe}")


def level_from_env(default: str = "warning") -> str:
    """Read the log level from ``OPENCODE_LOG_LEVEL``.

    Args:
        default: str: Level returned when the variable is unset, blank or not a
            recognised level name. The value is not itself validated.
    """
    value = os.environ.get("OPENCODE_LOG_LEVEL", default).strip().lower()
    return value if value in _LEVELS else default
