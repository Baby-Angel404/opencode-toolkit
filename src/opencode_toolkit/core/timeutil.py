"""Timestamp helpers shared by every component.

All timestamps are UTC, ISO-8601, second-resolution and formatted with a literal
``Z``. One format everywhere means snapshot timestamps, journal records and
checkpoint files sort lexicographically, which the index ordering relies on.
"""

from __future__ import annotations

from datetime import datetime, timezone

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now() -> str:
    """Return the current UTC time, e.g. ``2026-01-02T03:04:05Z``."""
    return datetime.now(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_timestamp(text: str) -> datetime:
    """Parse a timestamp produced by :func:`utc_now`.

    Raises :class:`ValueError` for anything else; callers convert that into
    their own domain error so the message can name the field.
    """
    return datetime.strptime(text, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def to_stamp(text: str) -> str:
    """Convert to the filesystem-friendly form ``20260102T030405Z``.

    Sorts identically to the ISO form, which lets snapshot filenames be listed
    in chronological order without parsing them.

    Args:
        text: str: Timestamp as produced by :func:`utc_now`. Separators are
            removed blindly, so the result is only a filename-safe stamp for
            input already in that format.
    """
    return text.replace("-", "").replace(":", "")
