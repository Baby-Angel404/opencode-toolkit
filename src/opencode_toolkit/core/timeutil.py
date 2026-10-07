"""Timestamp helpers shared by every component.

All timestamps are UTC, ISO-8601, second-resolution and formatted with a literal
``Z``. One format everywhere means snapshot timestamps, journal records and
checkpoint files sort lexicographically, which the index ordering relies on.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Final

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


#: Epoch used when nothing else pins the clock. Matches the zip format's own
#: minimum, so a reproducible build needs no magic date of its own.
REPRODUCIBLE_EPOCH: Final = "1980-01-01T00:00:00Z"

#: The conventional environment variable for reproducible builds.
SOURCE_DATE_EPOCH_ENV: Final = "SOURCE_DATE_EPOCH"


def reproducible_timestamp(environ: dict[str, str] | None = None) -> str:
    """Return a build timestamp that does not change between runs.

    A wall clock makes a "byte-reproducible" archive reproducible only when two
    builds happen to land in the same second. That is nearly always, which is
    worse than never: the pack advertises reproducibility and the release gate
    checks it, so a build that straddles a second boundary fails at random and
    nobody can point at the cause.

    ``SOURCE_DATE_EPOCH`` is the cross-ecosystem convention for exactly this, so
    it wins when set. Otherwise the fixed epoch is used, and reproducibility is
    a property of the build rather than of the clock.

    Args:
        environ: dict[str, str] | None: Environment mapping to read; defaults to
            :data:`os.environ`. A malformed value is ignored rather than raised,
            because an unparseable hint should not fail a build.

    Returns:
        str: A timestamp in :data:`TIMESTAMP_FORMAT`.
    """
    env = os.environ if environ is None else environ
    raw = env.get(SOURCE_DATE_EPOCH_ENV, "").strip()
    if raw:
        try:
            return datetime.fromtimestamp(int(raw), tz=timezone.utc).strftime(TIMESTAMP_FORMAT)
        except (ValueError, OverflowError, OSError):
            pass
    return REPRODUCIBLE_EPOCH
