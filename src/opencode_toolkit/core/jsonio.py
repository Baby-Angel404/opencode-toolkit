"""Deterministic JSON I/O.

Every artefact the toolkit writes is JSON with sorted keys, a trailing newline
and UTF-8 encoding. Determinism is not cosmetic here: checksums in the offline
pack and release artifacts are computed over these files, so key order and
whitespace must not vary between runs or on different machines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opencode_toolkit.core.errors import StateError, StorageError
from opencode_toolkit.core.fsio import atomic_write


def dumps(payload: Any, *, indent: int | None = 2) -> str:
    """Serialise *payload* deterministically.

    Keys are sorted, non-ASCII characters are preserved and values the encoder
    does not recognise are rendered with :func:`str`, so the output is stable
    across runs and machines.

    Args:
        payload: Any: Object to serialise.
        indent: int | None: Number of spaces per indent level. ``None`` emits a
            single line with no whitespace after separators.
    """
    separators = (",", ": ") if indent is not None else (",", ":")
    return json.dumps(
        payload,
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
        separators=separators,
        default=str,
    )


def dump_compact(payload: Any) -> str:
    """Serialise *payload* as a single line (for hashing and machine output).

    Args:
        payload: Any: Object to serialise.
    """
    return dumps(payload, indent=None)


def write(path: Path, payload: Any, *, indent: int | None = 2) -> None:
    """Atomically write *payload* as deterministic JSON to *path*.

    A trailing newline is appended so the file is well-formed for line-oriented
    tooling.

    Args:
        path: Path: Destination file; parent directories are created if needed.
        payload: Any: Object to serialise.
        indent: int | None: Number of spaces per indent level, or ``None`` for a
            single line.

    Raises:
        StorageError: The JSON cannot be written to *path*.
    """
    text = dumps(payload, indent=indent) + "\n"
    try:
        with atomic_write(path) as handle:
            handle.write(text)
    except OSError as exc:
        raise StorageError(
            f"cannot write {path}: {exc.strerror or exc}",
            details={"path": str(path)},
        ) from exc


def loads(text: str, *, source: str = "<string>") -> Any:
    """Parse JSON, converting decode errors into :class:`StateError`.

    Args:
        text: str: JSON document to decode.
        source: str: Label for the document, used only in the error message so
            the failure can name the file or field that was bad.

    Raises:
        StateError: *text* is not valid JSON.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise StateError(
            f"invalid JSON in {source}: {exc.msg} at line {exc.lineno} column {exc.colno}",
            details={"source": source, "line": exc.lineno, "column": exc.colno},
        ) from exc


def read(path: Path) -> Any:
    """Read and parse JSON from *path*.

    Args:
        path: Path: UTF-8 JSON file to read.

    Raises:
        StateError: The file is missing or does not contain valid JSON.
        StorageError: The file exists but cannot be read.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise StateError(
            f"file not found: {path}",
            code="state.missing",
            details={"path": str(path)},
        ) from exc
    except OSError as exc:
        raise StorageError(
            f"cannot read {path}: {exc.strerror or exc}",
            details={"path": str(path)},
        ) from exc
    return loads(text, source=str(path))
