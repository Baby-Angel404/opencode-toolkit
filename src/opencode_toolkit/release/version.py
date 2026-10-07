"""Version management.

``pyproject.toml`` is the single source of truth. Bumping rewrites that one
field and verifies the result parses and that the package imports; a version
that is only partially applied is refused.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from opencode_toolkit.core.errors import ConfigurationError
from opencode_toolkit.core.fsio import sha256_file, write_guarded
from opencode_toolkit.core.version import Version, detect_version, parse_version

BUMP_KINDS: Final = ("major", "minor", "patch")

_VERSION_LINE = re.compile(
    r'^(?P<prefix>\s*version\s*=\s*)(?P<quote>["\'])(?P<value>[^"\']+)(?P=quote)\s*$'
)


def current_version(root: Path) -> Version:
    """Return the version declared in ``pyproject.toml``.

    Args:
        root: Path: Project root containing ``pyproject.toml``.
    """
    return detect_version(root)


def bump_version(version: Version, kind: str) -> Version:
    """Return *version* incremented according to *kind*.

    A pre-release is stripped when bumping, because ``1.2.0-rc.1`` bumping patch
    means ``1.2.1``, not ``1.2.0-rc.2``; promoting to a release is an explicit
    action (``--release``) so it is never implicit.

    Args:
        version: Version: The version to increment; any pre-release suffix is stripped.
        kind: str: One of ``major``, ``minor`` or ``patch``; anything else is rejected.
    """
    if kind not in BUMP_KINDS:
        raise ConfigurationError(
            f"unknown version bump {kind!r}",
            details={"valid": list(BUMP_KINDS)},
        )
    match kind:
        case "major":
            return Version(version.major + 1, 0, 0)
        case "minor":
            return Version(version.major, version.minor + 1, 0)
        case _:
            return Version(version.major, version.minor, version.patch + 1)


def next_prerelease(version: Version, label: str = "rc.1") -> Version:
    """Return *version* with a pre-release suffix applied.

    Args:
        version: Version: The version the pre-release is based on.
        label: str: Pre-release suffix; must match ``rc.N``, ``alpha.N`` or ``beta.N``.
    """
    if not re.fullmatch(r"rc\.\d+|alpha\.\d+|beta\.\d+", label):
        raise ConfigurationError(
            f"invalid pre-release label {label!r}",
            details={"expected": "rc.N, alpha.N or beta.N"},
        )
    return Version(version.major, version.minor, version.patch, prerelease=label)


def find_version_line(text: str) -> tuple[int, str]:
    """Locate the ``[project]`` version line, returning ``(1-based line, value)``.

    Args:
        text: str: Full text of ``pyproject.toml``.
    """
    in_project = False
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("["):
            in_project = stripped == "[project]"
            continue
        if in_project and (match := _VERSION_LINE.match(line)):
            return index, match.group("value")
    raise ConfigurationError(
        "could not find a version field in the [project] table of pyproject.toml",
        details={"hint": "the file may be malformed; run `opencode doctor`"},
    )


def update_version_files(
    root: Path,
    target: Version,
    *,
    expected_current: Version | None = None,
) -> dict[str, str]:
    """Rewrite the version in ``pyproject.toml``.

    *expected_current* makes the write conditional: if the file changed since it
    was read, the update is refused instead of overwriting someone else's bump.

    Args:
        root: Path: Project root containing ``pyproject.toml``.
        target: Version: The version to write into the ``[project]`` table.
        expected_current: Version | None: Abort unless the file still declares this version.
    """
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        raise ConfigurationError(
            f"pyproject.toml not found at {pyproject}", details={"path": str(pyproject)}
        )

    current = detect_version(root)
    if expected_current is not None and current != expected_current:
        raise ConfigurationError(
            f"version on disk is {current}, not the expected {expected_current}; "
            "another process changed the file",
            code="release.version_conflict",
            details={"on_disk": str(current), "expected": str(expected_current)},
            hint="re-read the version and retry",
        )

    text = pyproject.read_text(encoding="utf-8")
    line_number, _ = find_version_line(text)
    lines = text.splitlines(keepends=True)
    original = "".join(lines)
    match = _VERSION_LINE.match(lines[line_number - 1])
    if match is None:  # pragma: no cover - find_version_line just matched it
        raise ConfigurationError("version line vanished between scan and rewrite")
    lines[line_number - 1] = (
        f"{match.group('prefix')}{match.group('quote')}{target}{match.group('quote')}\n"
    )

    write_guarded(pyproject, "".join(lines), expected_sha256=sha256_file(pyproject))
    del original

    # Fail loudly rather than leaving a version that parses but cannot import.
    verify = detect_version(root)
    if verify != target:
        raise ConfigurationError(
            f"version rewrite did not take effect: expected {target}, read {verify}",
            code="release.version_write_failed",
        )
    return {"pyproject.toml": str(target)}


def parse(text: str) -> Version:
    """Re-exported for convenience in the CLI.

    Args:
        text: str: Version string to parse, for example ``1.2.0-rc.1``.
    """
    return parse_version(text)
