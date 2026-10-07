"""Semantic version handling.

``MAJOR.MINOR.PATCH`` with optional pre-release and build metadata. The single
source of truth for the project version is ``pyproject.toml``; this module
reads it at runtime so there is exactly one place to bump.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from pathlib import Path
from typing import Final

from opencode_toolkit.core.errors import ConfigurationError

_SEMVER_RE: Final = re.compile(
    r"^(?P<major>0|[1-9]\d*)"
    r"\.(?P<minor>0|[1-9]\d*)"
    r"\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@total_ordering
@dataclass(frozen=True, slots=True)
class Version:
    """An immutable semantic version."""

    major: int
    minor: int
    patch: int
    prerelease: str | None = None
    build: str | None = None

    @classmethod
    def parse(cls, text: str) -> Version:
        """Parse *text*, raising :class:`ConfigurationError` when malformed.

        Args:
            text: str: Version string of the form
                ``MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]``; surrounding
                whitespace is ignored.

        Raises:
            ConfigurationError: *text* is not a valid semantic version.
        """
        match = _SEMVER_RE.match(text.strip())
        if match is None:
            raise ConfigurationError(
                f"not a valid semantic version: {text!r}",
                details={"expected": "MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]"},
            )
        return cls(
            major=int(match.group("major")),
            minor=int(match.group("minor")),
            patch=int(match.group("patch")),
            prerelease=match.group("prerelease"),
            build=match.group("build"),
        )

    def __str__(self) -> str:
        text = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            text += f"-{self.prerelease}"
        if self.build:
            text += f"+{self.build}"
        return text

    def _cmp_key(self) -> tuple[int, int, int, int, str]:
        # A pre-release sorts *before* the corresponding release, per semver §11.
        return (
            self.major,
            self.minor,
            self.patch,
            0 if self.prerelease else 1,
            self.prerelease or "",
        )

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._cmp_key() < other._cmp_key()

    @property
    def is_prerelease(self) -> bool:
        """``True`` when this version carries a semver pre-release tag."""
        return self.prerelease is not None


def parse_version(text: str) -> Version:
    """Module-level shortcut for :meth:`Version.parse`.

    Args:
        text: str: Version string to parse, with the same grammar and the same
            :class:`ConfigurationError` on failure.
    """
    return Version.parse(text)


def project_root() -> Path:
    """Locate the repository root.

    Walks up from this file looking for ``pyproject.toml``. Works from a source
    checkout and from an installed wheel (where the walk stops and falls back to
    the package directory).
    """
    here = Path(__file__).resolve()
    for candidate in here.parents:
        pyproject = candidate / "pyproject.toml"
        if pyproject.is_file():
            return candidate
    return here.parents[2]


def _version_from_pyproject(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    # Parsed with a regex rather than tomllib so the function works on Python
    # 3.10/3.11 too; the pattern only matches the [project] table's version.
    in_project = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_project = stripped == "[project]"
            continue
        if in_project and stripped.startswith("version"):
            _, _, value = stripped.partition("=")
            return value.strip().strip('"').strip("'")
    raise ConfigurationError("pyproject.toml does not declare [project] version")


def detect_version(root: Path | None = None) -> Version:
    """Return the project version declared in ``pyproject.toml``.

    Args:
        root: Path | None: Directory holding ``pyproject.toml``; defaults to the
            repository root located by :func:`project_root`.

    Raises:
        ConfigurationError: ``pyproject.toml`` is absent, declares no
            ``[project]`` version, or declares one that is not valid semver.
    """
    base = root or project_root()
    pyproject = base / "pyproject.toml"
    if not pyproject.is_file():
        raise ConfigurationError(
            "pyproject.toml not found; cannot determine the project version",
            details={"searched_from": str(base)},
        )
    return Version.parse(_version_from_pyproject(pyproject))


__version__: str = str(detect_version())
