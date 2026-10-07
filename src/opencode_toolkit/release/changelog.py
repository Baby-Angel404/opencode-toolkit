"""Changelog generation.

``CHANGELOG.md`` is generated from a structured, append-only fragment store
(``.changes/unreleased/*.json``), not by scraping commit messages. Each fragment
records the change type, area and description; a Conventional-Commits-style
parser is used only to *suggest* a fragment from a commit when one is missing.

Keeping history means the changelog for an old release is never rewritten by a
later run.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio
from opencode_toolkit.core.errors import StateError

FRAGMENT_KIND = "opencode-toolkit/changelog-fragment"
CHANGELOG_HEADER = "# Changelog"

#: Render order and section titles, matching Keep a Changelog.
CATEGORIES: tuple[tuple[str, str], ...] = (
    ("added", "Added"),
    ("changed", "Changed"),
    ("deprecated", "Deprecated"),
    ("removed", "Removed"),
    ("fixed", "Fixed"),
    ("security", "Security"),
)

VALID_TYPES = {key for key, _ in CATEGORIES}

_COMMIT_RE = re.compile(
    r"^(?P<type>feat|fix|docs|refactor|perf|test|build|ci|chore|security)"
    r"(?:\((?P<area>[^)]*)\))?(?P<breaking>!)?:\s*(?P<subject>.+)$"
)

_TYPE_MAP = {
    "feat": "added",
    "fix": "fixed",
    "security": "security",
    "docs": "changed",
    "refactor": "changed",
    "perf": "changed",
    "test": "changed",
    "build": "changed",
    "ci": "changed",
    "chore": "changed",
}


@dataclass(frozen=True, slots=True)
class Fragment:
    """One unreleased change."""

    id: str
    kind: str
    area: str
    description: str
    breaking: bool = False
    issue: str = ""

    def __post_init__(self) -> None:
        if self.kind not in VALID_TYPES:
            raise StateError(
                f"changelog fragment {self.id} has an unknown type {self.kind!r}",
                code="release.bad_fragment",
                details={"valid": sorted(VALID_TYPES)},
            )
        if not self.description.strip():
            raise StateError(
                f"changelog fragment {self.id} has an empty description",
                code="release.bad_fragment",
            )

    def to_dict(self) -> dict[str, Any]:
        """Return the fragment body, keyed as the stored fragment JSON is.

        The ``kind`` discriminator is added separately by :func:`write_fragment`.
        """
        return {
            "id": self.id,
            "type": self.kind,
            "area": self.area,
            "description": self.description,
            "breaking": self.breaking,
            "issue": self.issue,
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Fragment:
        """Rebuild a fragment from a stored fragment document.

        Args:
            document: dict[str, Any]: The decoded fragment JSON, including its ``kind``.

        Returns:

        Raises:
            StateError: If ``kind`` is missing or wrong, or if the resulting
                fragment has an unknown type or an empty description.
        """
        if document.get("kind") != FRAGMENT_KIND:
            raise StateError(
                "not a changelog fragment",
                code="release.bad_fragment",
                details={"found_kind": document.get("kind")},
            )
        return cls(
            id=str(document.get("id", "unknown")),
            kind=str(document.get("type", "changed")),
            area=str(document.get("area", "")),
            description=str(document.get("description", "")),
            breaking=bool(document.get("breaking", False)),
            issue=str(document.get("issue", "")),
        )

    def render(self) -> str:
        """Return the one-line bullet text, with breaking and issue markers appended."""
        parts = [self.description.rstrip()]
        if self.breaking:
            parts.append("**Breaking change.**")
        if self.issue:
            parts.append(f"({self.issue})")
        return " ".join(parts)


def fragments_dir(root: Path) -> Path:
    """Return the unreleased fragment directory for *root*.

    Args:
        root: Path: Project root holding the ``.changes/`` tree.
    """
    return root / ".changes" / "unreleased"


def load_fragments(root: Path) -> list[Fragment]:
    """Load every unreleased fragment, sorted by id.

    Args:
        root: Path: Project root holding the ``.changes/`` tree.
    """
    directory = fragments_dir(root)
    if not directory.is_dir():
        return []
    fragments: list[Fragment] = []
    for path in sorted(directory.glob("*.json")):
        document = jsonio.read(path)
        document.setdefault("id", path.stem)
        fragments.append(Fragment.from_dict(document))
    fragments.sort(key=lambda fragment: fragment.id)
    return fragments


def write_fragment(root: Path, fragment: Fragment) -> Path:
    """Write a fragment, refusing to overwrite one with the same id.

    Args:
        root: Path: Project root holding the ``.changes/`` tree.
        fragment: Fragment: The fragment to store; its ``id`` names the file.
    """
    directory = fragments_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{fragment.id}.json"
    jsonio.write(path, {"kind": FRAGMENT_KIND, **fragment.to_dict()})
    return path


def changelog_unreleased(fragments: Iterable[Fragment]) -> str:
    """Render the ``Unreleased`` section.

    Args:
        fragments: Iterable[Fragment]: Fragments to group by kind; consumed once.
    """
    items = list(fragments)
    lines = ["## Unreleased", ""]
    if not items:
        lines.append("No changes recorded yet.")
        lines.append("")
        return "\n".join(lines)

    for key, title in CATEGORIES:
        matching = [fragment for fragment in items if fragment.kind == key]
        if not matching:
            continue
        lines.append(f"### {title}")
        lines.append("")
        for fragment in matching:
            suffix = f" (`{fragment.area}`)" if fragment.area else ""
            lines.append(f"* {fragment.render()}{suffix}")
        lines.append("")
    return "\n".join(lines)


def changelog_release(
    fragments: Iterable[Fragment], version: str, *, released: date | None = None
) -> str:
    """Render a released version section.

    Args:
        fragments: Iterable[Fragment]: Fragments to group by kind; consumed once.
        version: str: Version this section documents.
        released: date | None: Release date; defaults to today.
    """
    stamp = (released or date.today()).isoformat()
    items = list(fragments)
    lines = [f"## {version} - {stamp}", ""]
    if not items:
        lines.append("No changes recorded for this release.")
        lines.append("")
        return "\n".join(lines)
    for key, title in CATEGORIES:
        matching = [fragment for fragment in items if fragment.kind == key]
        if not matching:
            continue
        lines.append(f"### {title}")
        lines.append("")
        for fragment in matching:
            suffix = f" (`{fragment.area}`)" if fragment.area else ""
            lines.append(f"* {fragment.render()}{suffix}")
        lines.append("")
    return "\n".join(lines)


def changelog_markdown(
    root: Path, *, version: str | None = None, released: date | None = None
) -> str:
    """Render the whole changelog: existing history plus the unreleased section.

    Args:
        root: Path: Project root holding ``CHANGELOG.md`` and ``.changes/``.
        version: str | None: Release to render at the top; omit to render ``Unreleased``.
        released: date | None: Release date; defaults to today.
    """
    path = root / "CHANGELOG.md"
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    if existing.startswith(CHANGELOG_HEADER):
        # Drop everything above the first release heading: that is the generated
        # preamble, regenerated every run.
        first_release = existing.find("\n## ")
        history = existing[first_release + 1 :] if first_release != -1 else ""
    else:
        history = ""
    if version:
        head = changelog_release(load_fragments(root), version, released=released)
    else:
        head = changelog_unreleased(load_fragments(root))
    # The parentheses are load-bearing: without them the second literal becomes
    # its own no-op statement and the release notes are silently dropped.
    return (
        f"{CHANGELOG_HEADER}\n\nAll notable changes are recorded here as structured fragments "
        f"under `.changes/unreleased/`.\n\n{head}{history}"
    )


def write_changelog(
    root: Path, *, version: str | None = None, released: date | None = None
) -> Path:
    """Regenerate ``CHANGELOG.md`` for *root* and return its path.

    Existing release history above the first ``## `` heading is preserved: only
    the generated preamble and the newest section are rewritten.

    Args:
        root: Path: Project root holding ``CHANGELOG.md`` and ``.changes/``.
        version: str | None: Release this section is for; omit to render ``Unreleased``.
        released: date | None: Release date; defaults to today.

    Returns:
    """
    path = root / "CHANGELOG.md"
    path.write_text(changelog_markdown(root, version=version, released=released), encoding="utf-8")
    return path


def fragment_from_commit(line: str) -> Fragment | None:
    """Suggest a fragment from a Conventional-Commits-style commit subject.

    Args:
        line: str: One commit subject line; returns ``None`` when it does not match.
    """
    match = _COMMIT_RE.match(line.strip())
    if match is None:
        return None
    kind = _TYPE_MAP.get(match.group("type"), "changed")
    subject = match.group("subject").strip()
    area = match.group("area") or ""
    return Fragment(
        id=f"cc-{abs(hash(line)) % 10_000_000:07d}",
        kind=kind,
        area=area,
        description=subject[0].upper() + subject[1:] if subject else subject,
        breaking=bool(match.group("breaking")),
    )


def clear_fragments(root: Path) -> int:
    """Remove released fragments, returning how many were removed.

    Args:
        root: Path: Project root holding the ``.changes/`` tree.
    """
    directory = fragments_dir(root)
    removed = 0
    for path in sorted(directory.glob("*.json")):
        path.unlink()
        removed += 1
    return removed
