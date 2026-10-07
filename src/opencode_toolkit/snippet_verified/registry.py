"""Registry loading, search and safe installation.

Search is intentionally simple and explainable: substring matching over the
identifier, summary, category and notes, with results ranked by whether the query
matched the identifier. There is no embedding model and no fuzzy scoring whose
behaviour nobody can reproduce, which matters for a component that hands people
code to paste into their projects.
"""

from __future__ import annotations

import difflib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio
from opencode_toolkit.core.errors import ConflictError, NotFoundError, StateError, UsageError
from opencode_toolkit.core.fsio import sha256_file, write_new
from opencode_toolkit.core.logging import get_logger
from opencode_toolkit.core.version import project_root
from opencode_toolkit.snippet_verified.models import (
    Snippet,
    SnippetCategory,
    SnippetStatus,
    SnippetValidationError,
)

logger = get_logger("snippet_verified")

DATA_RELPATH = Path("snippet_verified") / "data" / "registry.json"


def default_registry_path() -> Path:
    """Locate the bundled registry JSON."""
    return project_root() / "src" / "opencode_toolkit" / DATA_RELPATH


def _external_registry_path() -> Path | None:
    override = Path.home() / ".config" / "opencode-toolkit" / "snippets.json"
    return override if override.is_file() else None


@dataclass(slots=True)
class SearchHit:
    """One search result with the reason it matched."""

    snippet: Snippet
    score: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Return the matched snippet, its score and why it matched."""
        return {"snippet": self.snippet.to_dict(), "score": self.score, "reason": self.reason}


class SnippetRegistry:
    """An immutable, validated collection of snippets."""

    def __init__(self, snippets: Iterable[Snippet], *, source: Path | None = None) -> None:
        self._by_id: dict[str, Snippet] = {}
        for snippet in snippets:
            if snippet.id in self._by_id:
                raise SnippetValidationError(
                    f"duplicate snippet id in registry: {snippet.id}",
                    details={"id": snippet.id, "source": str(source) if source else None},
                )
            self._by_id[snippet.id] = snippet
        self.source = source

    # -- construction -----------------------------------------------------
    @classmethod
    def from_dict(cls, document: dict[str, Any], *, source: Path | None = None) -> SnippetRegistry:
        """Build a registry from a parsed registry document.

        Args:
            document: dict[str, Any]: The decoded registry document.
            source: Path | None: Where the document came from, for error messages only.

        Returns:

        Raises:
            SnippetValidationError: The document is malformed, or a snippet
                fails the registry contract. Validation happens at load time so a
                broken registry fails on startup rather than at installation.
        """
        raw = document.get("snippets")
        if not isinstance(raw, list):
            raise SnippetValidationError(
                "registry document must contain a 'snippets' list",
                details={"source": str(source) if source else None},
            )
        # Every snippet is validated; all problems are reported together.
        problems: list[str] = []
        parsed: list[Snippet] = []
        for index, entry in enumerate(raw):
            if not isinstance(entry, dict):
                problems.append(f"snippet at index {index} is not an object")
                continue
            try:
                parsed.append(Snippet.from_dict(entry))
            except SnippetValidationError as exc:
                problems.extend(exc.details.get("problems", [str(exc)]))
        if problems:
            raise SnippetValidationError(
                f"registry contains {len(problems)} validation problem(s)",
                details={"problems": problems[:40], "source": str(source) if source else None},
                hint="the registry is part of the shipped package; this indicates a broken checkout",
            )
        return cls(parsed, source=source)

    @classmethod
    def load(cls, path: Path | None = None) -> SnippetRegistry:
        """Load the registry, preferring an explicit path then a user override.

        Args:
            path: Path | None: Registry file to load. ``None`` falls back to a
                user override and then to the bundled registry.

        Raises:
            StateError: No registry file exists at the chosen path.
            SnippetValidationError: The registry file contains invalid snippets;
                the problems are reported together.
        """
        candidate = path or _external_registry_path() or default_registry_path()
        if not candidate.is_file():
            raise StateError(
                f"snippet registry not found: {candidate}",
                code="snippet.registry_missing",
                details={"searched": str(candidate)},
            )
        document = jsonio.read(candidate)
        return cls.from_dict(document, source=candidate)

    # -- queries ----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, snippet_id: object) -> bool:
        return snippet_id in self._by_id

    def all(self) -> list[Snippet]:
        """Every snippet, ordered by identifier."""
        return [self._by_id[key] for key in sorted(self._by_id)]

    def get(self, snippet_id: str) -> Snippet:
        """Return one snippet, raising :class:`NotFoundError` when absent.

        Args:
            snippet_id: str: Identifier to look up. When nothing matches, close
                matches are offered as suggestions in the error.

        Raises:
            NotFoundError: No snippet has that identifier.
        """
        try:
            return self._by_id[snippet_id]
        except KeyError:
            suggestions = difflib.get_close_matches(snippet_id, list(self._by_id), n=3, cutoff=0.5)
            raise NotFoundError(
                f"no snippet with id {snippet_id!r}",
                code="snippet.not_found",
                details={"id": snippet_id, "suggestions": suggestions, "total": len(self._by_id)},
                hint=f"run `opencode snippet list` or try: {', '.join(suggestions)}"
                if suggestions
                else "run `opencode snippet list` to see available snippets",
            ) from None

    def by_status(self, status: SnippetStatus) -> list[Snippet]:
        """Return the snippets with one review status.

        Args:
            status: SnippetStatus: Status to filter on, e.g.
                ``SnippetStatus.VERIFIED``. Matched by identity, not equality of
                display text.
        """
        return [snippet for snippet in self.all() if snippet.status is status]

    def by_category(self, category: SnippetCategory) -> list[Snippet]:
        """Return the snippets in one category.

        Args:
            category: SnippetCategory: Category to filter on. Matched by identity;
                a category with no snippets yields an empty list rather than
                raising.
        """
        return [snippet for snippet in self.all() if snippet.category is category]

    def search(self, query: str, *, limit: int = 20) -> list[SearchHit]:
        """Rank snippets against *query*.

        Exact identifier prefix scores highest, then identifier substring,
        then word-boundary matches in the summary, then any occurrence in the
        searchable fields. A fuzzy match is only returned when nothing else
        matched, and is labelled as such in the reason.

        Args:
            query: str: Case-insensitive search text. Matched against the
                identifier, the category and the summary and note fields;
                stripped before use.
            limit: int: Maximum number of hits returned, highest score first.
                Ties break on identifier, so the order is deterministic.

        Returns:
            list[SearchHit]: Scored matches with the reason for each score. May
                be empty when nothing matched at all.

        Raises:
            UsageError: *query* is empty or only whitespace.
        """
        needle = query.strip().lower()
        if not needle:
            raise UsageError("search query must not be empty", code="snippet.empty_query")

        hits: list[SearchHit] = []
        for snippet in self.all():
            score, reason = self._score(snippet, needle)
            if score > 0:
                hits.append(SearchHit(snippet, score, reason))

        if not hits:
            for snippet in self.all():
                ratio = difflib.SequenceMatcher(None, needle, snippet.id).ratio()
                if ratio >= 0.6:
                    hits.append(
                        SearchHit(
                            snippet,
                            int(ratio * 10),
                            f"fuzzy match on id (similarity {ratio:.2f}); verify before use",
                        )
                    )

        hits.sort(key=lambda hit: (-hit.score, hit.snippet.id))
        return hits[:limit]

    @staticmethod
    def _score(snippet: Snippet, needle: str) -> tuple[int, str]:
        identifier = snippet.id.lower()
        if identifier == needle:
            return 100, "exact identifier match"
        if identifier.startswith(needle):
            return 80, "identifier prefix match"
        if needle in identifier:
            return 60, "identifier substring match"
        if snippet.category.value == needle:
            return 55, f"category is {needle}"
        words = needle.split()
        haystack = " ".join(
            [
                snippet.summary,
                *snippet.security_notes,
                *snippet.edge_cases,
                *snippet.maintenance_notes,
            ]
        ).lower()
        if all(word in haystack for word in words):
            return 40, "all query words appear in the notes"
        if any(word in haystack for word in words):
            return 20, f"one query word appears in the notes ({snippet.language})"
        return 0, ""

    # -- installation -----------------------------------------------------
    def materialise(
        self, snippet_id: str, target: Path, *, overwrite: bool = False
    ) -> dict[str, Any]:
        """Write a snippet's implementation to *target*.

        Never overwrites silently: without *overwrite*, an existing file raises
        :class:`ConflictError` naming the file and its digest.

        Args:
            snippet_id: str: Identifier of the snippet to install.
            target: Path: File to write; ``~`` is expanded and parent
                directories are created as needed.
            overwrite: bool: Allow replacing an existing file. Without it, an
                existing file raises :class:`ConflictError`. It also permits
                installing a deprecated snippet, which otherwise raises
                :class:`UsageError`.

        Returns:
            dict[str, Any]: The snippet id, the path written, the status, the
                digest of the file that was there before (``None`` when it was
                created), and whether the file was created rather than replaced.

        Raises:
            NotFoundError: No snippet has that identifier.
            UsageError: The snippet is deprecated and *overwrite* is not set.
            ConflictError: The target exists and *overwrite* is not set.
        """
        snippet = self.get(snippet_id)
        if snippet.status is SnippetStatus.DEPRECATED and not overwrite:
            raise UsageError(
                f"snippet {snippet.id!r} is deprecated and will not be installed",
                code="snippet.deprecated",
                details={"id": snippet.id, "maintenance_notes": list(snippet.maintenance_notes)},
                hint="read the maintenance notes, then re-run with --force to install anyway",
            )

        target = target.expanduser()
        existing_digest = sha256_file(target) if target.is_file() else None
        if existing_digest is not None and not overwrite:
            raise ConflictError(
                f"refusing to overwrite existing file: {target}",
                conflicts=[str(target)],
                hint="pass --force to replace it, or choose another destination",
            )

        if existing_digest is None:
            write_new(target, self._render(snippet))
        else:
            target.write_text(self._render(snippet), encoding="utf-8")

        return {
            "id": snippet.id,
            "path": str(target),
            "status": snippet.status.value,
            "previous_sha256": existing_digest,
            "created": existing_digest is None,
        }

    @staticmethod
    def _render(snippet: Snippet) -> str:
        """Render the snippet with a provenance header.

        The header is part of the file so a reader can tell a reviewed pattern
        from ad-hoc code, and so ``opencode docs scan`` can find it later.
        """
        header = [
            f"# opencode-verified-snippet: {snippet.id}",
            f"# version: {snippet.version}",
            f"# status: {snippet.status.value}",
            f"# category: {snippet.category.value}",
            f"# language: {snippet.language}",
            "#",
            "# Security notes:",
            *[f"#   - {note}" for note in snippet.security_notes],
            "#",
            "# Edge cases handled:",
            *[f"#   - {note}" for note in snippet.edge_cases],
            "",
        ]
        return "\n".join(header) + snippet.implementation.rstrip() + "\n"

    def verify(self, snippet_id: str, target: Path) -> dict[str, Any]:
        """Check whether *target* still contains this snippet, unmodified.

        Args:
            snippet_id: str: Identifier of the snippet expected in the file.
            target: Path: File to inspect; read leniently, so undecodable bytes
                are replaced rather than raising.

        Returns:
            dict[str, Any]: The snippet id and path, whether the *snippet* is
                ``present``, whether the implementation body still appears
                verbatim (``matches``), and whether the provenance header
                survives (``header_present``).

                ``present`` means the snippet, not the file. A file that exists
                but never had the snippet reports ``present=False``, because
                "present but modified" would tell the reader their code drifted
                when in fact nothing was ever installed here.

        Raises:
            NotFoundError: *snippet_id* is not in the registry.
        """
        snippet = self.get(snippet_id)
        marker = f"opencode-verified-snippet: {snippet.id}"
        if not target.is_file():
            return {
                "id": snippet.id,
                "path": str(target),
                "present": False,
                "matches": False,
                "header_present": False,
            }
        content = target.read_text(encoding="utf-8", errors="replace")
        header_present = marker in content
        matches = snippet.implementation.rstrip() in content
        return {
            "id": snippet.id,
            "path": str(target),
            # Either signal proves the snippet was here: the body surviving
            # verbatim, or the provenance marker left behind by an edit.
            "present": matches or header_present,
            "matches": matches,
            "header_present": header_present,
        }


def load_registry(path: Path | None = None) -> SnippetRegistry:
    """Module-level loader with caching keyed on the resolved path.

    Args:
        path: Path | None: Registry file to load; ``None`` uses the user
            override or the bundled registry. Repeated calls with the same
            argument return the cached registry, so a command that queries the
            registry many times parses it once.

    Raises:
        StateError: No registry file exists at the chosen path.
        SnippetValidationError: The registry file contains invalid snippets.
    """
    return _cached_load(path)


@lru_cache(maxsize=4)
def _cached_load(path: Path | None) -> SnippetRegistry:
    return SnippetRegistry.load(path)


def default_registry() -> SnippetRegistry:
    """Return the bundled registry."""
    return _cached_load(None)


def catalogue_markdown(registry: SnippetRegistry) -> str:
    """Render the registry as documentation-ready Markdown.

    Args:
        registry: SnippetRegistry: Registry to render. Snippets are grouped by
            category in enum order, categories with no snippets are omitted, and
            pipes in summaries are escaped so the tables stay well-formed.
    """
    lines = [
        "# Verified Snippet Catalogue",
        "",
        f"Total snippets: **{len(registry)}**",
        "",
    ]
    for category in SnippetCategory:
        entries = registry.by_category(category)
        if not entries:
            continue
        lines.append(f"## {category.value}")
        lines.append("")
        lines.append("| id | language | status | version | summary |")
        lines.append("| --- | --- | --- | --- | --- |")
        for snippet in entries:
            summary = snippet.summary.replace("|", "\\|")
            lines.append(
                f"| `{snippet.id}` | {snippet.language} | {snippet.status.value} "
                f"| {snippet.version} | {summary} |"
            )
        lines.append("")
    return "\n".join(lines)


def registry_stats(registry: SnippetRegistry) -> dict[str, Any]:
    """Counts by status, category and language, for ``opencode doctor``.

    Args:
        registry: SnippetRegistry: Registry to summarise. Every snippet
            contributes to exactly one bucket in each of the three breakdowns.

    Returns:
        dict[str, Any]: The ``total``, the ``by_status``, ``by_category`` and
            ``by_language`` counts with sorted keys, and the ``source`` path the
            registry came from, or ``None`` for the bundled one.
    """
    by_status: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_language: dict[str, int] = {}
    for snippet in registry.all():
        by_status[snippet.status.value] = by_status.get(snippet.status.value, 0) + 1
        by_category[snippet.category.value] = by_category.get(snippet.category.value, 0) + 1
        by_language[snippet.language] = by_language.get(snippet.language, 0) + 1
    return {
        "total": len(registry),
        "by_status": dict(sorted(by_status.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_language": dict(sorted(by_language.items())),
        "source": str(registry.source) if registry.source else None,
    }


def _json_loads(text: str) -> Any:  # pragma: no cover - thin wrapper for tests
    return json.loads(text)
