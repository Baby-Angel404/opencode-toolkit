"""Snippet data model and validation.

Validation is strict on purpose. A snippet that fails validation cannot be
loaded, cannot be listed and cannot be written to disk, because every field in
the contract is something a consumer is entitled to rely on. ``add`` performs
the same validation against the *target file* before writing anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from opencode_toolkit.core.errors import StateError

#: Language identifiers the registry recognises.
SUPPORTED_LANGUAGES = ("python", "javascript", "typescript", "go", "shell", "yaml")

_IDENTIFIER_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

MIN_SNIPPET_LINES = 4


class SnippetCategory(str, Enum):
    """The taxonomy a snippet is filed under."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    ERROR_HANDLING = "error-handling"
    API_INTEGRATION = "api-integration"
    FILE_IO = "file-io"
    CONFIGURATION = "configuration"
    LOGGING = "logging"
    TESTING = "testing"

    def __str__(self) -> str:
        return self.value


class SnippetStatus(str, Enum):
    """Lifecycle status of a snippet."""

    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"

    def __str__(self) -> str:
        return self.value


class SnippetValidationError(StateError):
    """A snippet is missing required fields or contains invalid content."""

    code = "snippet.invalid"


def _require(
    document: dict[str, Any], key: str, kind: type | tuple[type, ...], problems: list[str]
) -> Any:
    if key not in document:
        problems.append(f"missing required field {key!r}")
        return None
    value = document[key]
    if not isinstance(value, kind):
        expected = kind.__name__ if isinstance(kind, type) else "/".join(k.__name__ for k in kind)
        problems.append(f"field {key!r} must be {expected}, got {type(value).__name__}")
        return None
    return value


def _require_list(
    document: dict[str, Any], key: str, problems: list[str], *, min_length: int = 1
) -> list[str]:
    value = _require(document, key, list, problems)
    if value is None:
        return []
    if not all(isinstance(item, str) and item.strip() for item in value):
        problems.append(f"field {key!r} must contain only non-empty strings")
        return []
    if len(value) < min_length:
        problems.append(
            f"field {key!r} needs at least {min_length} entr{'y' if min_length == 1 else 'ies'}"
        )
    return list(value)


@dataclass(frozen=True, slots=True)
class Snippet:
    """One reviewed pattern."""

    id: str
    language: str
    version: str
    status: SnippetStatus
    implementation: str
    dependencies: tuple[str, ...]
    security_notes: tuple[str, ...]
    edge_cases: tuple[str, ...]
    maintenance_notes: tuple[str, ...]
    category: SnippetCategory
    summary: str = ""
    tested_against: tuple[str, ...] = ()
    source: str = ""

    @property
    def line_count(self) -> int:
        """Return how many lines of code installing this snippet adds."""
        return len(self.implementation.splitlines())

    def to_dict(self, *, include_code: bool = False) -> dict[str, Any]:
        """Return a JSON-serialisable view, with the code only when asked.

        Args:
            include_code: bool: Include the ``implementation`` source under the
                ``"implementation"`` key. Defaults to ``False`` so listings and
                reports stay small; pass ``True`` when the code itself is needed.
        """
        payload: dict[str, Any] = {
            "id": self.id,
            "language": self.language,
            "version": self.version,
            "status": self.status.value,
            "category": self.category.value,
            "summary": self.summary,
            "dependencies": list(self.dependencies),
            "security_notes": list(self.security_notes),
            "edge_cases": list(self.edge_cases),
            "maintenance_notes": list(self.maintenance_notes),
            "tested_against": list(self.tested_against),
            "source": self.source,
            "line_count": self.line_count,
        }
        if include_code:
            payload["implementation"] = self.implementation
        return payload

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Snippet:
        """Parse and validate a snippet document, collecting every problem.

        Args:
            document: dict[str, Any]: Decoded snippet document from the registry
                JSON. Unknown keys are ignored.

        Raises:
            SnippetValidationError: The document is missing a required field or
                any field is invalid. Every problem found is reported together,
                so a broken registry can be fixed in one edit.
        """
        problems: list[str] = []
        identifier = _require(document, "id", str, problems)
        if identifier is not None and not _IDENTIFIER_RE.match(identifier):
            problems.append(f"field 'id' must be lowercase kebab-case, got {identifier!r}")

        language = _require(document, "language", str, problems)
        if language is not None and language not in SUPPORTED_LANGUAGES:
            problems.append(
                f"unsupported language {language!r}; supported: {', '.join(SUPPORTED_LANGUAGES)}"
            )

        version = _require(document, "version", str, problems)
        if version is not None and not re.match(r"^\d+\.\d+(\.\d+)?(-[\w.]+)?$", version):
            problems.append(f"field 'version' must be a semantic version, got {version!r}")

        status_value = _require(document, "status", str, problems)
        status: SnippetStatus | None = None
        if status_value is not None:
            try:
                status = SnippetStatus(status_value)
            except ValueError:
                problems.append(
                    f"unknown status {status_value!r}; expected one of "
                    f"{', '.join(s.value for s in SnippetStatus)}"
                )

        category_value = _require(document, "category", str, problems)
        category: SnippetCategory | None = None
        if category_value is not None:
            try:
                category = SnippetCategory(category_value)
            except ValueError:
                problems.append(
                    f"unknown category {category_value!r}; expected one of "
                    f"{', '.join(c.value for c in SnippetCategory)}"
                )

        implementation = _require(document, "implementation", str, problems)
        if implementation is not None:
            stripped = implementation.strip()
            if not stripped:
                problems.append("field 'implementation' must not be empty")
            elif len(stripped.splitlines()) < MIN_SNIPPET_LINES:
                problems.append(
                    f"field 'implementation' must contain at least {MIN_SNIPPET_LINES} lines; "
                    "a fragment is not a usable pattern"
                )
            offending = [
                number
                for number, line in enumerate(implementation.splitlines(), start=1)
                if line != line.rstrip()
            ]
            if offending:
                # A trailing newline is required; trailing spaces are not. The
                # check is per line because `rstrip()` on the whole string also
                # removes that final newline, which flagged every valid snippet.
                problems.append(
                    f"field 'implementation' has trailing whitespace on line(s) "
                    f"{', '.join(str(number) for number in offending[:5])}"
                )

        dependencies = _require_list(document, "dependencies", problems, min_length=0)
        security_notes = _require_list(document, "security_notes", problems)
        edge_cases = _require_list(document, "edge_cases", problems)
        maintenance_notes = _require_list(document, "maintenance_notes", problems)

        if problems:
            label = identifier or "<unnamed>"
            raise SnippetValidationError(
                f"snippet {label} failed validation with {len(problems)} problem(s)",
                details={"id": label, "problems": problems},
                hint="every field listed in the registry contract is required; see docs/components/snippets.md",
            )

        assert status is not None and category is not None and implementation is not None
        assert version is not None and language is not None
        return cls(
            id=identifier,
            language=language,
            version=version,
            status=status,
            implementation=implementation,
            dependencies=tuple(dependencies),
            security_notes=tuple(security_notes),
            edge_cases=tuple(edge_cases),
            maintenance_notes=tuple(maintenance_notes),
            category=category,
            summary=str(document.get("summary", "")),
            tested_against=tuple(str(item) for item in document.get("tested_against", [])),
            source=str(document.get("source", "")),
        )
