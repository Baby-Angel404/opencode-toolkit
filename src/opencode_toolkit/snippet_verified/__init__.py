"""Registry of reviewed, production-oriented code patterns.

A snippet is not "example code that runs". Each entry carries a status, a
compatibility statement, security notes that name the actual failure modes, and
edge cases -- so a reader can decide whether it fits before copying it.

Status is a first-class field and the registry refuses to serve ``deprecated``
snippets to ``snippet add`` without an explicit acknowledgement.
"""

from __future__ import annotations

from opencode_toolkit.snippet_verified.models import (
    Snippet,
    SnippetCategory,
    SnippetStatus,
    SnippetValidationError,
)
from opencode_toolkit.snippet_verified.registry import (
    SnippetRegistry,
    default_registry,
    load_registry,
)

__all__ = [
    "Snippet",
    "SnippetCategory",
    "SnippetRegistry",
    "SnippetStatus",
    "SnippetValidationError",
    "default_registry",
    "load_registry",
]
