"""Documentation drift detection and conservative repair.

Two halves:

* :mod:`scanner` -- extract the public API surface from source (Python precisely,
  via the AST; other languages heuristically, and labelled as such).
* :mod:`updater` -- rewrite only the machine-maintainable sections of a
  docstring (the ``Args:``/``Returns:``/``Raises:`` blocks) and leave every line
  of human prose byte-identical.

The updater never reformats a docstring it cannot fully understand. When a
docstring has no parameter block, or its prose would be touched, the file is
reported as ``needs_review`` rather than rewritten.
"""

from __future__ import annotations

from opencode_toolkit.live_docs.drift import DriftItem, DriftReport, diff_against_baseline
from opencode_toolkit.live_docs.scanner import ApiSurface, scan_tree
from opencode_toolkit.live_docs.updater import UpdateResult, apply_updates

__all__ = [
    "ApiSurface",
    "DriftItem",
    "DriftReport",
    "UpdateResult",
    "apply_updates",
    "diff_against_baseline",
    "scan_tree",
]
