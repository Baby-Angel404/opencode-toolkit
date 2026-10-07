"""Release engineering: versioning, changelog, artefacts, SBOM and the gate.

The **release gate** is the load-bearing piece. It is a machine-readable record
of every mandatory check with an explicit status. A check that did not run is
recorded as ``NOT_RUN``, which the gate treats exactly like ``FAIL``. That
distinction is the whole point: a pipeline step that was skipped by a bug in the
workflow must not be able to produce an approved release.

Publishing cannot bypass the gate -- see :mod:`opencode_toolkit.release.gate`,
which the Hugging Face and Kaggle workflows both consume.
"""

from __future__ import annotations

from opencode_toolkit.release.artifacts import ArtifactSet, build_artifacts
from opencode_toolkit.release.changelog import changelog_markdown, changelog_unreleased
from opencode_toolkit.release.gate import (
    CHECK_NAMES,
    CheckStatus,
    GateResult,
    ReleaseGate,
    load_gate,
    write_gate,
)
from opencode_toolkit.release.sbom import build_sbom, sbom_document
from opencode_toolkit.release.version import bump_version, current_version, update_version_files

__all__ = [
    "CHECK_NAMES",
    "ArtifactSet",
    "CheckStatus",
    "GateResult",
    "ReleaseGate",
    "build_artifacts",
    "build_sbom",
    "bump_version",
    "changelog_markdown",
    "changelog_unreleased",
    "current_version",
    "load_gate",
    "sbom_document",
    "update_version_files",
    "write_gate",
]
