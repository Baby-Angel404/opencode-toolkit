"""Verifiable offline packages.

A pack is a deterministic ZIP containing selected components, documentation, and
a signed-by-digest manifest. ``verify`` re-derives every checksum from the
archive itself, so a pack that was tampered with on the way to an air-gapped host
fails verification rather than installing.

Licensing is handled explicitly. Third-party code is only bundled when the
curated table below says its licence permits redistribution; anything unknown is
*excluded* and recorded as excluded. The pack never asserts a licence it has not
verified.
"""

from __future__ import annotations

from opencode_toolkit.offline_pack.builder import PackBuilder, build_pack
from opencode_toolkit.offline_pack.licenses import (
    LICENSE_POLICY,
    LicenseRecord,
    licence_for,
    redistribution_decision,
)
from opencode_toolkit.offline_pack.manifest import (
    MANIFEST_NAME,
    PackEntry,
    PackManifest,
    VerificationReport,
)

__all__ = [
    "LICENSE_POLICY",
    "MANIFEST_NAME",
    "LicenseRecord",
    "PackBuilder",
    "PackEntry",
    "PackManifest",
    "VerificationReport",
    "build_pack",
    "licence_for",
    "redistribution_decision",
]
