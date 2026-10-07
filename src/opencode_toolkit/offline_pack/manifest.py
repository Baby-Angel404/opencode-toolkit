"""Pack manifest and verification.

The manifest is the single source of truth for a pack's contents. Verification
re-reads the archive and recomputes every digest; it does not trust the manifest,
it only checks the archive against it.

A deterministic archive is built here rather than relying on the platform's zip
defaults: entries are sorted, timestamps are pinned to the toolkit version's
release epoch, and permissions are normalised. Two builds of the same tree at the
same version produce byte-identical archives.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio
from opencode_toolkit.core.errors import IntegrityError, StateError
from opencode_toolkit.core.fsio import sha256_bytes
from opencode_toolkit.core.version import detect_version

MANIFEST_NAME = "manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
INSTALL_NOTES_NAME = "INSTALL.md"

MANIFEST_KIND = "opencode-toolkit/pack-manifest"
MANIFEST_SCHEMA = 1

#: Fixed timestamp for archive entries so builds are byte-reproducible.
#: 1980-01-01 00:00:00 is the earliest value the zip format can represent.
REPRODUCIBLE_EPOCH = (1980, 1, 1, 0, 0, 0)

#: Components that may be selected into a pack.
KNOWN_COMPONENTS = (
    "core",
    "security-audit",
    "workflow-sync",
    "snippet-verified",
    "orchestrator",
    "offline-pack",
    "live-docs",
)


@dataclass(frozen=True, slots=True)
class PackEntry:
    """One file inside a pack."""

    path: str
    sha256: str
    size: int
    mode: str = "0644"
    component: str = "core"
    executable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return the entry as JSON-serialisable data."""
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
            "component": self.component,
            "executable": self.executable,
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> PackEntry:
        """Build an entry from one manifest object.

        Args:
            document: dict[str, Any]: One object from the manifest's ``entries``
                list. ``path``, ``sha256`` and ``size`` are required; ``mode``,
                ``component`` and ``executable`` fall back to ``0644``, ``core``
                and ``False``. The digest is stored, not recomputed here --
                verification recomputes it from the archive bytes.

        Raises:
            StateError: A required field is missing or malformed.
        """
        try:
            return cls(
                path=str(document["path"]),
                sha256=str(document["sha256"]),
                size=int(document["size"]),
                mode=str(document.get("mode", "0644")),
                component=str(document.get("component", "core")),
                executable=bool(document.get("executable", False)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise StateError(
                f"malformed pack entry: {exc}", details={"reason": type(exc).__name__}
            ) from exc


@dataclass(slots=True)
class PackManifest:
    """Everything needed to verify and install a pack."""

    name: str
    version: str
    created_at: str
    entries: list[PackEntry] = field(default_factory=list)
    components: list[str] = field(default_factory=list)
    excluded: list[dict[str, Any]] = field(default_factory=list)
    licenses: list[dict[str, Any]] = field(default_factory=list)
    base_version: str = ""
    incremental: bool = False
    tool_version: str = ""

    @property
    def total_bytes(self) -> int:
        """Return the summed uncompressed size of every entry."""
        return sum(entry.size for entry in self.entries)

    def content_digest(self) -> str:
        """One digest over the sorted entry list -- the pack's identity."""
        material = "\n".join(
            f"{entry.path}:{entry.sha256}:{entry.size}"
            for entry in sorted(self.entries, key=lambda e: e.path)
        )
        return sha256_bytes(material.encode("utf-8"))

    def to_dict(self) -> dict[str, Any]:
        """Return the full manifest document."""
        return {
            "kind": MANIFEST_KIND,
            "schema": MANIFEST_SCHEMA,
            "name": self.name,
            "version": self.version,
            "tool_version": self.tool_version or str(detect_version()),
            "created_at": self.created_at,
            "components": sorted(self.components),
            "base_version": self.base_version,
            "incremental": self.incremental,
            "entry_count": len(self.entries),
            "total_bytes": self.total_bytes,
            "content_digest": self.content_digest(),
            "entries": [entry.to_dict() for entry in sorted(self.entries, key=lambda e: e.path)],
            "excluded": self.excluded,
            "licenses": self.licenses,
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> PackManifest:
        """Parse a manifest document, rejecting a foreign or stale one.

        Args:
            document: dict[str, Any]: A decoded ``opencode-toolkit.json``. Both
                ``kind`` and ``schema`` must match exactly, so a manifest from a
                different tool or a future schema is refused instead of being
                partially interpreted.

        Raises:
            StateError: The document is not a manifest, or its schema is newer
                or older than this build understands. Guessing at an unknown
                schema could silently skip verification.
        """
        if document.get("kind") != MANIFEST_KIND:
            raise StateError(
                "not an opencode-toolkit pack manifest",
                code="pack.not_a_manifest",
                details={"found_kind": document.get("kind"), "expected": MANIFEST_KIND},
            )
        schema = document.get("schema")
        if schema != MANIFEST_SCHEMA:
            raise StateError(
                f"unsupported manifest schema {schema!r}; this build understands {MANIFEST_SCHEMA}",
                code="pack.schema_mismatch",
                details={"schema": schema, "supported": MANIFEST_SCHEMA},
            )
        raw_entries = document.get("entries")
        if not isinstance(raw_entries, list):
            raise StateError("manifest 'entries' must be a list", code="pack.invalid_manifest")
        return cls(
            name=str(document.get("name", "pack")),
            version=str(document.get("version", "0.0.0")),
            created_at=str(document.get("created_at", "")),
            entries=[PackEntry.from_dict(item) for item in raw_entries],
            components=[str(item) for item in document.get("components", [])],
            excluded=list(document.get("excluded", [])),
            licenses=list(document.get("licenses", [])),
            base_version=str(document.get("base_version", "")),
            incremental=bool(document.get("incremental", False)),
            tool_version=str(document.get("tool_version", "")),
        )

    def checksums_text(self) -> str:
        """Render the ``SHA256SUMS`` body (excluding the manifest itself)."""
        lines = [
            f"{entry.sha256}  {entry.path}" for entry in sorted(self.entries, key=lambda e: e.path)
        ]
        return "\n".join(lines) + ("\n" if lines else "")


@dataclass(slots=True)
class VerificationReport:
    """Result of verifying a pack."""

    archive: str
    ok: bool
    entries_checked: int = 0
    missing: list[str] = field(default_factory=list)
    mismatched: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    manifest_digest: str = ""
    version: str = ""
    components: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return the verification outcome as JSON-serialisable data."""
        return {
            "archive": self.archive,
            "ok": self.ok,
            "version": self.version,
            "components": sorted(self.components),
            "entries_checked": self.entries_checked,
            "manifest_digest": self.manifest_digest,
            "missing": sorted(self.missing),
            "mismatched": sorted(self.mismatched),
            "unexpected": sorted(self.unexpected),
            "errors": list(self.errors),
        }


def write_manifest_json(manifest: PackManifest) -> str:
    """Serialise a manifest deterministically.

    Args:
        manifest: PackManifest: Manifest to render. Components and entries are
            emitted sorted by name, so the same pack yields byte-identical JSON
            on every run; ``created_at`` must already be a fixed timestamp from
            the builder's reproducible clock.

    Returns:
        str: The manifest JSON text with a two-space indent and a trailing
        newline, ready to write into the archive.
    """
    return jsonio.dumps(manifest.to_dict(), indent=2) + "\n"


def read_manifest(archive: Path) -> PackManifest:
    """Extract and parse the manifest from a pack archive.

    Args:
        archive: Path: ZIP file to read. A missing ``opencode-toolkit.json``
            raises :class:`StateError` and a file that is not a readable ZIP
            raises :class:`IntegrityError`.

    Returns:
        PackManifest: The parsed manifest, checked against the current kind and
        schema before any digest is trusted.
    """
    try:
        with zipfile.ZipFile(archive) as bundle:
            try:
                raw = bundle.read(MANIFEST_NAME)
            except KeyError as exc:
                raise StateError(
                    f"pack {archive.name} has no {MANIFEST_NAME}",
                    code="pack.missing_manifest",
                    details={"archive": str(archive)},
                ) from exc
    except zipfile.BadZipFile as exc:
        raise IntegrityError(
            f"{archive} is not a readable ZIP archive: {exc}",
            details={"archive": str(archive)},
        ) from exc
    return PackManifest.from_dict(jsonio.loads(raw.decode("utf-8"), source=str(archive)))


def verify_archive(archive: Path) -> VerificationReport:
    """Recompute every digest in the archive and compare against the manifest.

    Args:
        archive: Path: ZIP file to verify. Every declared entry must be present
            with a matching digest and size, ``SHA256SUMS`` must match the
            manifest body it mirrors, and any member not declared in the manifest
            is reported as unexpected.

    Returns:
        VerificationReport: The outcome, with ``ok`` true only when nothing is
        missing, mismatched, unexpected or inconsistent. An undeclared file fails
        verification rather than being ignored.
    """
    manifest = read_manifest(archive)
    report = VerificationReport(
        archive=str(archive),
        ok=False,
        manifest_digest=manifest.content_digest(),
        version=manifest.version,
        components=list(manifest.components),
    )

    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        for entry in manifest.entries:
            if entry.path not in names:
                report.missing.append(entry.path)
                continue
            try:
                data = bundle.read(entry.path)
            except KeyError:  # pragma: no cover - name was present a moment ago
                report.missing.append(entry.path)
                continue
            actual = sha256_bytes(data)
            if actual != entry.sha256:
                report.mismatched.append(entry.path)
            elif entry.size != len(data):
                report.mismatched.append(f"{entry.path} (size {entry.size} != {len(data)})")
            else:
                report.entries_checked += 1
        declared = {entry.path for entry in manifest.entries}
        allowed = declared | {MANIFEST_NAME, CHECKSUMS_NAME, INSTALL_NOTES_NAME}
        report.unexpected = sorted(names - allowed)

    # The SHA256SUMS file must agree with the manifest body it mirrors.
    with zipfile.ZipFile(archive) as bundle:
        if CHECKSUMS_NAME in bundle.namelist():
            body = bundle.read(CHECKSUMS_NAME).decode("utf-8")
            if body != manifest.checksums_text():
                report.errors.append("SHA256SUMS does not match the manifest entries")

    report.ok = (
        not report.missing and not report.mismatched and not report.unexpected and not report.errors
    )
    return report


def assert_archive_is_safe(names: Iterable[str]) -> None:
    """Reject archive member names that would escape the extraction directory.

    Zip-slip protection. Even though only this tool's own packs are opened, a
    pack is an untrusted file the moment it arrives from a transfer.

    Args:
        names: Iterable[str]: Archive member paths, checked before extraction.
            Absolute paths and any member containing ``..`` raise
            :class:`IntegrityError`.
    """
    for name in names:
        normalised = Path(name)
        if normalised.is_absolute() or ".." in normalised.parts:
            raise IntegrityError(
                f"unsafe archive member path: {name}",
                details={"member": name},
                hint="the archive is malformed or hostile; do not extract it",
            )


def deterministic_zip_write(
    target: Path, members: list[tuple[str, bytes]], *, executable: set[str] | None = None
) -> None:
    """Write *members* to *target* as a byte-reproducible ZIP.

    Args:
        target: Path: Archive to create; parent directories are created as
            needed and any existing file is overwritten.
        members: list[tuple[str, bytes]]: ``(name, data)`` pairs to write. They
            are sorted by name and stamped with a fixed timestamp, so identical
            input produces a byte-identical archive.
        executable: set[str] | None: Member names to store with mode ``0755``;
            every other member gets ``0644``. ``None`` means nothing executable.
    """
    executable = executable or set()
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, data in sorted(members, key=lambda item: item[0]):
            info = zipfile.ZipInfo(filename=name, date_time=REPRODUCIBLE_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            external_attr = (0o755 if name in executable else 0o644) << 16
            info.external_attr = external_attr
            bundle.writestr(info, data)
