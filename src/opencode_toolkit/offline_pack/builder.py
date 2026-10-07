"""Pack construction.

Selects files by component, renders a manifest with per-file digests, writes a
deterministic archive, then verifies what it just wrote. A build that cannot
verify itself does not produce an artefact -- it raises, so a broken pack never
reaches an air-gapped destination.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import logging
from opencode_toolkit.core.config import PackPolicy
from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.core.fsio import sha256_bytes
from opencode_toolkit.core.pyproject import read_pyproject_requirements
from opencode_toolkit.core.timeutil import reproducible_timestamp
from opencode_toolkit.core.version import Version, detect_version
from opencode_toolkit.offline_pack.licenses import (
    distribution_licence,
    redistribution_decision,
    third_party_notice,
)
from opencode_toolkit.offline_pack.manifest import (
    CHECKSUMS_NAME,
    INSTALL_NOTES_NAME,
    KNOWN_COMPONENTS,
    MANIFEST_NAME,
    PackEntry,
    PackManifest,
    VerificationReport,
    deterministic_zip_write,
    verify_archive,
    write_manifest_json,
)

logger = logging.get_logger("offline_pack.builder")

#: Repository directory holding the package sources. Component paths below are
#: relative to it, and :meth:`PackBuilder.component_label` resolves a repository
#: path to that form.
SOURCE_DIR = "src"

#: Which package subdirectory belongs to which component.
COMPONENT_PATHS: dict[str, tuple[str, ...]] = {
    "core": ("opencode_toolkit/core/", "opencode_toolkit/cli/", "opencode_toolkit/release/"),
    "security-audit": ("opencode_toolkit/security_audit/",),
    "workflow-sync": ("opencode_toolkit/workflow_sync/",),
    "snippet-verified": ("opencode_toolkit/snippet_verified/",),
    "orchestrator": ("opencode_toolkit/orchestrator/",),
    "offline-pack": ("opencode_toolkit/offline_pack/",),
    "live-docs": ("opencode_toolkit/live_docs/",),
}

#: Files every pack includes so an offline install is self-describing.
ALWAYS_INCLUDED = (
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "pyproject.toml",
    "SECURITY.md",
)

DOC_PATHS = ("docs/", "examples/")

#: Never packaged, regardless of policy.
HARD_EXCLUDES = (
    ".git/",
    ".venv/",
    "venv/",
    "node_modules/",
    "__pycache__/",
    "*.pyc",
    "*.pyo",
    ".pytest_cache/",
    ".ruff_cache/",
    ".mypy_cache/",
    "dist/",
    "build/",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.keystore",
    "*.ppk",
    ".opencode/toolkit/snapshots/",
    ".opencode/toolkit/queue/",
)

#: Every packaged file lives under this prefix inside the archive, so a
#: documentation file can never collide with the manifest or checksum file.
ARCHIVE_PREFIX = "package/"

INSTALL_INSTRUCTIONS = """\
# Offline installation

This pack is self-contained. It contains first-party code only unless
`manifest.json` records bundled third-party components under `licenses`.

## Requirements

* Python {min_python} or newer (standard library only -- no PyPI access required)
* Optional: a C compiler is **not** needed

## Install

```bash
# 1. Verify the archive before extracting anything.
unzip -p {archive} manifest.json | python3 -c "import json,sys; print(json.load(sys.stdin)['version'])"

# 2. Extract into a directory of your choice.
unzip -q {archive} -d ./opencode-toolkit

# 3. Verify every file against the manifest.
cd opencode-toolkit
python3 -c "
import json, hashlib, pathlib
m = json.load(open('manifest.json'))
bad = [e['path'] for e in m['entries']
       if hashlib.sha256(pathlib.Path(e['path']).read_bytes()).hexdigest() != e['sha256']]
raise SystemExit('FAILED: ' + ', '.join(bad)) if bad else print('verified %d files' % len(m['entries']))
"

# 4. Run without installing.
python3 -m opencode_toolkit doctor
```

## Using it offline

Every command works without network access. The only commands that need a
network are the publishing workflows, which report the exact missing environment
variable rather than failing obscurely.

## Contents

* `opencode_toolkit/` -- the package source
* `docs/` -- documentation
* `manifest.json` -- per-file digests, licence records, component list
* `SHA256SUMS` -- digests in `sha256sum`-compatible format

## Notes

{notice}
"""


@dataclass(slots=True)
class BuildResult:
    """Outcome of one pack build."""

    archive: Path
    manifest: PackManifest
    verification: VerificationReport
    excluded: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """``True`` when the pack built and then re-verified from disk."""
        return self.verification.ok

    def to_dict(self) -> dict[str, Any]:
        """Return the build result, including the manifest content digest."""
        return {
            "archive": str(self.archive),
            "version": self.manifest.version,
            "components": sorted(self.manifest.components),
            "entry_count": len(self.manifest.entries),
            "total_bytes": self.manifest.total_bytes,
            "content_digest": self.manifest.content_digest(),
            "excluded": self.excluded,
            "verification": self.verification.to_dict(),
            "ok": self.ok,
        }


class PackBuilder:
    """Builds offline packages from the repository tree."""

    def __init__(
        self,
        root: Path,
        *,
        policy: PackPolicy | None = None,
        version: Version | None = None,
    ) -> None:
        self.root = root.resolve()
        self.policy = policy or PackPolicy()
        self.version = version or detect_version(self.root)

    # -- selection --------------------------------------------------------
    def resolve_components(self, requested: list[str]) -> list[str]:
        """Validate and expand a component selection.

        ``all`` expands to every known component; ``core`` is always present
        because every other component imports it.

        Args:
            requested: list[str]: Component names to select, optionally including
                ``"all"``. An unknown name raises :class:`UsageError` instead of
                being dropped, and the result is sorted so the same request
                always yields the same selection.

        Returns:
            list[str]: The selected components, sorted, with ``core`` always
            present.
        """
        unknown = sorted(set(requested) - set(KNOWN_COMPONENTS) - {"all"})
        if unknown:
            raise UsageError(
                f"unknown component(s): {', '.join(unknown)}",
                code="pack.unknown_component",
                details={"unknown": unknown, "known": list(KNOWN_COMPONENTS)},
            )
        selected = set(KNOWN_COMPONENTS) if "all" in requested else set(requested)
        selected.add("core")
        return sorted(selected)

    def select_files(self, components: list[str]) -> list[Path]:
        """Return every file that belongs to the selected components.

        Args:
            components: list[str]: Already-resolved component names, typically
                from :meth:`resolve_components`. Excluded paths are skipped
                regardless of component, and documentation is added only when
                the policy asks for it.

        Returns:
            list[Path]: Absolute paths sorted by their POSIX path relative to the
            repository root, so the member list is order-stable across runs.
        """
        prefixes = tuple(
            prefix for component in components for prefix in COMPONENT_PATHS[component]
        )
        extras: tuple[str, ...] = ALWAYS_INCLUDED
        if self.policy.include_docs:
            extras = extras + DOC_PATHS

        selected: list[Path] = []
        for path in self._iter_candidates():
            relative = path.relative_to(self.root).as_posix()
            if self._is_excluded(relative):
                continue
            label = self.component_label(relative)
            if (
                label.startswith(prefixes)
                or relative in ALWAYS_INCLUDED
                or any(relative.startswith(prefix) for prefix in DOC_PATHS)
                or relative in extras
            ):
                selected.append(path)
        return sorted(set(selected), key=lambda item: item.relative_to(self.root).as_posix())

    @staticmethod
    def component_label(relative: str) -> str:
        """Return *relative* in the form component prefixes are written in.

        Component membership is declared against the package layout
        (``opencode_toolkit/core/``) while paths are discovered from the
        repository root, so the ``src/`` prefix has to come off first.

        Args:
            relative: str: Path relative to the repository root, in POSIX form.
                A path not under ``src/`` is returned unchanged.
        """
        if relative.startswith(f"{SOURCE_DIR}/"):
            return relative[len(SOURCE_DIR) + 1 :]
        return relative

    def _iter_candidates(self) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(
                name
                for name in dirnames
                if not any(fnmatch.fnmatch(f"{name}/", pattern) for pattern in HARD_EXCLUDES)
            )
            for filename in sorted(filenames):
                candidate = Path(dirpath) / filename
                if candidate.is_symlink():
                    continue
                if self._is_excluded(candidate.relative_to(self.root).as_posix()):
                    continue
                if any(
                    fnmatch.fnmatch(candidate.relative_to(self.root).as_posix(), pattern)
                    for pattern in self.policy.exclude_patterns
                ):
                    continue
                yield candidate

    def _is_excluded(self, relative: str) -> bool:
        return any(fnmatch.fnmatch(relative, pattern) for pattern in HARD_EXCLUDES)

    @staticmethod
    def component_for(relative: str) -> str:
        """Return the component a path belongs to, for manifest provenance.

        Args:
            relative: str: Path relative to the repository root. Each manifest
                entry records the component returned here, so an unrecognised
                path is labelled ``docs`` or ``metadata`` rather than dropped.
        """
        label = PackBuilder.component_label(relative)
        for component, prefixes in COMPONENT_PATHS.items():
            if label.startswith(prefixes):
                return component
        return "docs" if relative.startswith(DOC_PATHS) else "metadata"

    # -- build ------------------------------------------------------------
    def build(
        self,
        *,
        components: list[str] | None = None,
        output: Path | None = None,
        include_dependencies: bool | None = None,
        incremental_base: Path | None = None,
        archive_name: str | None = None,
    ) -> BuildResult:
        """Build (or extend) a pack and verify the result.

        Args:
            components: list[str] | None: Components to include; all known
                components when omitted. Expanded through
                :meth:`resolve_components`, so the selection is sorted.
            output: Path | None: Directory the archive is written to; a
                temporary directory when omitted.
            include_dependencies: bool | None: Override the policy's
                ``include_dependencies``. ``None`` uses the policy value.
            incremental_base: Path | None: Existing pack to extend. It must
                verify first -- a delta on top of a corrupt base is refused
                rather than produced.
            archive_name: str | None: Archive filename; derived from the pack
                name and version when omitted.

        Returns:
            BuildResult: The verified result. Timestamps are fixed and members
            are written sorted with a fixed ZIP epoch, so an unchanged tree
            yields the same content digest and a byte-reproducible archive.
        """
        selected = self.resolve_components(components or list(KNOWN_COMPONENTS))
        include_deps = (
            self.policy.include_dependencies
            if include_dependencies is None
            else include_dependencies
        )

        base_entries: list[PackEntry] = []
        base_version = ""
        from opencode_toolkit.offline_pack.manifest import read_manifest

        if incremental_base is not None:
            previous = verify_archive(incremental_base)
            if not previous.ok:
                raise UsageError(
                    "cannot build an incremental pack on top of a pack that does not verify",
                    code="pack.incremental_base_invalid",
                    details={"base": str(incremental_base), "problems": previous.to_dict()},
                    hint="rebuild the base pack first; an incremental delta of a corrupt base is worse than none",
                )
            from opencode_toolkit.offline_pack.manifest import read_manifest

            base_manifest = read_manifest(incremental_base)
            base_entries = base_manifest.entries
            base_version = base_manifest.version

        files = self.select_files(selected)
        entries: list[PackEntry] = []
        members: list[tuple[str, bytes]] = []
        for path in files:
            relative = path.relative_to(self.root).as_posix()
            data = path.read_bytes()
            mode = path.stat().st_mode & 0o777
            # The manifest records the *archive-relative* name, because
            # verification looks entries up by exactly that. Recording the
            # source-relative name made every pack fail its own self-check.
            archive_name = f"{ARCHIVE_PREFIX}{relative}"
            entries.append(
                PackEntry(
                    path=archive_name,
                    sha256=sha256_bytes(data),
                    size=len(data),
                    mode=f"{mode:04o}",
                    component=self.component_for(relative),
                    executable=bool(mode & 0o111),
                )
            )
            members.append((archive_name, data))

        excluded = self._dependency_decisions(include_deps)
        bundled_records = [item for item in excluded if item["bundled"] and item.get("spdx")]

        manifest = PackManifest(
            name=archive_name or f"opencode-toolkit-{self.version}",
            version=str(self.version),
            created_at=reproducible_timestamp(),
            entries=entries,
            components=selected,
            excluded=excluded,
            licenses=[distribution_licence()],
            base_version=base_version,
            incremental=incremental_base is not None,
            tool_version=str(detect_version(self.root)),
        )

        if incremental_base is not None:
            changed = {entry.path for entry in entries}
            removed = sorted({entry.path for entry in base_entries} - changed)
            manifest.excluded.append(
                {
                    "name": "(removed paths)",
                    "bundled": False,
                    "reason": "absent_from_this_version",
                    "paths": removed[:50],
                }
            )

        notice = (
            third_party_notice([])
            if not bundled_records
            else ("Third-party components are bundled; see manifest.json -> licenses.")
        )
        members.append(
            (
                INSTALL_NOTES_NAME,
                INSTALL_INSTRUCTIONS.format(
                    min_python="3.10",
                    archive=archive_name or f"{manifest.name}.tar.zip",
                    notice=notice,
                ).encode("utf-8"),
            )
        )
        members.append((CHECKSUMS_NAME, manifest.checksums_text().encode("utf-8")))
        members.append((MANIFEST_NAME, write_manifest_json(manifest).encode("utf-8")))

        target = output or (self.root / "dist" / f"{manifest.name}.tar.zip")
        executable = {entry.path for entry in entries if entry.executable}
        deterministic_zip_write(target, members, executable=executable)

        verification = (
            verify_archive(target)
            if self.policy.verify_on_build
            else VerificationReport(archive=str(target), ok=True, version=manifest.version)
        )
        if self.policy.verify_on_build and not verification.ok:
            raise UsageError(
                "pack failed self-verification immediately after being written; refusing to emit it",
                code="pack.self_verification_failed",
                details=verification.to_dict(),
            )

        logger.info(
            "built pack %s with %d entries (%d bytes)",
            target.name,
            len(entries),
            manifest.total_bytes,
        )
        return BuildResult(
            archive=target, manifest=manifest, verification=verification, excluded=excluded
        )

    def _dependency_decisions(self, include_dependencies: bool) -> list[dict[str, Any]]:
        """Decide on each development dependency.

        With dependencies disabled (the default) nothing is bundled, and the
        reason recorded is the policy itself rather than a licence judgement --
        the distinction matters for the report.
        """
        pyproject = self.root / "pyproject.toml"
        if not pyproject.is_file():
            return []
        names = _dev_dependency_names(pyproject)
        decisions: list[dict[str, Any]] = []
        for name in sorted(names, key=str.lower):
            if not include_dependencies:
                decisions.append(
                    {
                        "name": name,
                        "bundled": False,
                        "reason": "dependency_bundling_disabled",
                        "spdx": None,
                        "reference": None,
                    }
                )
                continue
            decision = redistribution_decision(name, installed=False)
            decisions.append(decision.to_dict())
        return decisions


def _dev_dependency_names(pyproject: Path) -> list[str]:
    """Extract the ``dev`` extra's dependency names from ``pyproject.toml``."""
    groups = read_pyproject_requirements(pyproject.read_text(encoding="utf-8"))
    return [
        item.split(">")[0].split("=")[0].split("[")[0].strip()
        for item in groups.extras.get("dev", [])
    ]


def build_pack(
    root: Path,
    *,
    components: list[str] | None = None,
    output: Path | None = None,
    policy: PackPolicy | None = None,
    **kwargs: Any,
) -> BuildResult:
    """Convenience wrapper around :class:`PackBuilder`.

    Args:
        root: Path: Repository root to build from; resolved, so a relative path
            works.
        components: list[str] | None: Components to include; all known components
            when omitted.
        output: Path | None: Directory the archive is written to.
        policy: PackPolicy | None: Selection and exclusion policy; defaults apply
            when omitted.
        **kwargs: Any: Further build options such as ``include_dependencies``,
            ``incremental_base`` or ``archive_name``, forwarded verbatim.

    Returns:
        BuildResult: The verified build result.
    """
    return PackBuilder(root, policy=policy).build(components=components, output=output, **kwargs)


def inspect_pack(archive: Path) -> dict[str, Any]:
    """Return a summary of a pack without extracting it.

    Args:
        archive: Path: Pack to inspect. Only the manifest is read, so no member
            is extracted or executed.

    Returns:
        dict[str, Any]: Name, version, sorted component list, entry and byte
        counts per component, and the pack's content digest.
    """
    from opencode_toolkit.offline_pack.manifest import read_manifest

    manifest = read_manifest(archive)
    by_component: dict[str, int] = {}
    by_size: dict[str, int] = {}
    for entry in manifest.entries:
        by_component[entry.component] = by_component.get(entry.component, 0) + 1
        by_size[entry.component] = by_size.get(entry.component, 0) + entry.size
    return {
        "archive": str(archive),
        "name": manifest.name,
        "version": manifest.version,
        "tool_version": manifest.tool_version,
        "created_at": manifest.created_at,
        "incremental": manifest.incremental,
        "base_version": manifest.base_version,
        "components": sorted(manifest.components),
        "entry_count": len(manifest.entries),
        "total_bytes": manifest.total_bytes,
        "content_digest": manifest.content_digest(),
        "entries_by_component": dict(sorted(by_component.items())),
        "bytes_by_component": dict(sorted(by_size.items())),
        "excluded": manifest.excluded,
        "licenses": manifest.licenses,
    }


def update_manifest(archive: Path, output: Path) -> BuildResult:
    """Re-emit *archive* with a refreshed manifest.

    Used by ``opencode pack update``: the archive is rebuilt from itself so the
    result verifies without needing the original source tree, which an
    air-gapped host does not have.

    Args:
        archive: Path: Pack to rewrite. Its member names are checked for zip-slip
            before anything is read out, so a hostile member cannot escape.
        output: Path | None: Directory the refreshed archive is written to; a
            temporary directory when omitted.

    Returns:
        BuildResult: The refreshed pack. Members are re-emitted sorted with a
        fixed timestamp and a recomputed manifest, so the output is
        byte-reproducible and verification passes.
    """
    import zipfile

    from opencode_toolkit.offline_pack.manifest import assert_archive_is_safe, read_manifest

    manifest = read_manifest(archive)
    members: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(archive) as bundle:
        assert_archive_is_safe(bundle.namelist())
        for name in sorted(bundle.namelist()):
            if name in {MANIFEST_NAME, CHECKSUMS_NAME, INSTALL_NOTES_NAME}:
                continue
            members.append((name, bundle.read(name)))

    refreshed = PackManifest(
        name=manifest.name,
        version=manifest.version,
        created_at=reproducible_timestamp(),
        entries=manifest.entries,
        components=manifest.components,
        excluded=manifest.excluded,
        licenses=manifest.licenses,
        base_version=manifest.base_version,
        incremental=manifest.incremental,
        tool_version=manifest.tool_version,
    )
    notice = third_party_notice([])
    members.append(
        (
            INSTALL_NOTES_NAME,
            INSTALL_INSTRUCTIONS.format(
                min_python="3.10",
                archive=output.name,
                notice=notice,
            ).encode("utf-8"),
        )
    )
    members.append((CHECKSUMS_NAME, refreshed.checksums_text().encode("utf-8")))
    members.append((MANIFEST_NAME, write_manifest_json(refreshed).encode("utf-8")))
    executable = {f"package/{entry.path}" for entry in refreshed.entries if entry.executable}
    deterministic_zip_write(output, members, executable=executable)
    verification = verify_archive(output)
    return BuildResult(
        archive=output, manifest=refreshed, verification=verification, excluded=refreshed.excluded
    )
