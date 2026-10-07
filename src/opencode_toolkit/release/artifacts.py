"""Release artefacts.

Produces, from the built distribution:

* a source archive (``sdist``)
* the built wheel
* the offline pack
* a CycloneDX 1.5 SBOM in JSON
* ``SHA256SUMS`` over everything above
* a documentation bundle

Every checksum is computed from bytes that were actually written. Nothing here
fabricates a digest: if an artefact is missing, the build fails.
"""

from __future__ import annotations

import gzip
import io
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio, logging
from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.core.fsio import ensure_dir, sha256_file
from opencode_toolkit.core.timeutil import utc_now
from opencode_toolkit.core.version import Version, detect_version
from opencode_toolkit.offline_pack.builder import PackBuilder
from opencode_toolkit.release.sbom import build_sbom

logger = logging.get_logger("release.artifacts")

SDIST_NAME = "opencode-toolkit-sdist.tar.gz"
WHEEL_GLOB = "*.whl"
DOC_BUNDLE_NAME = "documentation.tar.gz"

#: Files always shipped in the documentation bundle.
DOC_FILES = ("README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "LICENSE")


@dataclass(slots=True)
class Artifact:
    """One produced artefact."""

    name: str
    path: Path
    size: int
    sha256: str
    kind: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the artefact."""
        return {
            "name": self.name,
            "path": str(self.path),
            "size": self.size,
            "sha256": self.sha256,
            "kind": self.kind,
            "note": self.note,
        }


@dataclass(slots=True)
class ArtifactSet:
    """Everything produced by one release build."""

    version: Version
    directory: Path
    artifacts: list[Artifact] = field(default_factory=list)
    build_log: list[str] = field(default_factory=list)

    def add(self, artifact: Artifact) -> Artifact:
        """Append *artifact* and return it, so callers can inline construction.

        Args:
            artifact: Artifact: The artefact to record, with its digest already computed.
        """
        self.artifacts.append(artifact)
        return artifact

    def by_kind(self, kind: str) -> list[Artifact]:
        """Return every artefact of *kind*, in the order they were added.

        Args:
            kind: str: Artefact kind to filter on, e.g. ``wheel`` or ``offline-pack``.
        """
        return [artifact for artifact in self.artifacts if artifact.kind == kind]

    def checksums_text(self) -> str:
        """Return ``SHA256SUMS`` content, sorted by artefact name.

        Uses the two-space ``sha256sum`` format and a trailing newline so the
        file can be checked with ``sha256sum --check`` directly.
        """
        lines = [
            f"{artifact.sha256}  {artifact.path.name}"
            for artifact in sorted(self.artifacts, key=lambda a: a.name)
        ]
        return "\n".join(lines) + ("\n" if lines else "")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable index of the build.

        Artefacts are sorted by name so two builds of the same tree produce the
        same index byte-for-byte.
        """
        return {
            "version": str(self.version),
            "directory": str(self.directory),
            "artifact_count": len(self.artifacts),
            "total_bytes": sum(artifact.size for artifact in self.artifacts),
            "artifacts": [
                artifact.to_dict() for artifact in sorted(self.artifacts, key=lambda a: a.name)
            ],
            "build_log": list(self.build_log),
        }


def build_artifacts(
    root: Path,
    output: Path,
    *,
    version: Version | None = None,
    skip_python_build: bool = False,
    include_pack: bool = True,
    pack_policy: Any | None = None,
) -> ArtifactSet:
    """Build every release artefact into *output*.

    Args:
        root: Path: Project root to build from.
        output: Path: Directory to write artefacts into; created if absent.
        version: Version | None: Version being released; detected from ``pyproject.toml`` if omitted.
        skip_python_build: bool: Skip the wheel build and log it in the build log.
        include_pack: bool: Also build the offline pack; a failed verification aborts.
        pack_policy: Any | None: Policy for the offline pack, e.g. :class:`PackPolicy`.
    """
    root = root.resolve()
    output = ensure_dir(output)
    resolved = version or detect_version(root)
    artifacts = ArtifactSet(version=resolved, directory=output)

    source_archive = output / SDIST_NAME
    _build_sdist(root, source_archive)
    artifacts.add(
        Artifact(
            name=source_archive.name,
            path=source_archive,
            size=source_archive.stat().st_size,
            sha256=sha256_file(source_archive),
            kind="source-archive",
            note="deterministic source distribution",
        )
    )

    if skip_python_build:
        artifacts.build_log.append("SKIPPED: python distribution build was explicitly disabled")
    else:
        wheel = _build_wheel(root, output, artifacts)
        if wheel is not None:
            artifacts.add(
                Artifact(
                    name=wheel.name,
                    path=wheel,
                    size=wheel.stat().st_size,
                    sha256=sha256_file(wheel),
                    kind="wheel",
                    note="Python wheel built from the verified source tree",
                )
            )

    if include_pack:
        builder = PackBuilder(root, version=resolved, policy=pack_policy)
        pack_path = output / f"opencode-toolkit-{resolved}-offline.zip"
        result = builder.build(output=pack_path)
        if not result.ok:
            raise UsageError(
                "offline pack failed verification; refusing to include it in the release",
                code="release.pack_failed",
                details=result.verification.to_dict(),
            )
        artifacts.add(
            Artifact(
                name=pack_path.name,
                path=pack_path,
                size=pack_path.stat().st_size,
                sha256=sha256_file(pack_path),
                kind="offline-pack",
                note=f"{len(result.manifest.entries)} files, content digest {result.manifest.content_digest()[:16]}",
            )
        )
        artifacts.build_log.append(
            f"offline pack verified: {result.verification.entries_checked} entries checked"
        )

    sbom_path = output / "sbom.cdx.json"
    sbom_path.write_text(build_sbom(root, version=resolved), encoding="utf-8")
    artifacts.add(
        Artifact(
            name=sbom_path.name,
            path=sbom_path,
            size=sbom_path.stat().st_size,
            sha256=sha256_file(sbom_path),
            kind="sbom",
            note="CycloneDX 1.5, runtime component closure",
        )
    )

    docs_path = output / DOC_BUNDLE_NAME
    _build_doc_bundle(root, docs_path)
    artifacts.add(
        Artifact(
            name=docs_path.name,
            path=docs_path,
            size=docs_path.stat().st_size,
            sha256=sha256_file(docs_path),
            kind="documentation",
            note="documentation bundle",
        )
    )

    checksums = output / "SHA256SUMS"
    checksums.write_text(artifacts.checksums_text(), encoding="utf-8")
    artifacts.build_log.append(
        f"wrote {len(artifacts.artifacts)} artefact checksums to {checksums.name}"
    )

    index = output / "artifacts.json"
    jsonio.write(index, artifacts.to_dict())
    return artifacts


def _build_sdist(root: Path, target: Path) -> None:
    """Build a deterministic source archive without invoking setuptools.

    Using ``tarfile`` directly keeps the release independent of whether the
    ``build`` package is installed, which matters for the air-gapped path.
    """
    include_roots = ("src", "docs", "examples", "scripts", "tests", ".github", ".changes")
    include_files = (
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "pyproject.toml",
    )

    members: list[tuple[str, bytes]] = []
    for name in include_roots:
        base = root / name
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            if any(
                part in {"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
                for part in path.parts
            ):
                continue
            if path.suffix in {".pyc", ".pyo"}:
                continue
            members.append((path.relative_to(root).as_posix(), path.read_bytes()))
    for name in include_files:
        path = root / name
        if path.is_file():
            members.append((name, path.read_bytes()))

    prefix = f"opencode-toolkit-{detect_version(root)}"
    # GzipFile(mtime=0) rather than tarfile's "w:gz" shorthand: the shorthand
    # stamps the *current* time into the gzip header, so two builds a second
    # apart produce different bytes and the reproducibility check fails for a
    # reason that has nothing to do with the content.
    with (
        target.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle,
    ):
        for name, data in members:
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o755 if data[:2] == b"#!" else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            bundle.addfile(info, io.BytesIO(data))


def _build_wheel(root: Path, output: Path, artifacts: ArtifactSet) -> Path | None:
    """Build the wheel with ``python -m build``; report honestly when unavailable."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            # sys.executable rather than a bare "python3": the build must use the
            # same interpreter the release is being cut with.
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(output), str(root)],
            capture_output=True,
            text=True,
            check=False,
            timeout=900,
        )
    except FileNotFoundError:
        artifacts.build_log.append("SKIPPED: wheel build -- python -m build is not installed")
        return None
    except subprocess.TimeoutExpired:
        artifacts.build_log.append("FAILED: wheel build exceeded 900s")
        return None
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()[-5:]
        artifacts.build_log.append(
            f"FAILED: wheel build exited {completed.returncode}: {' | '.join(tail)}"
        )
        return None
    wheels = sorted(output.glob(WHEEL_GLOB))
    if not wheels:
        artifacts.build_log.append("FAILED: wheel build produced no wheel")
        return None
    artifacts.build_log.append(f"built wheel {wheels[-1].name}")
    return wheels[-1]


def _build_doc_bundle(root: Path, target: Path) -> None:
    with tarfile.open(target, "w:gz", format=tarfile.PAX_FORMAT) as bundle:
        for directory in ("docs", "examples"):
            base = root / directory
            if not base.is_dir():
                continue
            for path in sorted(base.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                info = tarfile.TarInfo(path.relative_to(root).as_posix())
                data = path.read_bytes()
                info.size = len(data)
                info.mtime = 0
                info.mode = 0o644
                bundle.addfile(info, io.BytesIO(data))
        for name in DOC_FILES:
            path = root / name
            if not path.is_file():
                continue
            info = tarfile.TarInfo(name)
            data = path.read_bytes()
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            bundle.addfile(info, io.BytesIO(data))


def verify_artifacts(artifacts: ArtifactSet) -> dict[str, Any]:
    """Re-read every artefact and confirm its recorded digest still matches.

    Args:
        artifacts: ArtifactSet: The recorded build to re-check against the files on disk.
    """
    mismatched: list[str] = []
    missing: list[str] = []
    for artifact in artifacts.artifacts:
        if not artifact.path.is_file():
            missing.append(artifact.name)
            continue
        if sha256_file(artifact.path) != artifact.sha256:
            mismatched.append(artifact.name)
    return {
        "ok": not mismatched and not missing,
        "missing": missing,
        "mismatched": mismatched,
        "checked": len(artifacts.artifacts),
        "checked_at": utc_now(),
    }


def clean(directory: Path) -> None:
    """Remove a previous build directory, refusing to touch anything else.

    Args:
        directory: Path: Build directory to delete; a filesystem root is refused.
    """
    if not directory.is_dir():
        return
    if directory.resolve() == Path(directory.anchor):  # pragma: no cover - defensive
        raise UsageError("refusing to clean a filesystem root")
    shutil.rmtree(directory)
    logger.info("cleaned %s", directory)
