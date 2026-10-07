"""Kaggle publishing.

Kaggle Datasets are file bundles with a ``dataset-metadata.json`` file, which is
the right fit for a distributable release of this project. The API requires HTTP
Basic authentication with a username and key.

Requires ``KAGGLE_USERNAME`` and ``KAGGLE_KEY``. Either being absent produces a
``SKIP PUBLISH`` naming both variables. Neither value is ever logged.

The upload uses ``urllib`` rather than the ``kaggle`` CLI: the CLI's behaviour
and error reporting vary by version, and pinning our own HTTP call makes the
verification step reproducible.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import logging
from opencode_toolkit.core.errors import ConfigurationError, NetworkError
from opencode_toolkit.core.gitmeta import head_commit
from opencode_toolkit.core.version import Version, detect_version
from opencode_toolkit.publishing.artifacts import assert_clean
from opencode_toolkit.publishing.classify import (
    KAGGLE_KEY_ENV,
    KAGGLE_USERNAME_ENV,
    missing_credentials,
)
from opencode_toolkit.release.gate import GateResult

logger = logging.get_logger("publishing.kaggle")

KAGGLE_API = "https://www.kaggle.com/api/v1"

#: Where the full source and documentation live. The bundle is a release, not the
#: project, so the card has to say where the rest of it is.
DEFAULT_REPO_URL = "https://github.com/Baby-Angel404/opencode-toolkit"

METADATA_FILENAME = "dataset-metadata.json"
REQUIRED_METADATA_KEYS = ("title", "id", "licenses", "keywords")

STATUS_PUBLISHED = "PUBLISHED"
STATUS_SKIPPED = "SKIPPED"
STATUS_BLOCKED = "BLOCKED"
STATUS_FAILED = "FAILED"
STATUS_PUBLISHED_BUT_VERIFICATION_FAILED = "PUBLISHED_BUT_VERIFICATION_FAILED"


@dataclass(slots=True)
class KaggleResult:
    """Outcome of a Kaggle publish attempt."""

    status: str
    dataset_ref: str = ""
    reason: str = ""
    missing_configuration: list[str] = field(default_factory=list)
    verification: dict[str, Any] = field(default_factory=dict)
    file_count: int = 0

    @property
    def succeeded(self) -> bool:
        """``True`` only for a fully published and verified dataset."""
        return self.status == STATUS_PUBLISHED

    def to_dict(self) -> dict[str, Any]:
        """Return the publish result as JSON-serialisable data."""
        return {
            "platform": "kaggle",
            "status": self.status,
            "dataset_ref": self.dataset_ref,
            "reason": self.reason,
            "missing_configuration": list(self.missing_configuration),
            "verification": self.verification,
            "file_count": self.file_count,
            "succeeded": self.succeeded,
        }


#: One-line purpose for each artefact kind the release produces. The dataset card
#: is the only place a visitor learns what a file is for, so an undescribed file
#: in the bundle is a card that has failed at its one job.
ARTEFACT_PURPOSE: dict[str, str] = {
    "wheel": "Installable wheel. `pip install` this to get the `opencode` CLI.",
    "source-archive": "Source distribution. Build from source to audit what you run.",
    "offline-pack": "Offline pack: the toolkit plus its verified snippets, checksummed, for air-gapped use.",
    "sbom": "CycloneDX SBOM. Machine-readable inventory of every component.",
    "documentation": "This project's documentation set, archived.",
    "artifact_index": "Signed index of this bundle: sizes and SHA-256 digests.",
    "checksums": "SHA-256 digests of every other file here. Verify before trusting anything.",
}

#: Files that must appear in the card, or the card is incomplete.
CARD_FILENAME = "README.md"


def _human_bytes(count: int) -> str:
    """Return *count* bytes in a unit a human reads without converting."""
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"  # pragma: no cover - unreachable


def verified_release_files(root: Path) -> tuple[str, ...]:
    """Return the artefact paths a signed build manifest vouches for.

    A dataset bundle carries the release outputs, so ``dist/*`` has to get past
    the publishing exclusion. Doing that by name rather than by lifting the
    exclusion means only files the build recorded -- with a size and a SHA-256
    -- are copied, and an unvetted file someone dropped in ``dist/`` is not.

    Args:
        root: Path: Path: Path: Path: Repository root; ``dist/artifacts.json`` is read from it.
    """
    from opencode_toolkit.core import jsonio

    index = root / "dist" / "artifacts.json"
    if not index.is_file():
        return ()
    try:
        document = jsonio.read(index)
    except Exception:
        return ()
    names = document.get("artifacts") if isinstance(document, dict) else None
    if not isinstance(names, list):
        return ()
    vouched = {
        f"dist/{item['name']}"
        for item in names
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    # The manifest cannot list itself, and its checksum file is written after it,
    # so both are named here. They are written by the release build itself, which
    # is the same provenance as everything the manifest does list.
    for companion in ("dist/artifacts.json", "dist/SHA256SUMS"):
        if (root / companion).is_file():
            vouched.add(companion)
    return tuple(sorted(vouched))


def write_dataset_card(
    directory: Path,
    *,
    root: Path,
    gate: GateResult | None = None,
    repo_url: str = DEFAULT_REPO_URL,
) -> str:
    """Render the card into *directory* as ``README.md`` and return its text.

    Args:
        directory: Path: Path: Path: Path: Prepared dataset bundle; the card is written here so it reflects exactly the files that will be uploaded.
        root: Path: Path: Path: Path: Repository root, used to detect the release version.
        gate: GateResult | None: GateResult | None: GateResult | None: GateResult | None: The gate that permitted publishing, quoted in the card's provenance so a visitor can see why it was allowed.
        repo_url: str: str: str: str: Repository the full source and documentation live at.
    """
    permitted, reason = gate.publish_permitted() if gate is not None else (False, "")
    text = dataset_card(
        directory,
        version=detect_version(root),
        commit=head_commit(root),
        gate_reason=reason if permitted else "",
        repo_url=repo_url,
    )
    (directory / CARD_FILENAME).write_text(text, encoding="utf-8")
    return text


def dataset_card(
    directory: Path,
    *,
    version: Version,
    commit: str = "",
    gate_reason: str = "",
    repo_url: str = DEFAULT_REPO_URL,
) -> str:
    """Render the visitor-facing dataset card for the bundle in *directory*.

    Generated from what is actually on disk rather than written by hand, so it
    cannot claim a file the bundle does not contain or describe a size that has
    changed. Every top-level file is listed, because the card is the only place
    a visitor is told what they downloaded.

    Args:
        directory: Path: Path: Path: Path: Prepared dataset bundle to describe.
        version: Version: Version: Version: Version: Release this bundle was cut from.
        commit: str: str: str: str: Commit the release was built from, for provenance.
        gate_reason: str: str: str: str: Why the release gate permitted publishing, if known.
        repo_url: str: str: str: str: Repository the full source and docs live at.
    """
    entries: list[tuple[str, str, int]] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in {CARD_FILENAME, METADATA_FILENAME}:
            continue
        entries.append(
            (path.relative_to(directory).as_posix(), _purpose_of(path), path.stat().st_size)
        )

    lines: list[str] = [
        f"# OpenCode Toolkit {version}",
        "",
        "A modular engineering toolkit for OpenCode projects, shipped as a verified",
        "file bundle: security auditing across four languages, encrypted workflow sync,",
        "a reviewed snippet registry, task-graph orchestration, an offline pack, and",
        "documentation drift detection.",
        "",
        "**Zero third-party runtime dependencies.** The CLI runs on the Python standard",
        "library alone, which is what makes the offline pack redistributable without a",
        "third-party licence audit and a clean-checkout install deterministic.",
        "",
        "## What is in this bundle",
        "",
        "| File | Size | What it is |",
        "| --- | ---: | --- |",
    ]
    for name, purpose, size in entries:
        lines.append(f"| `{name}` | {_human_bytes(size)} | {purpose} |")

    present = {name for name, _, _ in entries}
    lines.append("")
    lines.append("## Verifying what you downloaded")
    lines.append("")
    lines.append("Nothing here should be trusted on the strength of this page. Check it:")
    lines.append("")
    if "SHA256SUMS" in present:
        lines += [
            "```console",
            "$ sha256sum --check --ignore-missing SHA256SUMS",
            "```",
            "",
            "Every digest must report `OK`. If one does not, nothing else on this page",
            "is worth reading.",
            "",
        ]
    else:
        # Never promise a verification step this bundle cannot perform.
        lines += [
            "This bundle was published without a checksum manifest, so there is no",
            "command here that would let you check it. Treat every file as unverified",
            "and prefer a build with `SHA256SUMS`.",
            "",
        ]

    if gate_reason:
        lines += [
            "The release gate that permitted this refuses to publish until all thirteen",
            "checks pass: build, format, lint, types, unit, integration, CLI, security,",
            "dependency audit, secret scan, documentation, package, and reproducibility.",
            "",
        ]

    if any(name.endswith(".whl") for name in present):
        lines += [
            "## Using it",
            "",
            "Install the wheel and point it at your project:",
            "",
            "```console",
            "$ pip install opencode-toolkit",
            "$ opencode doctor                    # what is and is not available here",
            "$ opencode security-audit . --strict",
            "```",
            "",
        ]
    if any(n.endswith("-offline.zip") for n in present):
        lines += [
            "Working offline or on an air-gapped host? Take the offline pack instead, which",
            "bundles the toolkit with its verified snippets and per-file checksums.",
            "",
        ]

    lines += [
        "## What this bundle is not",
        "",
        "Being precise about this is the point of publishing it here rather than as a",
        "model or an app:",
        "",
        "- **Not a model.** There are no trained weights and no inference code.",
        "- **Not a dataset.** There is no row data and no training corpus.",
        "- **Not an application.** It is a command-line tool, not a service to host.",
        "- **Not a container.** No image is included; the runtime needs only CPython.",
        "",
        "What it *is* is a reproducible software bundle with a verifiable manifest.",
        "",
        "## Provenance",
        "",
    ]
    if commit:
        lines.append(f"- Built from commit `{commit}`.")
    if gate_reason:
        lines.append(f"- Release gate: {gate_reason}.")
    lines += [
        f"- Source, issue tracker and full documentation: {repo_url}",
        "- Licence: Apache-2.0. Third-party code: none at runtime, so there is nothing",
        "  else to attribute.",
        "",
        "## Licence",
        "",
        "Apache-2.0. See `LICENSE` in this bundle.",
        "",
    ]
    return "\n".join(lines)


def _purpose_of(path: Path) -> str:
    """Describe *path* by what it is, falling back to its shape."""
    name = path.name
    if name.endswith(".whl"):
        return ARTEFACT_PURPOSE["wheel"]
    if name.endswith("-sdist.tar.gz"):
        return ARTEFACT_PURPOSE["source-archive"]
    if name.endswith("-offline.zip"):
        return ARTEFACT_PURPOSE["offline-pack"]
    if name.endswith(".cdx.json"):
        return ARTEFACT_PURPOSE["sbom"]
    if name.endswith(".tar.gz"):
        return ARTEFACT_PURPOSE["documentation"]
    if name == "SHA256SUMS":
        return ARTEFACT_PURPOSE["checksums"]
    if name == "artifacts.json":
        return ARTEFACT_PURPOSE["artifact_index"]
    if name == "LICENSE":
        return "The Apache-2.0 licence text."
    if name == "CHANGELOG.md":
        return "What changed in each release."
    if name.startswith("docs/"):
        return f"Documentation: {Path(name).stem.replace('-', ' ')}."
    if name.endswith(".md"):
        return "Documentation."
    return "Supporting file."


def validate_dataset_card(directory: Path) -> tuple[bool, list[str]]:
    """Check the card exists and actually describes the bundle it ships with.

    A card that omits a file is worse than no card: it reads as a complete
    inventory and is not one. Anything present must be named, so a file added to
    the bundle without a line of description fails the publish.

    Args:
        directory: Path: Path: Path: Path: Prepared dataset directory holding ``README.md``.
    """
    problems: list[str] = []
    card = directory / CARD_FILENAME
    if not card.is_file():
        return False, [f"{CARD_FILENAME} is the dataset card and was not found"]
    text = card.read_text(encoding="utf-8")
    if not text.lstrip().startswith("#"):
        problems.append(f"{CARD_FILENAME} does not start with a heading")
    for required in ("## What is in this bundle", "## Provenance", "## Licence"):
        if required not in text:
            problems.append(f"{CARD_FILENAME} is missing the {required!r} section")
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(directory).as_posix()
        if relative in {CARD_FILENAME, METADATA_FILENAME}:
            continue
        if f"`{relative}`" not in text:
            problems.append(f"{CARD_FILENAME} does not describe {relative}")
    return not problems, problems


def _describe_resources(root: Path) -> list[dict[str, str]]:
    """Describe the release artefacts a visitor will find in the bundle.

    Args:
        root: Path: Repository root, used to locate ``dist/`` when a build is
            present so the listing reflects real files rather than a guess.
    """
    resources: list[dict[str, str]] = [
        {"path": CARD_FILENAME, "description": "Dataset card: contents, verification, provenance."},
        {"path": METADATA_FILENAME, "description": "Kaggle dataset metadata."},
    ]
    dist = root / "dist"
    if not dist.is_dir():
        return resources
    for path in sorted(dist.glob("*")):
        if not path.is_file():
            continue
        resources.append({"path": path.name, "description": _purpose_of(path)})
    return resources


def dataset_metadata(
    root: Path, *, owner: str = "", slug: str = "opencode-toolkit"
) -> dict[str, Any]:
    """Build the Kaggle dataset metadata for this release.

    Args:
        root: Path: Path: Path: Path: Repository root; its detected version supplies ``version.version_number``.
        owner: str: str: str: str: Kaggle account or organisation that owns the dataset; when empty, ``id`` is emitted as the bare *slug*.
        slug: str: str: str: str: Dataset slug used when *owner* is empty.
    """
    version = detect_version(root)
    return {
        "title": "OpenCode Toolkit",
        "id": f"{owner}/{slug}" if owner else slug,
        "licenses": [{"name": "CC0-1.0"}],
        "keywords": [
            "opencode",
            "security-audit",
            "static-analysis",
            "supply-chain",
            "sbom",
            "devops",
            "tooling",
            "orchestration",
            "offline",
            "python",
            "security",
        ],
        "subtitle": (
            "Verified release bundle: security auditing, encrypted sync, snippets, "
            "orchestration, offline pack"
        ),
        "description": (
            "OpenCode Toolkit is a Python CLI providing multi-language security auditing, "
            "encrypted workflow synchronisation, a verified snippet registry, multi-agent "
            "task orchestration, verifiable offline packages and documentation drift "
            "detection. The runtime has no third-party dependencies."
        ),
        # Every real file, described. The previous entry listed only the metadata
        # file itself, so the dataset page described nothing it contained.
        "resources": _describe_resources(root),
        "version": {
            "version_number": str(version),
            "description": f"opencode-toolkit {version}",
        },
        "subtitle_note": f"opencode-toolkit {version}",
        "extra_notes": (
            "Contains only first-party code under Apache-2.0. No credentials, model weights "
            "or datasets are included; the publishing directory is secret-scanned before upload."
        ),
        "keywords_list": ["opencode", "security-audit", "supply-chain", "orchestration"],
        "licenses_list": ["CC0-1.0"],
    }


def validate_dataset_metadata(directory: Path) -> tuple[bool, list[str]]:
    """Validate ``dataset-metadata.json`` before upload.

    Args:
        directory: Path: Path: Path: Path: Prepared dataset directory; its ``dataset-metadata.json`` is parsed and checked against :data:`REQUIRED_METADATA_KEYS`.
    """
    problems: list[str] = []
    path = directory / METADATA_FILENAME
    if not path.is_file():
        return False, [f"{METADATA_FILENAME} is required by Kaggle and was not found"]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, [f"{METADATA_FILENAME} is not valid JSON: {exc.msg} at line {exc.lineno}"]
    if not isinstance(document, dict):
        return False, [f"{METADATA_FILENAME} must contain a JSON object"]

    for key in REQUIRED_METADATA_KEYS:
        if key not in document:
            problems.append(f"missing required metadata key: {key}")
    identifier = document.get("id")
    if isinstance(identifier, str) and not re_full_owner_slug(identifier):
        problems.append(f"metadata 'id' must be 'owner/slug' or 'slug', got {identifier!r}")

    licenses = document.get("licenses")
    if isinstance(licenses, list):
        for item in licenses:
            if not isinstance(item, dict) or "name" not in item:
                problems.append("each entry in 'licenses' must be an object with a 'name' field")
                break

    keywords = document.get("keywords")
    if keywords is not None and not isinstance(keywords, list | str):
        problems.append("'keywords' must be a list or a string")

    version = document.get("version")
    if version is not None and (not isinstance(version, dict) or "version_number" not in version):
        problems.append("'version' must be an object containing 'version_number'")
    return not problems, problems


def re_full_owner_slug(identifier: str) -> bool:
    """Return ``True`` when *identifier* is ``owner/slug`` or ``slug``.

    Args:
        identifier: str: str: str: str: Candidate metadata ``id``, matched in full against ``[A-Za-z0-9_-]+`` with an optional ``owner/`` prefix.
    """
    import re

    return bool(re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)?", identifier))


class KagglePublisher:
    """Publishes a prepared directory as a Kaggle Dataset."""

    def __init__(
        self,
        *,
        dataset_slug: str = "opencode-toolkit",
        private: bool = False,
        api_base: str = KAGGLE_API,
    ) -> None:
        if not dataset_slug.strip():
            raise ConfigurationError("a Kaggle dataset slug is required")
        self.dataset_slug = dataset_slug
        self.private = private
        self.api_base = api_base.rstrip("/")

    @property
    def dataset_ref(self) -> str:
        """Return the ``datasets/<slug>`` reference Kaggle identifies this by."""
        return f"datasets/{self.dataset_slug}"

    @staticmethod
    def _auth_header(username: str, key: str) -> str:
        raw = f"{username}:{key}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")

    # -- gates ------------------------------------------------------------
    def check_gate(self, gate: GateResult) -> KaggleResult | None:
        """Return a BLOCKED result when the gate does not permit publishing.

        Args:
            gate: GateResult: GateResult: GateResult: GateResult: Recorded release gate decision; when it does not permit publishing, its reason is logged and carried in the result.
        """
        permitted, reason = gate.publish_permitted()
        if permitted:
            return None
        logger.error("kaggle publish refused: %s", reason)
        return KaggleResult(
            status=STATUS_BLOCKED,
            dataset_ref=self.dataset_ref,
            reason=reason,
            verification={"gate_decision": gate.decision, "gate_reason": gate.reason()},
        )

    def check_credentials(self, *, environ: dict[str, str] | None = None) -> KaggleResult | None:
        """Return a SKIPPED result when a required credential is absent.

        Args:
            environ: dict[str, str] | None: dict[str, str] | None: dict[str, str] | None: dict[str, str] | None: Environment mapping to read from; defaults to :data:`os.environ`. Only the presence of ``KAGGLE_USERNAME`` and ``KAGGLE_KEY`` is checked -- no credential value is returned or logged.
        """
        missing = missing_credentials(KAGGLE_USERNAME_ENV, KAGGLE_KEY_ENV, environ=environ)
        if not missing:
            return None
        reason = f"{' and '.join(missing)} not set; publishing is not attempted"
        logger.warning("kaggle publish skipped: %s", reason)
        return KaggleResult(
            status=STATUS_SKIPPED,
            dataset_ref=self.dataset_ref,
            reason=reason,
            missing_configuration=[
                f"environment variable {name} (in GitHub Actions: a repository secret with the same name)"
                for name in (KAGGLE_USERNAME_ENV, KAGGLE_KEY_ENV)
            ],
        )

    # -- publish ----------------------------------------------------------
    def publish(self, directory: Path, *, environ: dict[str, str] | None = None) -> KaggleResult:
        """Upload *directory* as a Dataset zip and verify it afterwards.

        Args:
            directory: Path: Path: Path: Path: Prepared dataset directory to zip and upload; it is metadata- and secret-validated before any upload is attempted.
            environ: dict[str, str] | None: dict[str, str] | None: dict[str, str] | None: dict[str, str] | None: Environment mapping to read from; defaults to :data:`os.environ`. ``KAGGLE_USERNAME`` and ``KAGGLE_KEY`` are read from it to authenticate; the values are never returned or logged.
        """
        env = dict(os.environ if environ is None else environ)

        ok, problems = validate_dataset_metadata(directory)
        if not ok:
            return KaggleResult(
                status=STATUS_BLOCKED,
                dataset_ref=self.dataset_ref,
                reason="dataset metadata validation failed",
                verification={"problems": problems},
            )

        try:
            assert_clean(directory)
        except Exception as exc:
            return KaggleResult(
                status=STATUS_BLOCKED,
                dataset_ref=self.dataset_ref,
                reason="secret scan failed",
                verification={"error": str(exc)},
            )

        missing = missing_credentials(KAGGLE_USERNAME_ENV, KAGGLE_KEY_ENV, environ=env)
        if missing:
            return self.check_credentials(environ=env) or KaggleResult(
                status=STATUS_SKIPPED, dataset_ref=self.dataset_ref, reason="no credentials"
            )

        username = env[KAGGLE_USERNAME_ENV]
        key = env[KAGGLE_KEY_ENV]
        archive = directory.parent / f"{self.dataset_slug}.zip"
        _zip_directory(directory, archive)

        try:
            _upload(archive, username=username, key=key, api_base=self.api_base)
        except NetworkError as exc:
            return KaggleResult(
                status=STATUS_FAILED,
                dataset_ref=self.dataset_ref,
                reason=_scrub(exc.message, key),
                file_count=len(list(directory.rglob("*"))),
            )

        verification = self.verify(username=username, key=key)
        if not verification.get("ok"):
            return KaggleResult(
                status=STATUS_PUBLISHED_BUT_VERIFICATION_FAILED,
                dataset_ref=self.dataset_ref,
                reason="upload completed but post-publish verification did not confirm the dataset",
                file_count=verification.get("file_count", 0),
                verification=verification,
            )
        return KaggleResult(
            status=STATUS_PUBLISHED,
            dataset_ref=self.dataset_ref,
            reason="upload completed and the dataset was verified",
            file_count=verification.get("file_count", 0),
            verification=verification,
        )

    # -- verification -----------------------------------------------------
    def verify(self, *, username: str, key: str) -> dict[str, Any]:
        """Confirm the dataset exists remotely and reports its files.

        Args:
            username: str: str: str: str: Kaggle account used in the request URL and in HTTP Basic authentication.
            key: str: str: str: str: Kaggle API key used only in the ``Authorization`` header; the value is never returned or logged.
        """
        url = f"{self.api_base}/datasets/list/{username}/{self.dataset_slug}"
        headers = {"Authorization": self._auth_header(username, key)}
        request = urllib.request.Request(url, headers=headers)
        try:
            # S310: the endpoint is the fixed https:// Kaggle API base, never a
            # caller-supplied URL, so no scheme confusion is possible here.
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return {
                "ok": False,
                "reason": f"remote dataset returned HTTP {exc.code}",
                "checked": ["existence"],
            }
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise NetworkError(
                f"cannot reach {self.api_base}: {exc}",
                details={"url": url},
                hint="publication may have succeeded; re-run verification rather than re-uploading",
            ) from exc

        try:
            document = json.loads(payload)
        except json.JSONDecodeError:
            return {"ok": False, "reason": "remote response was not JSON", "checked": ["existence"]}

        remote_files = document.get("resources") or document.get("files") or []
        names = [
            str(item.get("path", item)) if isinstance(item, dict) else str(item)
            for item in remote_files
        ]
        missing = [name for name in (METADATA_FILENAME, "README.md") if name not in names]
        return {
            "ok": not missing,
            "reason": "remote dataset confirmed"
            if not missing
            else f"missing remote files: {missing}",
            "checked": ["existence", METADATA_FILENAME, "README.md"],
            "file_count": len(names),
            "remote_names": sorted(names)[:20],
        }


def _zip_directory(directory: Path, archive: Path) -> Path:
    """Zip *directory* with sorted entries so the upload is reproducible."""
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(directory.rglob("*")):
            if path.is_file() and not path.is_symlink():
                bundle.write(path, arcname=path.relative_to(directory).as_posix())
    return archive


def _upload(archive: Path, *, username: str, key: str, api_base: str) -> None:
    """POST the archive to the Kaggle dataset upload endpoint."""
    url = f"{api_base}/datasets/create/{username}/{archive.stem}"
    body = archive.read_bytes()
    headers = {
        "Authorization": KagglePublisher._auth_header(username, key),
        "Content-Type": "application/zip",
        "Content-Length": str(len(body)),
    }
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        # S310: the endpoint is the fixed https:// Kaggle API base.
        with urllib.request.urlopen(request, timeout=900) as response:
            if response.status >= 400:  # pragma: no cover - urlopen raises first
                raise NetworkError(f"Kaggle rejected the upload with HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        raise NetworkError(
            f"Kaggle upload failed with HTTP {exc.code}",
            details={"url": url, "code": exc.code},
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetworkError(f"Kaggle upload failed: {exc}", details={"url": url}) from exc


def _scrub(message: str, key: str) -> str:
    if not key:
        return message
    return message.replace(key, "***redacted***")
