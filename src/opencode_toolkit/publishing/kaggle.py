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
from opencode_toolkit.core.version import detect_version
from opencode_toolkit.publishing.artifacts import assert_clean
from opencode_toolkit.publishing.classify import (
    KAGGLE_KEY_ENV,
    KAGGLE_USERNAME_ENV,
    missing_credentials,
)
from opencode_toolkit.release.gate import GateResult

logger = logging.get_logger("publishing.kaggle")

KAGGLE_API = "https://www.kaggle.com/api/v1"

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


def dataset_metadata(
    root: Path, *, owner: str = "", slug: str = "opencode-toolkit"
) -> dict[str, Any]:
    """Build the Kaggle dataset metadata for this release.

    Args:
        root: Path: Repository root; its detected version supplies
            ``version.version_number``.
        owner: str: Kaggle account or organisation that owns the dataset; when
            empty, ``id`` is emitted as the bare *slug*.
        slug: str: Dataset slug used when *owner* is empty.
    """
    version = detect_version(root)
    return {
        "title": "OpenCode Toolkit",
        "id": f"{owner}/{slug}" if owner else slug,
        "licenses": [{"name": "CC0-1.0"}],
        "keywords": ["opencode", "security", "devops", "tooling", "static-analysis"],
        "subtitle": "Unified OpenCode engineering toolkit with security auditing and release tooling",
        "description": (
            "OpenCode Toolkit is a Python CLI providing multi-language security auditing, "
            "encrypted workflow synchronisation, a verified snippet registry, multi-agent "
            "task orchestration, verifiable offline packages and documentation drift "
            "detection. The runtime has no third-party dependencies."
        ),
        "resources": [
            {
                "path": METADATA_FILENAME,
                "description": "Kaggle dataset metadata",
            }
        ],
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
        directory: Path: Prepared dataset directory; its
            ``dataset-metadata.json`` is parsed and checked against
            :data:`REQUIRED_METADATA_KEYS`.
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
        identifier: str: Candidate metadata ``id``, matched in full against
            ``[A-Za-z0-9_-]+`` with an optional ``owner/`` prefix.
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
            gate: GateResult: Recorded release gate decision; when it does not
                permit publishing, its reason is logged and carried in the result.
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
            environ: dict[str, str] | None: Environment mapping to read from;
                defaults to :data:`os.environ`. Only the presence of
                ``KAGGLE_USERNAME`` and ``KAGGLE_KEY`` is checked -- no
                credential value is returned or logged.
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
            directory: Path: Prepared dataset directory to zip and upload; it is
                metadata- and secret-validated before any upload is attempted.
            environ: dict[str, str] | None: Environment mapping to read from;
                defaults to :data:`os.environ`. ``KAGGLE_USERNAME`` and
                ``KAGGLE_KEY`` are read from it to authenticate; the values are
                never returned or logged.
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
            username: str: Kaggle account used in the request URL and in HTTP
                Basic authentication.
            key: str: Kaggle API key used only in the ``Authorization`` header;
                the value is never returned or logged.
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
