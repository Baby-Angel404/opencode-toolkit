"""Hugging Face publishing.

Requires ``HUGGINGFACE_TOKEN`` as an environment variable or a GitHub Actions
secret. The token value is never logged, never written to a file, and never
included in an error message.

The upload itself uses the ``huggingface_hub`` Python client when it is
installed. It is **not** a runtime dependency of this toolkit, so a checkout
without it produces a clear, actionable ``BLOCKED`` result rather than a traceback
-- which is the correct outcome for an offline or air-gapped host.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import logging
from opencode_toolkit.core.errors import ConfigurationError, NetworkError
from opencode_toolkit.core.version import detect_version
from opencode_toolkit.publishing.artifacts import assert_clean
from opencode_toolkit.publishing.classify import HUGGINGFACE_TOKEN_ENV, missing_credentials
from opencode_toolkit.release.gate import GateResult

logger = logging.get_logger("publishing.huggingface")

HF_ENDPOINT = "https://huggingface.co"

#: Statuses a publish attempt can end in. ``SKIPPED`` is a first-class outcome,
#: never conflated with success.
PUBLISHED = "PUBLISHED"
SKIPPED = "SKIPPED"
BLOCKED = "BLOCKED"
FAILED = "FAILED"
PUBLISHED_BUT_VERIFICATION_FAILED = "PUBLISHED_BUT_VERIFICATION_FAILED"


@dataclass(slots=True)
class HuggingFaceResult:
    """Outcome of a Hugging Face publish attempt."""

    status: str
    repository: str = ""
    repo_type: str = "space"
    reason: str = ""
    missing_configuration: list[str] = field(default_factory=list)
    verification: dict[str, Any] = field(default_factory=dict)
    files_uploaded: int = 0

    @property
    def succeeded(self) -> bool:
        """``True`` only for a fully published and verified Space."""
        return self.status == PUBLISHED

    def to_dict(self) -> dict[str, Any]:
        """Return the publish result as JSON-serialisable data."""
        return {
            "platform": "huggingface",
            "status": self.status,
            "repository": self.repository,
            "repo_type": self.repo_type,
            "reason": self.reason,
            "missing_configuration": list(self.missing_configuration),
            "verification": self.verification,
            "files_uploaded": self.files_uploaded,
            "succeeded": self.succeeded,
        }


@dataclass(slots=True)
class SpaceMetadata:
    """The ``README.md`` YAML front matter a Hugging Face Space requires."""

    title: str
    emoji: str
    sdk: str
    app_port: int
    license: str
    short_description: str
    suggested_hardware: str
    sdk_version: str

    def to_yaml(self) -> str:
        """Render the front matter block."""
        return (
            "---\n"
            f"title: {self.title}\n"
            f"emoji: {self.emoji}\n"
            f"colorFrom: indigo\n"
            "colorTo: gray\n"
            f"sdk: {self.sdk}\n"
            f"app_port: {self.app_port}\n"
            f"license: {self.license}\n"
            f"short_description: {self.short_description}\n"
            f"suggested_hardware: {self.suggested_hardware}\n"
            f"sdk_version: {self.sdk_version}\n"
            "---\n"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the Space metadata as the README front matter it becomes."""
        return {
            "title": self.title,
            "emoji": self.emoji,
            "sdk": self.sdk,
            "app_port": self.app_port,
            "license": self.license,
            "short_description": self.short_description,
            "suggested_hardware": self.suggested_hardware,
            "sdk_version": self.sdk_version,
        }


def space_metadata(root: Path) -> SpaceMetadata:
    """Derive Space metadata from the repository itself.

    Args:
        root: Path: Repository root; its detected version supplies
            ``sdk_version`` (the major number).
    """
    return SpaceMetadata(
        title="OpenCode Toolkit",
        emoji="🛠",
        sdk="docker",
        app_port=7860,
        license="apache-2.0",
        short_description="Security, sync and orchestration toolkit for OpenCode projects",
        suggested_hardware="cpu-basic",
        sdk_version=str(detect_version(root).major),
    )


def validate_space_metadata(directory: Path) -> tuple[bool, list[str]]:
    """Validate the Space directory before uploading.

    Args:
        directory: Path: Prepared Space directory; its ``README.md`` front
            matter and root ``Dockerfile`` are inspected.

    Returns ``(ok, problems)`` rather than raising, so the caller can decide
    whether to block or to report.
    """
    problems: list[str] = []
    readme = directory / "README.md"
    if not readme.is_file():
        problems.append("README.md is required by every Space and was not found")
        return False, problems

    text = readme.read_text(encoding="utf-8")
    if not text.startswith("---"):
        problems.append("README.md must begin with YAML front matter delimited by ---")
        return False, problems

    parts = text.split("---", 2)
    if len(parts) < 3:
        problems.append("README.md front matter is not terminated by a second ---")
        return False, problems

    try:
        import yaml
    except ModuleNotFoundError:
        yaml = None

    if yaml is not None:
        try:
            document = yaml.safe_load(parts[1])
        except yaml.YAMLError as exc:
            problems.append(f"README.md front matter is not valid YAML: {exc}")
            return False, problems
        if not isinstance(document, dict):
            problems.append("README.md front matter must be a YAML mapping")
            return False, problems
        for key in ("title", "sdk", "app_port"):
            if key not in document:
                problems.append(f"README.md front matter is missing required key: {key}")
        sdk = document.get("sdk")
        if sdk not in {"docker", "gradio", "streamlit", "static"}:
            problems.append(
                f"unsupported Space sdk {sdk!r}; expected docker, gradio, streamlit or static"
            )
    else:
        # Without PyYAML, verify the required keys textually rather than skipping
        # the check entirely.
        for key in ("title:", "sdk:", "app_port:"):
            if key not in parts[1]:
                problems.append(
                    f"README.md front matter is missing required key: {key.replace(':', '')}"
                )

    if not (directory / "Dockerfile").is_file():
        problems.append("a docker Space requires a Dockerfile at the Space root")
    if not (directory / ".dockerignore").is_file():
        logger.debug(
            "no .dockerignore at the Space root; the Docker build context will be larger than necessary"
        )
    return not problems, problems


class HuggingFacePublisher:
    """Publishes a prepared directory to the Hugging Face Hub."""

    def __init__(
        self,
        namespace: str,
        *,
        repo_id: str = "opencode-toolkit",
        endpoint: str = HF_ENDPOINT,
        private: bool = True,
    ) -> None:
        if not namespace.strip():
            raise ConfigurationError("a Hugging Face namespace (user or organisation) is required")
        self.namespace = namespace.strip()
        self.repo_id = repo_id
        self.endpoint = endpoint.rstrip("/")
        self.private = private

    @property
    def repository(self) -> str:
        """Return the ``namespace/repo_id`` slug the Hub identifies this Space by."""
        return f"{self.namespace}/{self.repo_id}"

    # -- gates ------------------------------------------------------------
    def check_gate(self, gate: GateResult) -> HuggingFaceResult | None:
        """Return a BLOCKED result when the release gate does not permit publishing.

        Args:
            gate: GateResult: Recorded release gate decision; when it does not
                permit publishing, its reason is logged and carried in the result.
        """
        permitted, reason = gate.publish_permitted()
        if permitted:
            return None
        logger.error("huggingface publish refused: %s", reason)
        return HuggingFaceResult(
            status=BLOCKED,
            repository=self.repository,
            reason=reason,
            verification={"gate_decision": gate.decision, "gate_reason": gate.reason()},
        )

    def check_credentials(
        self, *, environ: dict[str, str] | None = None
    ) -> HuggingFaceResult | None:
        """Return a SKIPPED result when the token is absent.

        Args:
            environ: dict[str, str] | None: Environment mapping to read from;
                defaults to :data:`os.environ`. Only the presence of
                ``HUGGINGFACE_TOKEN`` is checked -- the token value is never
                returned or logged.
        """
        missing = missing_credentials(HUGGINGFACE_TOKEN_ENV, environ=environ)
        if not missing:
            return None
        reason = f"{HUGGINGFACE_TOKEN_ENV} is not set; publishing is not attempted"
        logger.warning("huggingface publish skipped: %s", reason)
        return HuggingFaceResult(
            status=SKIPPED,
            repository=self.repository,
            reason=reason,
            missing_configuration=[
                f"environment variable {HUGGINGFACE_TOKEN_ENV} "
                "(in GitHub Actions: a repository secret with the same name)"
            ],
        )

    # -- publish ----------------------------------------------------------
    def publish(
        self, directory: Path, *, environ: dict[str, str] | None = None
    ) -> HuggingFaceResult:
        """Upload *directory* and verify the remote repository afterwards.

        Args:
            directory: Path: Prepared Space directory to upload; it is metadata-
                and secret-validated before any upload is attempted.
            environ: dict[str, str] | None: Environment mapping to read from;
                defaults to :data:`os.environ`. ``HUGGINGFACE_TOKEN`` is read
                from it to authenticate; the value is never returned or logged.
        """
        env = dict(os.environ if environ is None else environ)

        ok, problems = validate_space_metadata(directory)
        if not ok:
            return HuggingFaceResult(
                status=BLOCKED,
                repository=self.repository,
                reason="Space metadata validation failed",
                verification={"problems": problems},
            )

        try:
            assert_clean(directory)
        except Exception as exc:
            return HuggingFaceResult(
                status=BLOCKED,
                repository=self.repository,
                reason="secret scan failed",
                verification={"error": str(exc)},
            )

        token = env.get(HUGGINGFACE_TOKEN_ENV, "")
        if not token.strip():
            return self.check_credentials(environ=env) or HuggingFaceResult(
                status=SKIPPED, repository=self.repository, reason="no token"
            )

        try:
            from huggingface_hub import HfApi
        except ModuleNotFoundError:
            return HuggingFaceResult(
                status=BLOCKED,
                repository=self.repository,
                reason="the huggingface_hub client is not installed",
                missing_configuration=[
                    "Python package 'huggingface_hub' (install it in the publishing job, "
                    "not in the toolkit runtime)"
                ],
            )

        api = HfApi(token=token)
        try:
            api.create_repo(
                repo_id=self.repository,
                repo_type="space",
                space_sdk="docker",
                private=self.private,
                exist_ok=True,
            )
            uploaded = api.upload_folder(
                folder_path=str(directory),
                repo_id=self.repository,
                repo_type="space",
                ignore_patterns=["__pycache__", "*.pyc", ".git/*"],
            )
        except Exception as exc:
            # The message is included; the token is never part of it because the
            # client does not echo it, and it is scrubbed defensively anyway.
            return HuggingFaceResult(
                status=FAILED,
                repository=self.repository,
                reason=f"upload failed: {_scrub(str(exc), token)}",
            )

        file_count = (
            len((getattr(uploaded, "__iter__", None) and list(uploaded)) or []) if uploaded else 0
        )
        verification = self.verify(token=token)
        if not verification.get("ok"):
            return HuggingFaceResult(
                status=PUBLISHED_BUT_VERIFICATION_FAILED,
                repository=self.repository,
                reason="upload completed but post-publish verification did not confirm the remote state",
                files_uploaded=file_count,
                verification=verification,
            )
        return HuggingFaceResult(
            status=PUBLISHED,
            repository=self.repository,
            reason="upload completed and the remote repository was verified",
            files_uploaded=file_count,
            verification=verification,
        )

    # -- verification -----------------------------------------------------
    def verify(self, *, token: str = "") -> dict[str, Any]:
        """Confirm the remote repository exists and contains the expected files.

        Args:
            token: str: Bearer token for the request; when empty the request is
                sent unauthenticated. The value is used only in the
                ``Authorization`` header and is never returned or logged.

        Uses the Hub HTTP API directly so verification does not depend on the
        client library being importable, and so a missing file is distinguishable
        from a network failure.
        """
        url = f"{self.endpoint}/api/spaces/{self.repository}"
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            # S310: the endpoint is the fixed https:// Hugging Face API base, so
            # no caller-supplied scheme can reach urlopen.
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=30
            ) as response:
                document = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return {
                "ok": False,
                "reason": f"remote repository returned HTTP {exc.code}",
                "checked": ["existence"],
            }
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise NetworkError(
                f"cannot reach {self.endpoint}: {exc}",
                details={"url": url},
                hint="publication may have succeeded; re-run verification rather than re-uploading",
            ) from exc

        siblings = [str(item.get("rfilename", "")) for item in document.get("siblings", [])]
        required = ["README.md", "Dockerfile"]
        missing = [name for name in required if name not in siblings]
        return {
            "ok": not missing,
            "reason": "remote repository confirmed"
            if not missing
            else f"missing remote files: {missing}",
            "checked": ["existence", "README.md", "Dockerfile"],
            "file_count": len(siblings),
            "sha": document.get("sha"),
            "private": document.get("private"),
        }


def _scrub(message: str, token: str) -> str:
    """Remove the token from any message before it reaches a log."""
    if not token:
        return message
    return message.replace(token, "***redacted***")
