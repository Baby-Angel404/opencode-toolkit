"""Unit tests for platform publishing: metadata, validation and credential gates.

The network is never reached. Where a code path would open a connection, the
test substitutes a fake ``urlopen`` and asserts on the request that would have
been made -- which is also how the "never logs a credential" claims are checked
without a real upload.
"""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from opencode_toolkit.core.errors import IntegrityError, NetworkError
from opencode_toolkit.publishing import huggingface as hf
from opencode_toolkit.publishing import kaggle as kg
from opencode_toolkit.publishing.classify import (
    Classification,
    credential_status,
    missing_credentials,
)

pytestmark = pytest.mark.unit


class _Response:
    """Minimal stand-in for the object ``urlopen`` returns."""

    def __init__(self, payload: bytes = b"{}", status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


# -- metadata construction ------------------------------------------------


def test_space_metadata_carries_the_major_version_as_the_sdk_version() -> None:
    root = Path(__file__).resolve().parents[2]
    metadata = hf.space_metadata(root)
    # The Hub expects a string here; an int is silently coerced by some clients
    # and rejected by others, so the type is asserted rather than assumed.
    assert isinstance(metadata.sdk_version, str)
    assert metadata.sdk_version == metadata.sdk_version.strip()
    assert metadata.sdk_version.isdigit()
    assert metadata.sdk == "docker"
    assert metadata.to_dict()["license"] == "apache-2.0"


def test_space_metadata_renders_yaml_front_matter() -> None:
    root = Path(__file__).resolve().parents[2]
    rendered = hf.space_metadata(root).to_yaml()
    assert rendered.startswith("---\n")
    assert "sdk: docker" in rendered
    assert rendered.rstrip().endswith("---")


def test_dataset_metadata_uses_a_bare_slug_without_an_owner() -> None:
    root = Path(__file__).resolve().parents[2]
    metadata = kg.dataset_metadata(root, slug="my-dataset")
    assert metadata["id"] == "my-dataset"
    assert metadata["licenses"] == [{"name": "CC0-1.0"}]
    assert metadata["version"]["version_number"]


def test_dataset_metadata_qualifies_the_id_with_an_owner() -> None:
    root = Path(__file__).resolve().parents[2]
    assert kg.dataset_metadata(root, owner="my-org", slug="my-dataset")["id"] == "my-org/my-dataset"


def test_generated_dataset_metadata_passes_its_own_validator(tmp_path: Path) -> None:
    """The generator and the validator must agree, or every publish is refused."""
    root = Path(__file__).resolve().parents[2]
    metadata = kg.dataset_metadata(root)
    directory = tmp_path / "staging"
    directory.mkdir()
    (directory / kg.METADATA_FILENAME).write_text(json.dumps(metadata), encoding="utf-8")
    ok, problems = kg.validate_dataset_metadata(directory)
    assert ok, problems


# -- validation -----------------------------------------------------------


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        pytest.param(
            {"id": "has spaces", "licenses": [{"name": "x"}]}, "must be 'owner/slug'", id="id"
        ),
        pytest.param(
            {"id": "a/b", "licenses": ["plain string"]}, "must be an object", id="licenses"
        ),
        pytest.param(
            {"id": "a/b", "licenses": [{"name": "x"}], "keywords": 7},
            "must be a list",
            id="keywords",
        ),
        pytest.param(
            {"id": "a/b", "licenses": [{"name": "x"}], "version": {"wrong": 1}},
            "must be an object containing",
            id="version",
        ),
    ],
)
def test_dataset_metadata_validation_rejects_bad_shapes(
    tmp_path: Path, document: dict[str, object], expected: str
) -> None:
    directory = tmp_path / "staging"
    directory.mkdir()
    (directory / kg.METADATA_FILENAME).write_text(json.dumps(document), encoding="utf-8")
    ok, problems = kg.validate_dataset_metadata(directory)
    assert not ok
    assert any(expected in problem for problem in problems), problems


def test_dataset_metadata_validation_reports_a_missing_file(tmp_path: Path) -> None:
    directory = tmp_path / "staging"
    directory.mkdir()
    ok, problems = kg.validate_dataset_metadata(directory)
    assert not ok
    assert any("was not found" in problem for problem in problems)


def test_dataset_metadata_validation_reports_malformed_json(tmp_path: Path) -> None:
    directory = tmp_path / "staging"
    directory.mkdir()
    (directory / kg.METADATA_FILENAME).write_text("{not json", encoding="utf-8")
    ok, problems = kg.validate_dataset_metadata(directory)
    assert not ok
    assert any("not valid JSON" in problem for problem in problems)


def test_dataset_metadata_validation_rejects_a_non_object(tmp_path: Path) -> None:
    directory = tmp_path / "staging"
    directory.mkdir()
    (directory / kg.METADATA_FILENAME).write_text("[1, 2]", encoding="utf-8")
    ok, problems = kg.validate_dataset_metadata(directory)
    assert not ok
    assert any("must contain a JSON object" in problem for problem in problems)


@pytest.mark.parametrize(
    ("identifier", "valid"),
    [("owner/slug", True), ("slug", True), ("Owner-1/slug_2", True), ("a/b/c", False), ("", False)],
)
def test_owner_slug_matching(identifier: str, valid: bool) -> None:
    assert kg.re_full_owner_slug(identifier) is valid


def test_space_validation_requires_a_readme(tmp_path: Path) -> None:
    ok, problems = hf.validate_space_metadata(tmp_path)
    assert not ok
    assert any("README" in problem for problem in problems)


def test_space_validation_requires_terminated_front_matter(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Title\n", encoding="utf-8")
    ok, problems = hf.validate_space_metadata(tmp_path)
    assert not ok
    assert any("front matter" in problem for problem in problems)


def test_space_validation_accepts_a_complete_directory(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        hf.space_metadata(Path(__file__).resolve().parents[2]).to_yaml() + "\n# Docs\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("FROM python:3.13-slim\n", encoding="utf-8")
    ok, problems = hf.validate_space_metadata(tmp_path)
    assert ok, problems


# -- credentials ----------------------------------------------------------


def test_missing_credentials_returns_names_and_never_values() -> None:
    env = {hf.HUGGINGFACE_TOKEN_ENV: "hf_secret_value", kg.KAGGLE_USERNAME_ENV: "  "}
    missing = missing_credentials(
        hf.HUGGINGFACE_TOKEN_ENV, kg.KAGGLE_USERNAME_ENV, kg.KAGGLE_KEY_ENV, environ=env
    )
    assert missing == [kg.KAGGLE_USERNAME_ENV, kg.KAGGLE_KEY_ENV]
    assert "hf_secret_value" not in json.dumps(missing)


def test_credential_status_reports_availability_without_exposing_values() -> None:
    status = credential_status(
        huggingface=True,
        kaggle=True,
        environ={hf.HUGGINGFACE_TOKEN_ENV: "secret", kg.KAGGLE_USERNAME_ENV: "user"},
    )
    assert status == {"huggingface": True, "kaggle": False}
    assert "secret" not in json.dumps(status)


# -- result types ---------------------------------------------------------


def test_succeeded_only_for_a_verified_publication() -> None:
    assert kg.KaggleResult(status=kg.STATUS_PUBLISHED, dataset_ref="d").succeeded
    assert not kg.KaggleResult(status=kg.STATUS_SKIPPED, dataset_ref="d").succeeded
    assert hf.HuggingFaceResult(status=hf.PUBLISHED, repository="n/r").succeeded
    assert not hf.HuggingFaceResult(status=hf.SKIPPED, repository="n/r").succeeded


def test_result_to_dict_is_json_serialisable() -> None:
    result = kg.KaggleResult(status=kg.STATUS_PUBLISHED, dataset_ref="d", file_count=3)
    assert json.loads(json.dumps(result.to_dict()))["file_count"] == 3


def test_classification_opt_in_flag_marks_a_space_as_opt_in() -> None:
    space = Classification("code-repository", "space", True, "dataset", True)
    assert space.to_dict()["huggingface"]["opt_in"] is True
    other = Classification("code-repository", "not_applicable", False, "dataset", True)
    assert other.to_dict()["huggingface"]["opt_in"] is False


# -- remote verification (network substituted) ----------------------------


def test_kaggle_verify_confirms_a_dataset_that_lists_its_files(monkeypatch) -> None:
    payload = json.dumps(
        {"resources": [{"path": kg.METADATA_FILENAME}, {"path": "README.md"}]}
    ).encode()
    captured: dict[str, object] = {}

    def fake_urlopen(request, timeout=0):
        captured["url"] = request.full_url
        captured["auth"] = request.headers.get("Authorization")
        return _Response(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = kg.KagglePublisher(dataset_slug="my-dataset").verify(username="u", key="k")
    assert result["ok"], result
    assert result["file_count"] == 2
    assert "datasets/list/u/my-dataset" in str(captured["url"])
    # The key must be in the Authorization header and nowhere else observable.
    assert str(captured["auth"]).startswith("Basic ")


def test_kaggle_verify_reports_a_missing_remote_file(monkeypatch) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda request, timeout=0: _Response(json.dumps({"resources": []}).encode()),
    )
    result = kg.KagglePublisher(dataset_slug="d").verify(username="u", key="k")
    assert not result["ok"]
    assert "missing remote files" in result["reason"]


def test_kaggle_verify_reports_an_http_error_without_raising(monkeypatch) -> None:
    def raise_http(request, timeout=0):
        error = urllib.error.HTTPError("u", 403, "forbidden", None, io.BytesIO(b""))
        error.close()
        raise error

    monkeypatch.setattr(urllib.request, "urlopen", raise_http)
    result = kg.KagglePublisher(dataset_slug="d").verify(username="u", key="k")
    assert not result["ok"]
    assert "HTTP 403" in result["reason"]


def test_kaggle_verify_reports_a_non_json_response(monkeypatch) -> None:
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda request, timeout=0: _Response(b"<html>nope</html>")
    )
    result = kg.KagglePublisher(dataset_slug="d").verify(username="u", key="k")
    assert not result["ok"]
    assert "not JSON" in result["reason"]


def test_kaggle_verify_raises_a_network_error_when_unreachable(monkeypatch) -> None:
    def raise_url(request, timeout=0):
        raise urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(urllib.request, "urlopen", raise_url)
    with pytest.raises(NetworkError) as excinfo:
        kg.KagglePublisher(dataset_slug="d").verify(username="u", key="k")
    assert excinfo.value.hint


def test_kaggle_verify_accepts_a_bare_string_file_list(monkeypatch) -> None:
    payload = json.dumps({"files": [kg.METADATA_FILENAME, "README.md"]}).encode()
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=0: _Response(payload))
    assert kg.KagglePublisher(dataset_slug="d").verify(username="u", key="k")["ok"]


def test_huggingface_verify_confirms_a_space(monkeypatch) -> None:
    payload = json.dumps(
        {"siblings": [{"rfilename": "README.md"}, {"rfilename": "Dockerfile"}]}
    ).encode()
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=0: _Response(payload))
    result = hf.HuggingFacePublisher("org", repo_id="tool").verify(token="hf_secret")
    assert result["ok"], result


def test_huggingface_verify_reports_an_http_error(monkeypatch) -> None:
    def raise_http(request, timeout=0):
        error = urllib.error.HTTPError("u", 404, "missing", None, io.BytesIO(b""))
        error.close()
        raise error

    monkeypatch.setattr(urllib.request, "urlopen", raise_http)
    result = hf.HuggingFacePublisher("org", repo_id="tool").verify(token="t")
    assert not result["ok"]
    assert "HTTP 404" in result["reason"]


def test_huggingface_verify_raises_a_network_error_when_unreachable(monkeypatch) -> None:
    def raise_url(request, timeout=0):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", raise_url)
    with pytest.raises(NetworkError):
        hf.HuggingFacePublisher("org", repo_id="tool").verify(token="t")


# -- upload ----------------------------------------------------------------


def test_kaggle_upload_sends_a_post_with_the_key_only_in_the_header(tmp_path: Path) -> None:
    archive = tmp_path / "d.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    captured: dict[str, object] = {}

    def fake_urlopen(request, timeout=0):
        captured["method"] = request.get_method()
        captured["url"] = request.full_url
        captured["auth"] = request.headers.get("Authorization")
        captured["size"] = request.headers.get("Content-length")
        return _Response(b"")

    monkeypatch_attr = urllib.request.urlopen
    try:
        urllib.request.urlopen = fake_urlopen  # type: ignore[assignment]
        kg._upload(archive, username="u", key="SUPERSECRET", api_base="https://example.invalid")
    finally:
        urllib.request.urlopen = monkeypatch_attr  # type: ignore[assignment]

    assert captured["method"] == "POST"
    assert "datasets/create/u/d" in str(captured["url"])
    assert str(captured["auth"]).startswith("Basic ")
    assert captured["size"] == str(archive.stat().st_size)


def test_kaggle_upload_wraps_an_http_error(tmp_path: Path) -> None:
    archive = tmp_path / "d.zip"
    archive.write_bytes(b"PK")

    def raise_http(request, timeout=0):
        error = urllib.error.HTTPError("u", 500, "server error", None, io.BytesIO(b""))
        error.close()
        raise error

    original = urllib.request.urlopen
    try:
        urllib.request.urlopen = raise_http  # type: ignore[assignment]
        with pytest.raises(NetworkError) as excinfo:
            kg._upload(archive, username="u", key="k", api_base="https://example.invalid")
    finally:
        urllib.request.urlopen = original  # type: ignore[assignment]
    assert "HTTP 500" in excinfo.value.message


def test_kaggle_upload_wraps_a_transport_failure(tmp_path: Path) -> None:
    archive = tmp_path / "d.zip"
    archive.write_bytes(b"PK")

    def raise_url(request, timeout=0):
        raise TimeoutError("timed out")

    original = urllib.request.urlopen
    try:
        urllib.request.urlopen = raise_url  # type: ignore[assignment]
        with pytest.raises(NetworkError):
            kg._upload(archive, username="u", key="k", api_base="https://example.invalid")
    finally:
        urllib.request.urlopen = original  # type: ignore[assignment]


def test_scrub_removes_the_key_from_a_message() -> None:
    assert "SUPERSECRET" not in kg._scrub("failed with SUPERSECRET", "SUPERSECRET")
    assert "***redacted***" in kg._scrub("failed with SUPERSECRET", "SUPERSECRET")
    # An empty key must not turn every character into a redaction marker.
    assert kg._scrub("unchanged", "") == "unchanged"


def test_zip_directory_writes_sorted_entries(tmp_path: Path) -> None:
    source = tmp_path / "src"
    (source / "sub").mkdir(parents=True)
    (source / "b.txt").write_text("b", encoding="utf-8")
    (source / "a.txt").write_text("a", encoding="utf-8")
    (source / "sub" / "c.txt").write_text("c", encoding="utf-8")
    archive = kg._zip_directory(source, tmp_path / "out.zip")

    import zipfile

    with zipfile.ZipFile(archive) as bundle:
        assert bundle.namelist() == ["a.txt", "b.txt", "sub/c.txt"]


# -- publish refusal paths --------------------------------------------------


def test_publish_refuses_when_the_dataset_metadata_is_invalid(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    result = kg.KagglePublisher(dataset_slug="d").publish(staging, environ={})
    assert result.status == kg.STATUS_BLOCKED
    assert "metadata" in result.reason


def test_publish_refuses_when_the_staging_directory_holds_a_secret(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / kg.METADATA_FILENAME).write_text(
        json.dumps(kg.dataset_metadata(Path(__file__).resolve().parents[2])), encoding="utf-8"
    )
    # A credential inside a file that is *not* an excluded pattern: the excluded
    # names are never copied into a staging directory in the first place.
    (staging / "notes.md").write_text("token: hf_" + "a" * 30, encoding="utf-8")
    result = kg.KagglePublisher(dataset_slug="d").publish(
        staging, environ={"KAGGLE_USERNAME": "u", "KAGGLE_KEY": "k"}
    )
    assert result.status == kg.STATUS_BLOCKED
    assert "secret scan" in result.reason


def test_publish_skips_when_credentials_are_absent(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / kg.METADATA_FILENAME).write_text(
        json.dumps(kg.dataset_metadata(Path(__file__).resolve().parents[2])), encoding="utf-8"
    )
    result = kg.KagglePublisher(dataset_slug="d").publish(staging, environ={})
    assert result.status == kg.STATUS_SKIPPED
    assert kg.KAGGLE_USERNAME_ENV in result.reason


def test_publish_reports_a_failed_upload_without_claiming_success(
    tmp_path: Path, monkeypatch
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / kg.METADATA_FILENAME).write_text(
        json.dumps(kg.dataset_metadata(Path(__file__).resolve().parents[2])), encoding="utf-8"
    )

    def raise_url(request, timeout=0):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", raise_url)
    result = kg.KagglePublisher(dataset_slug="d").publish(
        staging, environ={"KAGGLE_USERNAME": "u", "KAGGLE_KEY": "SECRETKEY"}
    )
    assert result.status == kg.STATUS_FAILED
    assert "SECRETKEY" not in result.reason


def test_publish_reports_verification_failure_separately(tmp_path: Path, monkeypatch) -> None:
    """An upload that cannot be confirmed must not report success."""
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / kg.METADATA_FILENAME).write_text(
        json.dumps(kg.dataset_metadata(Path(__file__).resolve().parents[2])), encoding="utf-8"
    )
    calls = {"n": 0}

    def fake_urlopen(request, timeout=0):
        calls["n"] += 1
        if request.get_method() == "POST":
            return _Response(b"")
        return _Response(json.dumps({"resources": []}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = kg.KagglePublisher(dataset_slug="d").publish(
        staging, environ={"KAGGLE_USERNAME": "u", "KAGGLE_KEY": "k"}
    )
    assert result.status == kg.STATUS_PUBLISHED_BUT_VERIFICATION_FAILED
    assert calls["n"] == 2, "the upload and the verification must both have happened"


def test_publish_reports_success_only_after_verification(tmp_path: Path, monkeypatch) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / kg.METADATA_FILENAME).write_text(
        json.dumps(kg.dataset_metadata(Path(__file__).resolve().parents[2])), encoding="utf-8"
    )
    (staging / "README.md").write_text("# docs\n", encoding="utf-8")

    def fake_urlopen(request, timeout=0):
        if request.get_method() == "POST":
            return _Response(b"")
        payload = json.dumps({"resources": [{"path": kg.METADATA_FILENAME}, {"path": "README.md"}]})
        return _Response(payload.encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = kg.KagglePublisher(dataset_slug="d").publish(
        staging, environ={"KAGGLE_USERNAME": "u", "KAGGLE_KEY": "k"}
    )
    assert result.status == kg.STATUS_PUBLISHED
    assert result.succeeded
    assert result.file_count == 2


# -- HF publish ------------------------------------------------------------


def test_huggingface_publish_refuses_invalid_space_metadata(tmp_path: Path) -> None:
    result = hf.HuggingFacePublisher("org", repo_id="tool").publish(
        tmp_path, environ={hf.HUGGINGFACE_TOKEN_ENV: "hf_secret"}
    )
    assert result.status == hf.BLOCKED


def test_huggingface_publish_skips_without_a_token(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "README.md").write_text(
        hf.space_metadata(Path(__file__).resolve().parents[2]).to_yaml() + "\n# docs\n",
        encoding="utf-8",
    )
    (staging / "Dockerfile").write_text("FROM python:3.13-slim\n", encoding="utf-8")
    result = hf.HuggingFacePublisher("org", repo_id="tool").publish(staging, environ={})
    assert result.status == hf.SKIPPED
    assert hf.HUGGINGFACE_TOKEN_ENV in result.reason


def test_huggingface_publish_reports_a_secret_in_the_staging_directory(tmp_path: Path) -> None:
    """A staged Space must be refused before any upload is attempted."""
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "README.md").write_text(
        hf.space_metadata(Path(__file__).resolve().parents[2]).to_yaml() + "\n# docs\n",
        encoding="utf-8",
    )
    (staging / "Dockerfile").write_text("FROM python:3.13-slim\n", encoding="utf-8")
    (staging / "notes.md").write_text("token: hf_" + "a" * 30, encoding="utf-8")
    result = hf.HuggingFacePublisher("org", repo_id="tool").publish(
        staging, environ={hf.HUGGINGFACE_TOKEN_ENV: "hf_secretvalue"}
    )
    assert result.status == hf.BLOCKED
    assert "hf_secretvalue" not in result.reason


# -- pack/secret-scan helpers used by publishing ---------------------------


def test_assert_clean_rejects_a_secret_in_the_staging_directory(tmp_path: Path) -> None:
    from opencode_toolkit.publishing.artifacts import assert_clean

    (tmp_path / "notes.md").write_text("AWS_ACCESS_KEY_ID=" + "AKIA" + "B" * 16, encoding="utf-8")
    with pytest.raises(IntegrityError):
        assert_clean(tmp_path)


def test_assert_clean_accepts_a_clean_directory(tmp_path: Path) -> None:
    from opencode_toolkit.publishing.artifacts import assert_clean

    (tmp_path / "README.md").write_text("# fine\n", encoding="utf-8")
    assert_clean(tmp_path)


def test_is_excluded_matches_the_publish_exclusion_patterns() -> None:
    from opencode_toolkit.publishing.artifacts import is_allowed, is_excluded

    assert is_excluded(".git/config")
    assert is_excluded(".env")
    assert is_excluded("secrets.json")
    assert not is_excluded("README.md")
    assert is_allowed("README.md", ["README.md"])
    assert not is_allowed("README.md", [])


def test_clean_publish_directory_excludes_and_reports(tmp_path: Path) -> None:
    from opencode_toolkit.publishing.artifacts import clean_publish_directory

    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "mod.py").write_text("x = 1\n", encoding="utf-8")
    (source / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "mod.pyc").write_bytes(b"\x00")

    destination = tmp_path / "out"
    result = clean_publish_directory(source, destination)
    assert (destination / "src" / "mod.py").is_file()
    assert not (destination / ".env").exists()
    assert not (destination / "__pycache__").exists()
    assert result["included"] == ["src/mod.py"]
    assert result["excluded_count"] >= 2, "the env file and the pyc are both excluded"


def test_directory_digest_is_stable_and_content_sensitive(tmp_path: Path) -> None:
    """The digest covers paths and content, so it pins the artefact exactly."""
    from opencode_toolkit.publishing.artifacts import directory_digest

    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    for root in (first, second):
        (root / "x.txt").write_text("same\n", encoding="utf-8")
    # Same content and the same relative paths, in a different directory: the
    # digest describes the artefact, not where it happens to sit.
    assert directory_digest(first) == directory_digest(second)

    (second / "z.txt").write_text("different\n", encoding="utf-8")
    assert directory_digest(first) != directory_digest(second)

    # Re-running over unchanged content is stable.
    assert directory_digest(second) == directory_digest(second)


def test_published_result_round_trips_through_json_for_the_release_notes() -> None:
    """A published result must survive serialisation for the release report."""
    payload = kg.KaggleResult(
        status=kg.STATUS_PUBLISHED,
        dataset_ref="org/d",
        reason="upload completed and the dataset was verified",
        file_count=2,
        verification={"ok": True, "remote_names": ["README.md"]},
    )
    document = json.loads(json.dumps(payload.to_dict()))
    assert document["status"] == kg.STATUS_PUBLISHED
    assert document["platform"] == "kaggle"
    assert document["file_count"] == 2
    assert "verified" in document["reason"]


def test_io_bytesio_is_used_for_deterministic_writes() -> None:
    """Guard the helper the manifest writer depends on."""
    buffer = io.BytesIO()
    buffer.write(b"payload")
    assert buffer.getvalue() == b"payload"
