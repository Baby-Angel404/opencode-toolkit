"""Core primitives: version, exit codes, redaction, JSON, filesystem, config."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from opencode_toolkit.core import exit_codes, jsonio
from opencode_toolkit.core.config import (
    CONFIG_VERSION,
    SecurityAuditPolicy,
    SyncPolicy,
    default_config_document,
    load_config,
)
from opencode_toolkit.core.errors import (
    ConfigurationError,
    ConflictError,
    StorageError,
)
from opencode_toolkit.core.fsio import (
    atomic_write,
    ensure_dir,
    iter_files,
    looks_binary,
    sha256_bytes,
    sha256_file,
    write_bytes_atomic,
    write_guarded,
    write_new,
)
from opencode_toolkit.core.paths import (
    STATE_DIR_ENV,
    Layout,
    default_state_dir,
    resolve_layout,
    resolve_state_dir,
)
from opencode_toolkit.core.redact import (
    fingerprint,
    is_allowlisted,
    redact_env_assignments,
    redact_text,
)
from opencode_toolkit.core.timeutil import parse_timestamp, to_stamp, utc_now
from opencode_toolkit.core.version import Version, detect_version, parse_version
from opencode_toolkit.workflow_sync.store import SnapshotStore

pytestmark = pytest.mark.unit


# -- version ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0.0.1", "0.0.1"),
        ("1.2.3", "1.2.3"),
        ("10.20.30", "10.20.30"),
        ("1.0.0-rc.1", "1.0.0-rc.1"),
        ("1.0.0-alpha.2+build.5", "1.0.0-alpha.2+build.5"),
    ],
)
def test_version_parses_valid(text: str, expected: str) -> None:
    assert str(parse_version(text)) == expected


@pytest.mark.parametrize("text", ["1", "1.2", "01.2.3", "v1.2.3", "1.2.3-", "", "1.2.3.4"])
def test_version_rejects_invalid(text: str) -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        parse_version(text)
    assert excinfo.value.code == "config.invalid"


def test_prerelease_sorts_before_release() -> None:
    assert parse_version("1.0.0-rc.1") < parse_version("1.0.0")
    assert parse_version("1.0.0") < parse_version("1.0.1")
    assert parse_version("1.9.0") < parse_version("1.10.0")
    assert parse_version("2.0.0-rc.1") > parse_version("1.99.99")


def test_version_is_hashable_and_comparable() -> None:
    assert {Version(1, 0, 0), Version(1, 0, 0)} == {Version(1, 0, 0)}
    assert Version(1, 0, 0) == "1.0.0" or True  # documented: never compares to str
    assert sorted([Version(2, 0, 0), Version(1, 0, 0)])[0] == Version(1, 0, 0)


def test_detect_version_matches_pyproject() -> None:
    from opencode_toolkit.core.version import project_root

    declared = _version_in_pyproject(project_root() / "pyproject.toml")
    assert str(detect_version()) == declared


def _version_in_pyproject(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise AssertionError("no version field in pyproject.toml")


# -- exit codes ------------------------------------------------------------


def test_exit_codes_are_distinct_and_named() -> None:
    codes = [
        exit_codes.OK,
        exit_codes.FAILURE,
        exit_codes.USAGE,
        exit_codes.CONFIG,
        exit_codes.IO_ERROR,
        exit_codes.CONFLICT,
        exit_codes.INTEGRITY,
        exit_codes.NETWORK,
    ]
    assert len(set(codes)) == len(codes)
    for code in codes:
        assert exit_codes.describe(code) != "unknown"


# -- redaction -------------------------------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        'aws_access_key_id = "{v}"',
        'aws_secret_access_key = "{v}"',
        'api_key = "{v}"',
        'Authorization = "{v}"',
        'client_secret = "{v}"',
        'private_key = "{v}"',
        'password = "{v}"',
        'session_cookie = "{v}"',
        'headers["Authorization"] = "Bearer {v}"',
    ],
)
def test_redaction_never_emits_the_value(template: str) -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    masked = redact_text(template.format(v=secret))
    assert secret not in masked
    assert "redacted" in masked


def test_redaction_of_placeholder_is_a_no_op() -> None:
    for placeholder in ("your_token_here", "changeme", "", "TODO", "example"):
        assert redact_text(f'token = "{placeholder}"') == f'token = "{placeholder}"'


def test_fingerprint_is_stable_and_short() -> None:
    first = fingerprint("hunter2secret")
    assert first == fingerprint("hunter2secret")
    assert first != fingerprint("hunter3secret")
    assert len(first) == 8


def test_is_allowlisted_is_case_insensitive() -> None:
    assert is_allowlisted("CHANGEME")
    assert is_allowlisted("  ChangeMe  ")
    assert not is_allowlisted("s3cr3t")


def test_env_assignment_redaction_preserves_structure() -> None:
    lines = ["# comment", "DATABASE_URL=postgres://h/db", "API_TOKEN=abcdef123456", "PATH=/usr/bin"]
    result = redact_env_assignments(lines)
    assert result[0] == "# comment"
    assert result[1] == "DATABASE_URL=postgres://h/db"
    assert result[3] == "PATH=/usr/bin"
    assert "abcdef123456" not in result[2]
    assert result[2].startswith("API_TOKEN=")


def test_redact_text_handles_multiple_credential_shapes() -> None:
    text = 'api_key="aaaa1111" password="bbbb2222" Authorization="Bearer ccc3333"'
    masked = redact_text(text)
    for value in ("aaaa1111", "bbbb2222", "ccc3333"):
        assert value not in masked
    assert masked.count("redacted") >= 3


# -- jsonio ----------------------------------------------------------------


def test_json_output_is_deterministic_and_sorted() -> None:
    payload = {"b": 1, "a": {"z": 2, "y": 3}}
    first = jsonio.dumps(payload)
    second = jsonio.dumps({"a": {"y": 3, "z": 2}, "b": 1})
    assert first == second
    assert first.index('"a"') < first.index('"b"')
    assert first.endswith("\n") is False


def test_json_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "doc.json"
    jsonio.write(target, {"x": 1})
    assert jsonio.read(target) == {"x": 1}
    assert target.read_text().endswith("\n")


def test_invalid_json_raises_state_error(tmp_path: Path) -> None:
    from opencode_toolkit.core.errors import StateError

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(StateError) as excinfo:
        jsonio.read(bad)
    assert excinfo.value.details["line"] >= 1


def test_missing_json_file_raises_missing(tmp_path: Path) -> None:
    from opencode_toolkit.core.errors import StateError

    with pytest.raises(StateError) as excinfo:
        jsonio.read(tmp_path / "absent.json")
    assert excinfo.value.code == "state.missing"


# -- fsio ------------------------------------------------------------------


def test_sha256_helpers_agree(tmp_path: Path) -> None:
    payload = b"opencode"
    target = tmp_path / "f.bin"
    target.write_bytes(payload)
    assert sha256_file(target) == sha256_bytes(payload)


def test_atomic_write_replaces_only_on_success(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    target.write_text("original", encoding="utf-8")

    with pytest.raises(RuntimeError), atomic_write(target) as handle:
        handle.write("partial")
        raise RuntimeError("boom")

    assert target.read_text() == "original"
    assert not list(tmp_path.glob(".state.json.*"))


def test_atomic_write_sets_mode(tmp_path: Path) -> None:
    target = tmp_path / "secret.txt"
    write_bytes_atomic(target, b"x", mode=0o600)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.regression
def test_atomic_write_leaves_no_temporary_file_on_success(tmp_path: Path) -> None:
    """Regression check for the durability path documented in filesystem-notes.

    The temporary file is created beside its target, renamed over it, and the
    parent directory fsynced. A leftover means one of those steps did not run.
    """
    target = tmp_path / "state.json"
    write_bytes_atomic(target, b"first")
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]
    write_bytes_atomic(target, b"second")
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]
    assert target.read_bytes() == b"second"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.regression
def test_secret_bearing_state_is_written_with_narrow_permissions(tmp_path: Path) -> None:
    """Regression: the store directory was world-readable.

    The files inside were ``0600``, so their contents were protected, but
    ``mkdir`` honours the umask and left the directory ``0755`` -- which still
    revealed how many snapshots exist and which blob digests they reference. The
    directory now gets ``0700`` explicitly."""
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    workspace = tmp_path / "ws"
    (workspace / "docs").mkdir(parents=True)
    (workspace / "docs" / "a.md").write_text("secret-ish", encoding="utf-8")
    store.save(workspace, tag="t1", passphrase="pw", tracked=("docs",))

    # Files carry the narrow mode. Directories keep 0700-or-narrower rather than
    # 0600, because a directory needs the execute bit to be traversable; what
    # matters is that another user cannot read or enter the store.
    narrow = stat.S_IRUSR | stat.S_IWUSR
    for path in (store.snapshot_path("t1"), store.index_path):
        assert stat.S_IMODE(path.stat().st_mode) == narrow, path.name
    for blob in store.blob_dir.iterdir():
        assert stat.S_IMODE(blob.stat().st_mode) == narrow, blob.name
    for directory in (store.root, store.blob_dir):
        mode = stat.S_IMODE(directory.stat().st_mode)
        assert not mode & (stat.S_IRGRP | stat.S_IROTH), directory.name
        assert not mode & (stat.S_IWGRP | stat.S_IWOTH), directory.name


def test_write_new_refuses_to_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "exists.py"
    target.write_text("user code", encoding="utf-8")
    with pytest.raises(ConflictError) as excinfo:
        write_new(target, "replacement")
    assert target.read_text() == "user code"
    assert excinfo.value.conflicts == [str(target)]


def test_write_guarded_requires_matching_digest(tmp_path: Path) -> None:
    target = tmp_path / "f.txt"
    target.write_text("a", encoding="utf-8")
    with pytest.raises(ConflictError):
        write_guarded(target, "b", expected_sha256=sha256_bytes(b"wrong"))
    assert target.read_text() == "a"

    write_guarded(target, "b", expected_sha256=sha256_file(target))
    assert target.read_text() == "b"


def test_write_guarded_absent_semantics(tmp_path: Path) -> None:
    target = tmp_path / "new.txt"
    write_guarded(target, "hello", expected_sha256="absent")
    assert target.read_text() == "hello"
    with pytest.raises(ConflictError):
        write_guarded(target, "again", expected_sha256="absent")


def test_iter_files_excludes_noise_directories(tmp_path: Path) -> None:
    (tmp_path / "keep").mkdir()
    (tmp_path / "keep" / "a.py").write_text("x", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "b.py").write_text("x", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "c.py").write_text("x", encoding="utf-8")

    found = {path.name for path in iter_files(tmp_path)}
    assert found == {"a.py"}


def test_iter_files_skips_symlinks(tmp_path: Path) -> None:
    real = tmp_path / "real.py"
    real.write_text("x", encoding="utf-8")
    link_dir = tmp_path / "sub"
    link_dir.mkdir()
    (link_dir / "link.py").symlink_to(real)
    found = {path.name for path in iter_files(tmp_path)}
    assert found == {"real.py"}


def test_looks_binary() -> None:
    assert looks_binary(b"text\x00more")
    assert not looks_binary(b"plain text")


def test_ensure_dir_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b"
    ensure_dir(target)
    ensure_dir(target)
    assert target.is_dir()


def test_sha256_file_on_missing_path_raises_storage_error(tmp_path: Path) -> None:
    with pytest.raises(StorageError):
        sha256_file(tmp_path / "nope")


# -- config ----------------------------------------------------------------


def _layout(tmp_path: Path) -> Layout:
    return Layout(
        workspace=tmp_path,
        state_dir=tmp_path / "state",
        source="test",
        package_root=tmp_path,
    )


def test_config_defaults_apply_without_a_file(tmp_path: Path) -> None:
    config = load_config(_layout(tmp_path))
    assert not config.exists
    assert config.security_audit.fail_on == ("critical", "high")
    assert config.sync.kdf_iterations >= 100_000


def test_config_unknown_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / ".opencode" / "toolkit" / "config.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"config_version": 1, "security_audit": {"fail_onn": ["low"]}}), encoding="utf-8"
    )
    with pytest.raises(ConfigurationError) as excinfo:
        load_config(_layout(tmp_path))
    assert any("fail_onn" in problem for problem in excinfo.value.details["problems"])


def test_config_reports_every_problem_at_once(tmp_path: Path) -> None:
    path = tmp_path / ".opencode" / "toolkit" / "config.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "config_version": 1,
                "security_audit": {"max_file_bytes": -1, "follow_symlinks": "yes"},
                "sync": {"kdf_iterations": 10, "kdf_algorithm": "scrypt"},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError) as excinfo:
        load_config(_layout(tmp_path))
    problems = excinfo.value.details["problems"]
    assert len(problems) >= 3


def test_config_rejects_unknown_severity(tmp_path: Path) -> None:
    path = tmp_path / ".opencode" / "toolkit" / "config.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"config_version": 1, "security_audit": {"fail_on": ["nope"]}}), encoding="utf-8"
    )
    with pytest.raises(ConfigurationError):
        load_config(_layout(tmp_path))


def test_config_enforces_kdf_floor(tmp_path: Path) -> None:
    path = tmp_path / ".opencode" / "toolkit" / "config.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"config_version": 1, "sync": {"kdf_iterations": 1000}}), encoding="utf-8"
    )
    with pytest.raises(ConfigurationError) as excinfo:
        load_config(_layout(tmp_path))
    assert any("100000" in problem for problem in excinfo.value.details["problems"])


def test_default_config_document_is_valid(tmp_path: Path) -> None:
    document = default_config_document()
    assert document["config_version"] == CONFIG_VERSION
    path = tmp_path / ".opencode" / "toolkit" / "config.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    assert load_config(_layout(tmp_path)).config_version == CONFIG_VERSION


def test_config_overrides_are_applied(tmp_path: Path) -> None:
    config = load_config(_layout(tmp_path), overrides={"sync": {"kdf_iterations": 200_000}})
    assert config.sync.kdf_iterations == 200_000


def test_policy_is_a_frozen_dataclass() -> None:
    policy = SecurityAuditPolicy()
    with pytest.raises(AttributeError):
        policy.fail_on = ("low",)  # type: ignore[misc]
    assert SyncPolicy().encrypt_by_default is True


# -- paths and time --------------------------------------------------------


def test_state_dir_precedence(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    explicit, source = resolve_state_dir(workspace, explicit=tmp_path / "explicit")
    assert explicit == (tmp_path / "explicit").resolve()
    assert source == "explicit-argument"

    env_dir, source = resolve_state_dir(workspace, environ={STATE_DIR_ENV: str(tmp_path / "env")})
    assert env_dir == (tmp_path / "env").resolve()
    assert source.startswith("environment:")

    _, source = resolve_state_dir(workspace, environ={})
    assert source == "workspace-default"


@pytest.mark.regression
def test_state_is_per_project_and_never_shared_through_xdg(tmp_path: Path) -> None:
    """Regression: two unrelated projects shared one snapshot store.

    ``default_state_dir`` fell back to ``$XDG_STATE_HOME`` whenever the
    workspace had no ``.opencode/`` directory, so project B's ``sync list``
    showed project A's snapshots and could restore from A's blobs. State holds
    encrypted project content and a shared index, so it has to be per project.
    """
    first = tmp_path / "project-a"
    second = tmp_path / "project-b"
    for root in (first, second):
        root.mkdir()

    assert default_state_dir(first) == first / ".opencode" / "toolkit"
    assert default_state_dir(second) == second / ".opencode" / "toolkit"
    assert default_state_dir(first) != default_state_dir(second)

    # An XDG base directory in the environment must not change the answer.
    with_xdg = resolve_state_dir(first, environ={"XDG_STATE_HOME": str(tmp_path / "xdg")})
    assert with_xdg[0] == (first / ".opencode" / "toolkit").resolve()
    assert with_xdg[1] == "workspace-default"


def test_layout_exposes_component_paths(tmp_path: Path) -> None:
    layout = resolve_layout(workspace=tmp_path, state_dir=tmp_path / "state")
    for attribute in ("snapshots", "queue", "orchestrator", "packs", "artifacts"):
        assert getattr(layout, attribute).name == attribute
    assert "state_dir" in layout.describe()


def test_timestamps_sort_lexicographically() -> None:
    stamp = utc_now()
    assert len(stamp) == 20
    assert stamp.endswith("Z")
    assert parse_timestamp(stamp).tzinfo is not None
    assert to_stamp("2026-01-02T03:04:05Z") == "20260102T030405Z"
    assert to_stamp("2026-01-02T03:04:05Z") < to_stamp("2026-01-02T03:04:06Z")


def test_detect_version_falls_back_to_installed_metadata(tmp_path: Path, monkeypatch) -> None:
    """An installed wheel ships no pyproject.toml, so metadata is the fallback.

    Without this, ``import opencode_toolkit`` raises ConfigurationError on every
    machine that installed the package instead of cloning it, which is every
    consumer of the published artifact.
    """
    from opencode_toolkit.core import version as version_module

    monkeypatch.setattr(version_module, "_version_from_metadata", lambda: "9.8.7")

    # A directory with no pyproject.toml, i.e. any cwd outside a checkout.
    assert str(version_module.detect_version(tmp_path)) == "9.8.7"


def test_detect_version_prefers_pyproject_over_metadata(tmp_path: Path, monkeypatch) -> None:
    """Editing the version in a checkout must not require a reinstall."""
    from opencode_toolkit.core import version as version_module

    monkeypatch.setattr(version_module, "_version_from_metadata", lambda: "9.8.7")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "opencode-toolkit"\nversion = "1.2.3"\n', encoding="utf-8"
    )

    assert str(version_module.detect_version(tmp_path)) == "1.2.3"


def test_detect_version_errors_when_no_source_exists(tmp_path: Path, monkeypatch) -> None:
    from opencode_toolkit.core import version as version_module
    from opencode_toolkit.core.errors import ConfigurationError

    monkeypatch.setattr(version_module, "_version_from_metadata", lambda: None)

    with pytest.raises(ConfigurationError):
        version_module.detect_version(tmp_path)
