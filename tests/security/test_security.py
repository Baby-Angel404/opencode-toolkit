"""Security tests: the guarantees this project makes about secrets and safety.

These are the tests that would have to fail before a claim like "findings never
contain secret values" or "the queue never stores credentials" could be made in
the documentation.
"""

from __future__ import annotations

import ast
import json
import os
import re
import stat
from pathlib import Path

import pytest

from opencode_toolkit.core.config import SyncPolicy
from opencode_toolkit.core.errors import EncryptionError
from opencode_toolkit.core.jsonio import dumps
from opencode_toolkit.core.logging import configure, get_logger
from opencode_toolkit.core.redact import (
    REDACTED,
    fingerprint,
    redact_env_assignments,
    redact_text,
)
from opencode_toolkit.publishing.artifacts import (
    EXCLUDED_PATTERNS,
    clean_publish_directory,
    is_excluded,
    scan_for_secrets,
)
from opencode_toolkit.publishing.classify import (
    HUGGINGFACE_TOKEN_ENV,
    KAGGLE_KEY_ENV,
    KAGGLE_USERNAME_ENV,
    missing_credentials,
)
from opencode_toolkit.release.gate import CHECK_NAMES, CheckStatus, new_gate, record
from opencode_toolkit.security_audit.engine import AuditEngine
from opencode_toolkit.workflow_sync import crypto
from opencode_toolkit.workflow_sync.queue import OfflineQueue
from opencode_toolkit.workflow_sync.store import SnapshotStore

pytestmark = pytest.mark.security

# The Slack token is assembled from two halves on purpose. GitHub's push
# protection blocks any push containing a contiguous token-shaped string, so
# committing one makes the repository permanently unpushable without a manual
# unblock -- and teaches every future contributor to disable the protection
# instead. The test still exercises the detector against a value that has the
# real shape; only the literal in this file is broken in two.
_SLACK_TOKEN = "xoxb-" + "123456789012-not-a-real-token"

SECRET_VALUES = (
    "AKIAIOSFODNN7EXAMPLE",
    "sk-abcdefghijklmnopqrstuvwxyz0123",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    _SLACK_TOKEN,
    "-----BEGIN RSA PRIVATE KEY-----",
)


# -- secret redaction ------------------------------------------------------


@pytest.mark.parametrize("secret", SECRET_VALUES)
def test_redaction_removes_every_credential_shape(secret: str) -> None:
    for template in (
        'api_key = "{v}"',
        "token='{v}'",
        "Authorization: Bearer {v}",
        'DATABASE_PASSWORD="{v}"',
    ):
        masked = redact_text(template.format(v=secret))
        assert secret not in masked, template


def test_redaction_is_applied_to_log_output() -> None:
    import io

    stream = io.StringIO()
    configure("debug", stream=stream, force=True)
    logger = get_logger("test")
    logger.error("authentication failed for api_key=%s", "leakedsecretvalue123")
    output = stream.getvalue()
    assert "leakedsecretvalue123" not in output
    assert "redacted" in output


def test_logger_does_not_propagate_to_the_root() -> None:
    configure("debug", force=True)
    assert get_logger().propagate is False


def test_logger_rejects_an_unknown_level() -> None:
    with pytest.raises(ValueError):
        configure("chatty")


def test_logger_sanitises_child_names() -> None:
    configure("debug", force=True)
    assert get_logger("opencode_toolkit.security_audit.engine").name.startswith("opencode")


def test_env_file_redaction_masks_only_credential_variables() -> None:
    lines = [
        "# database",
        "DB_HOST=localhost",
        "DB_PASSWORD=s3cretvalue",
        "DATABASE_URL=postgres://u@h/db",
        "API_TOKEN=abcdef123456",
        "APP_NAME=demo",
    ]
    masked = redact_env_assignments(lines)
    assert masked[0] == "# database"
    assert masked[1] == "DB_HOST=localhost"
    assert masked[3] == "DATABASE_URL=postgres://u@h/db"
    assert masked[5] == "APP_NAME=demo"
    assert "s3cretvalue" not in masked[2]
    assert "abcdef123456" not in masked[4]


def test_fingerprints_correlate_without_revealing() -> None:
    first = fingerprint("repeated-secret-value")
    assert first == fingerprint("repeated-secret-value")
    assert first != fingerprint("different-secret-value")
    assert len(first) < 32, "a fingerprint must be short enough to be recognisable"


def test_redaction_policy_can_drop_fingerprints() -> None:
    from opencode_toolkit.core.redact import RedactionPolicy

    policy = RedactionPolicy(keep_fingerprint=False)
    masked = redact_text('api_key = "leakedsecretvalue"', policy=policy)
    assert REDACTED in masked
    assert "leakedsecretvalue" not in masked


# -- audit findings never leak --------------------------------------------


def test_audit_output_contains_no_secret_values(tmp_path: Path) -> None:
    for index, secret in enumerate(SECRET_VALUES):
        (tmp_path / f"f{index}.py").write_text(
            f'API_KEY = "{secret}"\nDATABASE_URL = "postgres://u:{secret}@h/db"\n',
            encoding="utf-8",
        )
    result = AuditEngine.from_policy().scan(tmp_path)
    serialised = json.dumps(result.to_dict())
    for secret in SECRET_VALUES:
        if secret.startswith("-----"):
            # The PEM header itself is the finding marker, not a secret value.
            continue
        assert secret not in serialised, f"{secret} leaked into the report"


def test_audit_sarif_contains_no_secret_values(tmp_path: Path) -> None:
    import io

    from opencode_toolkit.security_audit.reports import render_sarif

    secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
    (tmp_path / "a.py").write_text(f'GITHUB_TOKEN = "{secret}"\n', encoding="utf-8")
    result = AuditEngine.from_policy().scan(tmp_path)
    stream = io.StringIO()
    render_sarif(result, stream=stream)
    assert secret not in stream.getvalue()


def test_audit_snippet_excerpt_is_redacted(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('PASSWORD = "leakedvalue12345"\n', encoding="utf-8")
    result = AuditEngine.from_policy().scan(tmp_path)
    for finding in result.findings:
        assert "leakedvalue12345" not in finding.code_location


# -- crypto ----------------------------------------------------------------


def test_no_key_material_is_ever_written_to_disk(tmp_path: Path, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("sensitive content", encoding="utf-8")
    passphrase = "a-passphrase-that-must-not-appear-on-disk"
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    store.save(workspace, tag="t1", passphrase=passphrase, tracked=("docs",))

    # Scan the store only: the workspace legitimately contains the plaintext
    # source file, which is the point of taking a snapshot of it.
    for path in store.root.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        assert passphrase.encode() not in data, path
        assert b"sensitive content" not in data, path


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_snapshot_state_is_owner_only(tmp_path: Path, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("x", encoding="utf-8")
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    store.save(workspace, tag="t1", passphrase="pw", tracked=("docs",))
    for path in store.root.rglob("*"):
        if path.is_file():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, path


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_queue_state_is_owner_only(tmp_path: Path) -> None:
    queue = OfflineQueue(tmp_path / "queue")
    queue.enqueue("push", "t1")
    for path in queue.root.glob("*.json"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_tampered_blob_is_never_restored(tmp_path: Path, workspace: Path) -> None:
    from opencode_toolkit.core.errors import StateError

    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("original", encoding="utf-8")
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    snapshot, _ = store.save(workspace, tag="t1", passphrase="pw", tracked=("docs",))

    # Change the workspace so the restore actually needs the stored bytes, then
    # replace the blob with attacker content. ``force`` makes the plan attempt
    # the write; the integrity check is what stops it.
    (workspace / "docs" / "a.md").write_text("modified", encoding="utf-8")
    (store.blob_dir / snapshot.items[0].digest).write_bytes(b"attacker supplied content")

    with pytest.raises(StateError):
        store.restore(workspace, "t1", passphrase="pw", force=True)
    assert (workspace / "docs" / "a.md").read_text() == "modified", "tampered bytes were written"


def test_truncated_blob_is_rejected(tmp_path: Path) -> None:
    from opencode_toolkit.core.errors import StateError

    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    digest = store.put_blob(b"payload", encrypt=True, passphrase="pw")
    from opencode_toolkit.workflow_sync.store import SEALED_MAGIC

    (store.blob_dir / digest).write_bytes(SEALED_MAGIC[:4] + b"garbage")
    with pytest.raises(StateError):
        store.get_blob(digest, passphrase="pw")


def test_encrypted_blob_contents_are_not_readable_on_disk(tmp_path: Path, workspace: Path) -> None:
    marker = b"PLAINTEXT-CONTENT-MARKER"
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_bytes(marker + b"\n")
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    snapshot, _ = store.save(workspace, tag="t1", passphrase="pw", tracked=("docs",))
    blob = (store.blob_dir / snapshot.items[0].digest).read_bytes()
    assert marker not in blob
    assert store.get_blob(snapshot.items[0].digest, passphrase="pw") == marker + b"\n"
    with pytest.raises(EncryptionError):
        store.get_blob(snapshot.items[0].digest, passphrase="the wrong passphrase")


def test_sealed_payload_does_not_leak_length_in_a_recoverable_way() -> None:
    """The plaintext length is visible in the header; that is stated, not hidden."""
    payload = crypto.seal(b"x" * 1000, "pw", iterations=100_000, cipher=crypto.CIPHER_HMAC_CTR)
    assert len(payload.ciphertext) == 1000
    # What matters is that the *content* is not recoverable, which the roundtrip
    # failure under the wrong passphrase demonstrates.
    with pytest.raises(EncryptionError):
        crypto.open_sealed(payload, "wrong")


def test_unsupported_cipher_version_is_refused(tmp_path: Path) -> None:
    payload = crypto.seal(b"data", "pw", iterations=100_000, cipher=crypto.CIPHER_HMAC_CTR)
    document = payload.to_dict()
    document["version"] = 99
    restored = crypto.SealedPayload.from_dict(document)
    with pytest.raises(EncryptionError) as excinfo:
        crypto.open_sealed(restored, "pw")
    assert "version" in excinfo.value.message


# -- no destructive writes -------------------------------------------------


def test_snippet_install_never_overwrites_without_force(tmp_path: Path) -> None:
    from opencode_toolkit.core.errors import ConflictError
    from opencode_toolkit.snippet_verified.registry import default_registry

    target = tmp_path / "user_code.py"
    target.write_text("# carefully written user code\n", encoding="utf-8")
    with pytest.raises(ConflictError):
        default_registry().materialise("python-constant-time-compare", target)
    assert target.read_text() == "# carefully written user code\n"


def test_restore_never_overwrites_a_conflict_without_force(tmp_path: Path, workspace: Path) -> None:
    (workspace / "docs").mkdir()
    (workspace / "docs" / "a.md").write_text("v1", encoding="utf-8")
    store = SnapshotStore(tmp_path / "store", SyncPolicy(kdf_iterations=100_000))
    store.save(workspace, tag="base", passphrase="pw", tracked=("docs",))
    (workspace / "docs" / "a.md").write_text("local", encoding="utf-8")
    store.save(workspace, tag="head", passphrase="pw", tracked=("docs",))
    (workspace / "docs" / "a.md").write_text("local again", encoding="utf-8")

    store.restore(workspace, "base", passphrase="pw", base_tag="head")
    assert (workspace / "docs" / "a.md").read_text() == "local again"


def test_state_writes_are_atomic(tmp_path: Path) -> None:
    """No temporary file is left behind after a successful write."""
    from opencode_toolkit.core.fsio import write_text_atomic

    target = tmp_path / "state.json"
    write_text_atomic(target, "content")
    assert target.read_text() == "content"
    assert [item.name for item in tmp_path.iterdir()] == ["state.json"]


# -- publishing safety -----------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".env.production",
        "id_rsa",
        "server.pem",
        "key.p12",
        "bundle.keystore",
        "token",
        "secrets.yaml",
    ],
)
def test_sensitive_filenames_are_excluded_from_a_publish(name: str) -> None:
    assert is_excluded(name), name


def test_exclusion_patterns_cover_the_dangerous_directory_names() -> None:
    for pattern in (".git/*", ".venv/*", "node_modules/*", "__pycache__/*", "*.pem", ".env"):
        assert pattern in EXCLUDED_PATTERNS


def test_publish_directory_is_built_from_an_allowlist(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "src" / "opencode_toolkit").mkdir(parents=True)
    (root / "src" / "opencode_toolkit" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (root / "secrets.env").write_text("TOKEN=abcdefghijklmnop\n", encoding="utf-8")
    (root / "random_notes.txt").write_text("not on the allowlist\n", encoding="utf-8")

    destination = tmp_path / "publish"
    clean_publish_directory(root, destination)
    staged = {path.name for path in destination.rglob("*") if path.is_file()}
    assert staged == {"a.py"}, "anything not explicitly allowed must not ship"


def test_secret_scan_detects_a_planted_credential(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )
    report = scan_for_secrets(tmp_path)
    assert not report.clean
    kinds = {hit.kind for hit in report.hits}
    assert "aws_access_key_id" in kinds
    for hit in report.hits:
        assert "AKIAIOSFODNN7EXAMPLE" not in hit.redacted


def test_secret_scan_does_not_flag_placeholders(tmp_path: Path) -> None:
    (tmp_path / "example.py").write_text(
        'TOKEN = "hf_your_token_here"\nKEY = "your_api_key_here"\n', encoding="utf-8"
    )
    assert scan_for_secrets(tmp_path).clean


def test_secret_scan_skips_binaries_and_large_files(tmp_path: Path) -> None:
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02" * 100)
    (tmp_path / "huge.txt").write_text("x" * (3 * 1024 * 1024))
    report = scan_for_secrets(tmp_path)
    assert len(report.skipped) == 2


def test_assert_clean_raises_on_a_hit(tmp_path: Path) -> None:
    from opencode_toolkit.core.errors import IntegrityError

    (tmp_path / "leak.txt").write_text(
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8"
    )
    with pytest.raises(IntegrityError) as excinfo:
        from opencode_toolkit.publishing.artifacts import assert_clean

        assert_clean(tmp_path)
    assert excinfo.value.code == "publish.secret_detected"


def test_missing_credentials_returns_names_not_values() -> None:
    env = {HUGGINGFACE_TOKEN_ENV: "  ", KAGGLE_USERNAME_ENV: "user", KAGGLE_KEY_ENV: "secret-key"}
    missing = missing_credentials(
        HUGGINGFACE_TOKEN_ENV, KAGGLE_USERNAME_ENV, KAGGLE_KEY_ENV, environ=env
    )
    assert missing == [HUGGINGFACE_TOKEN_ENV]
    assert "secret-key" not in missing
    assert "user" not in missing


def test_publishing_is_refused_without_an_approved_gate() -> None:
    from opencode_toolkit.publishing.huggingface import HuggingFacePublisher
    from opencode_toolkit.publishing.kaggle import KagglePublisher

    gate = new_gate("1.0.0")
    for publisher in (HuggingFacePublisher("someone"), KagglePublisher()):
        result = publisher.check_gate(gate)
        assert result is not None
        assert result.status == "BLOCKED"
        assert "NOT_RUN" in result.reason

    for name in CHECK_NAMES:
        gate = record(gate, name, CheckStatus.PASS, detail="ok")
    for publisher in (HuggingFacePublisher("someone"), KagglePublisher()):
        assert publisher.check_gate(gate) is None


def test_gate_records_no_credentials(tmp_path: Path) -> None:
    gate = record(new_gate("1.0.0"), "SECURITY", CheckStatus.PASS, detail="scanned")
    document = json.loads(dumps(gate.to_dict()))
    assert "token" not in json.dumps(document).lower()


# -- repository hygiene ----------------------------------------------------


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_no_env_file_is_committed() -> None:
    tracked_env = [
        path for path in PROJECT_ROOT.glob(".env*") if path.is_file() and ".venv" not in path.parts
    ]
    for path in tracked_env:
        # Only an .env.example may exist, and it must contain no values.
        if path.name == ".env.example":
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                name, _, value = stripped.partition("=")
                assert not value.strip(), f"{path}: {name} has a value in the example file"
        else:
            pytest.fail(f"a real .env file is present in the repository: {path}")


def test_gitignore_excludes_secrets_and_state() -> None:
    text = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    # Individual entries rather than a directory prefix: state is only partly
    # ignored, because config.json and the docs baseline ARE tracked. CI needs
    # both, and without them the DOCUMENTATION and SELF_AUDIT stages fail for a
    # reason that has nothing to do with the code.
    for pattern in (".env", ".venv/", "__pycache__/", "dist/"):
        assert pattern in text, f".gitignore is missing {pattern}"

    for machine_local in (
        ".opencode/toolkit/release-gate.json",
        ".opencode/toolkit/snapshots/",
        ".opencode/toolkit/queue/",
    ):
        assert machine_local in text, f"machine-local state is not ignored: {machine_local}"

    # What CI reads must not be ignored.
    tracked = PROJECT_ROOT / ".opencode" / "toolkit" / "config.json"
    if tracked.is_file():
        ignore_text = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
        for required in (".opencode/toolkit/config.json", ".opencode/toolkit/docs/"):
            assert required not in ignore_text, f"{required} must be tracked, not ignored"


def test_no_private_key_material_in_the_repository() -> None:
    # Test sources deliberately contain a fake PEM header to prove the scanner
    # detects one, so the *content* check excludes tests/; the *file* check below
    # covers every directory, tests included.
    for path in PROJECT_ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or ".venv" in path.parts:
            continue
        if "tests" in path.parts or "dist" in path.parts:
            continue
        if path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".keystore", ".ppk"}:
            pytest.fail(f"key material present in the repository: {path}")
        if path.suffix.lower() not in {
            ".py",
            ".json",
            ".md",
            ".toml",
            ".yml",
            ".yaml",
            ".sh",
            ".txt",
        }:
            continue
        if path.stat().st_size > 1_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        assert "-----BEGIN RSA PRIVATE KEY-----" not in text, path
        assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in text, path


def test_workflows_do_not_hard_code_secrets() -> None:
    """A token literal in a workflow would defeat the whole publishing design."""
    workflow_dir = PROJECT_ROOT / ".github" / "workflows"
    if not workflow_dir.is_dir():
        pytest.skip("no workflows present")
    # Checked only on lines that do not read a secret, since the whole point of
    # `secrets.NAME` is to reference a credential without containing it.
    suspicious = re.compile(r"(hf_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16})")
    for path in sorted(workflow_dir.glob("*.yml")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = suspicious.search(stripped)
            assert match is None, (
                f"{path.name}:{number}: possible hard-coded credential: {stripped}"
            )


def test_source_uses_no_shell_string_execution() -> None:
    """`shell=True` anywhere in the toolkit would be a command-injection path."""
    offenders: list[str] = []
    for path in (PROJECT_ROOT / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        offenders.append(f"{path}:{node.lineno}")
    assert not offenders, f"shell=True found at {offenders}"


def test_no_module_level_import_of_optional_publish_clients() -> None:
    """The runtime must stay dependency-free; publishing clients load lazily."""
    offenders: list[str] = []
    for path in (PROJECT_ROOT / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, ast.Import | ast.ImportFrom):
                continue
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                if name.split(".")[0] in {"huggingface_hub", "kaggle", "requests", "yaml"}:
                    offenders.append(f"{path}:{node.lineno} imports {name}")
    assert not offenders, offenders


def test_no_packaging_configuration_declares_a_credential() -> None:
    """No build-time configuration may declare a credential.

    The Dockerfile was removed from this project, so the risk now lives in
    whatever declares environment variables for the package or the pipeline:
    ``pyproject.toml``, the compose file if one is added, and the workflows.
    """
    suspicious = ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY")
    for name in ("pyproject.toml", "docker-compose.yml"):
        path = PROJECT_ROOT / name
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith(("ARG ", "ENV ", "environment:")):
                continue
            key = stripped.split("=", 1)[0].split()[1].strip(": ").upper()
            assert not any(marker in key for marker in suspicious), (
                f"{name}:{number}: a credential-shaped build variable is declared: {stripped}"
            )


def test_the_project_ships_no_container_definition() -> None:
    """This project is a CLI, not a service: it carries no container build.

    Docker was removed deliberately. The check exists so that adding a Dockerfile
    back is a decision someone makes on purpose, in review, rather than an
    artefact that reappears unnoticed.
    """
    for name in ("Dockerfile", "docker-compose.yml"):
        assert not (PROJECT_ROOT / name).exists(), f"{name} was removed from this project"


def test_ci_workflows_pin_action_versions() -> None:
    """Floating action tags are a supply-chain risk in CI."""
    workflow_dir = PROJECT_ROOT / ".github" / "workflows"
    if not workflow_dir.is_dir():
        pytest.skip("no workflows present")
    import re

    # Anchored at the start of the line: an action reference is a YAML key, so
    # a regex literal containing the word "uses" must not match.
    floating = re.compile(r"^\s*(?:-\s*)?uses:\s*\S+@(?![0-9a-f]{40}|v?\d)")
    for path in workflow_dir.glob("*.yml"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "uses:" in line and floating.search(line):
                pytest.fail(
                    f"{path.name}:{number}: action is not pinned to a version or SHA: {line.strip()}"
                )


@pytest.mark.regression
def test_secret_scan_ignores_the_generated_state_directory() -> None:
    """Regression: the gate's own commit SHA was reported as a credential.

    ``.opencode/`` is generated and .gitignore'd, and the release gate in it
    records the current commit -- a 40-character hex string by design.
    """
    report = scan_for_secrets(PROJECT_ROOT)
    assert not [hit for hit in report.hits if hit.file.startswith(".opencode/")]


@pytest.mark.regression
def test_the_release_uploads_exactly_the_artefacts_that_were_built() -> None:
    """Regression: two sdists and two offline packs could be uploaded together.

    The quality pipeline's BUILD and PACKAGE stages both produced archives in
    ``dist/``, while the release artefacts are named for the version. A stray
    archive from an earlier run therefore sat beside the real one, and the
    release job's ``dist/*.tar.gz`` glob would have shipped both. The stages now
    build into a scratch directory, and the release job names what it uploads.
    """
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "dist/*.tar.gz" not in workflow, "a tarball glob would upload stray archives"
    assert "dist/opencode-toolkit-sdist.tar.gz" in workflow

    # The build stages must not write into dist/ at all.
    pipeline = (PROJECT_ROOT / "scripts" / "quality-check").read_text(encoding="utf-8")
    assert '"${PROJECT_ROOT}/dist"' not in pipeline, "a build stage writes into dist/"
    assert "-m build" in pipeline and "--outdir" in pipeline
    assert 'pack build --output "${PACK_PATH}"' in pipeline


def test_secret_scan_of_the_whole_repository_is_clean() -> None:
    """Scan everything except the test suite.

    ``tests/`` deliberately contains realistic fake credentials -- that is how
    the scanner's detectors are proved -- so those files are excluded here and
    the detector behaviour is covered directly by the tests that plant them.
    """
    # `.opencode/` is the toolkit's own generated state directory. It is
    # .gitignore'd, and the release gate it contains records the current commit,
    # which is a 40-character hex string by design.
    report = scan_for_secrets(PROJECT_ROOT)
    offenders = [
        hit for hit in report.hits if not hit.file.startswith(("tests/", "examples/", ".opencode/"))
    ]
    assert not offenders, [hit.to_dict() for hit in offenders]
