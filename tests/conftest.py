"""Shared fixtures.

Every fixture that touches the filesystem uses ``tmp_path``, and every test that
touches configuration or state sets ``OPENCODE_TOOLKIT_STATE_DIR`` explicitly, so
the suite never reads or writes the developer's real state directory.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from opencode_toolkit.core.config import Config, SyncPolicy, load_config
from opencode_toolkit.core.paths import Layout, resolve_layout

#: Marker sets must match pyproject.toml's ``markers`` list.
MARKERS = ("unit", "integration", "cli", "security", "regression", "slow")


@pytest.fixture(autouse=True)
def _isolate_state(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Point every state-directory lookup at a per-test temporary directory."""
    state = tmp_path_factory.mktemp("state")
    monkeypatch.setenv("OPENCODE_TOOLKIT_STATE_DIR", str(state))
    monkeypatch.setenv("OPENCODE_TOOLKIT_WORKSPACE", "")
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    yield


@pytest.fixture(autouse=True)
def _deterministic_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove ambient credentials so credential tests cannot touch real values."""
    for name in ("HUGGINGFACE_TOKEN", "KAGGLE_USERNAME", "KAGGLE_KEY", "OPENCODE_LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)
    yield


@pytest.fixture
def fast_sync_policy() -> SyncPolicy:
    """A PBKDF2 work factor that is above the enforced floor but fast for tests.

    The floor is 100000 for correctness; the default 600000 is for production.
    Tests use the floor so the suite stays fast while still exercising the real
    KDF path -- a test-only bypass of the KDF would prove nothing.
    """
    return SyncPolicy(kdf_iterations=100_000)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A minimal workspace the toolkit recognises."""
    root = tmp_path / "workspace"
    (root / "src" / "opencode_toolkit").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools>=68.0"]\nbuild-backend = "setuptools.build_meta"\n\n'
        '[project]\nname = "opencode-toolkit"\nversion = "9.9.9"\nrequires-python = ">=3.10"\n'
        "dependencies = []\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def layout(tmp_path: Path, workspace: Path) -> Layout:
    """A resolved layout whose state directory is inside ``tmp_path``."""
    return resolve_layout(workspace=workspace, state_dir=tmp_path / "state")


@pytest.fixture
def config() -> Config:
    """Default configuration with the fast sync policy applied."""

    base = tmp_config()
    return Config(
        sync=fast_sync_policy,
        **{
            key: getattr(base, key)
            for key in (
                "config_version",
                "project_name",
                "security_audit",
                "orchestrator",
                "pack",
                "docs",
                "release",
            )
        },
    )


def tmp_config() -> Config:
    """Configuration built purely from defaults, with no filesystem access."""
    return load_config(
        Layout(
            workspace=Path(os.sep),
            state_dir=Path(os.sep),
            source="test",
            package_root=Path(os.sep),
        )
    )


@pytest.fixture
def cli_invoke(tmp_path: Path, workspace: Path, monkeypatch: pytest.MonkeyPatch):
    """Invoke the CLI in-process and capture stdout, stderr and the exit code.

    Running in-process rather than through a subprocess keeps failures readable
    and makes the suite fast; the installed-entry-point path is covered
    separately by ``test_entrypoint_module``.
    """
    from opencode_toolkit.cli.main import main

    monkeypatch.chdir(workspace)

    class Result:
        def __init__(self) -> None:
            self.code = 0
            self.out = ""
            self.err = ""

        def json(self) -> object:
            import json

            return json.loads(self.out)

    def invoke(*argv: str, cwd: Path | None = None) -> Result:
        import contextlib
        import io

        result = Result()
        out, err = io.StringIO(), io.StringIO()
        if cwd is not None:
            monkeypatch.chdir(cwd)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result.code = main(
                ["--workspace", str(workspace), *argv],
                stdout=out,
                stderr=err,
            )
        result.out = out.getvalue()
        result.err = err.getvalue()
        return result

    return invoke


@pytest.fixture
def write_file(tmp_path: Path):
    """Write a file under ``tmp_path`` and return its path."""
    counter = {"n": 0}

    def _write(relative: str, content: str) -> Path:
        counter["n"] += 1
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    return _write
