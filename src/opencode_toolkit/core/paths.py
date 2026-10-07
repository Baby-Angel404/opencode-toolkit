"""Filesystem and workspace layout resolution.

State is resolved in a fixed precedence order, and the precedence is printed by
``opencode doctor`` so a surprising path is always explainable:

1. explicit ``--state-dir`` argument
2. ``OPENCODE_TOOLKIT_STATE_DIR`` environment variable
3. ``.opencode/toolkit`` inside the workspace root
4. the XDG state directory, else ``~/.local/state/opencode-toolkit``

Every component funnels through :func:`resolve_workspace` so behaviour is
consistent no matter which command is run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from opencode_toolkit.core.errors import ConfigurationError
from opencode_toolkit.core.version import project_root

STATE_DIR_ENV = "OPENCODE_TOOLKIT_STATE_DIR"
WORKSPACE_ENV = "OPENCODE_TOOLKIT_WORKSPACE"


def find_workspace_root(start: Path | None = None) -> Path:
    """Return the nearest ancestor containing a project marker.

    Markers, in order: ``.opencode/toolkit``, ``pyproject.toml``, ``.git``.

    Args:
        start: Path | None: Directory to start walking up from; defaults to the
            current working directory. Resolved before the walk.
    """
    current = (start or Path.cwd()).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".opencode" / "toolkit").is_dir():
            return candidate
        if (candidate / "pyproject.toml").is_file():
            return candidate
        if (candidate / ".git").exists():
            return candidate
    return current


@dataclass(frozen=True, slots=True)
class Layout:
    """Resolved filesystem layout for one invocation."""

    workspace: Path
    state_dir: Path
    source: str
    package_root: Path
    notes: tuple[str, ...] = field(default=())

    @property
    def snapshots(self) -> Path:
        """Encrypted workflow-sync snapshot store."""
        return self.state_dir / "snapshots"

    @property
    def queue(self) -> Path:
        """Offline operation queue."""
        return self.state_dir / "queue"

    @property
    def orchestrator(self) -> Path:
        """Orchestrator plans, checkpoints and journals."""
        return self.state_dir / "orchestrator"

    @property
    def packs(self) -> Path:
        """Built offline packages."""
        return self.state_dir / "packs"

    @property
    def docs_cache(self) -> Path:
        """Cached documentation drift baselines."""
        return self.state_dir / "docs"

    @property
    def artifacts(self) -> Path:
        """Release artifacts."""
        return self.state_dir / "artifacts"

    def describe(self) -> dict[str, str]:
        """Return a JSON-friendly description used by ``doctor``."""
        return {
            "workspace": str(self.workspace),
            "state_dir": str(self.state_dir),
            "state_dir_source": self.source,
            "snapshots": str(self.snapshots),
            "queue": str(self.queue),
            "orchestrator": str(self.orchestrator),
            "packs": str(self.packs),
            "artifacts": str(self.artifacts),
        }


def default_state_dir(workspace: Path) -> Path:
    """Return the per-workspace state directory.

    Args:
        workspace: Path: Workspace root whose state directory is being derived.

    The result is not resolved, and may not exist yet.

    State is **per project**, always. The XDG base directory is not consulted:
    an XDG location is shared by every project on the machine, and this state
    holds encrypted snapshots of project content alongside the snapshot index,
    so two unrelated repositories would see each other's snapshot tags and one
    project's restore would be able to read the other's blobs.

    Use ``--state-dir`` or ``OPENCODE_TOOLKIT_STATE_DIR`` to put the state
    somewhere else -- a shared volume, say, when the point is to synchronise it
    between machines. That is an explicit choice rather than a fallback.
    """
    return workspace / ".opencode" / "toolkit"


def resolve_workspace(explicit: Path | str | None = None) -> Path:
    """Resolve the workspace root from an argument, the env var, or the cwd.

    Args:
        explicit: Path | str | None: Workspace given on the command line. When
            ``None``, ``OPENCODE_TOOLKIT_WORKSPACE`` is used, and failing that
            :func:`find_workspace_root` from the current directory.

    Raises:
        ConfigurationError: The resolved path does not exist or is not a
            directory.
    """
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.exists():
            raise ConfigurationError(
                f"workspace path does not exist: {path}",
                details={"path": str(path)},
            )
        if not path.is_dir():
            raise ConfigurationError(
                f"workspace path is not a directory: {path}",
                details={"path": str(path)},
            )
        return path.resolve()
    env_value = os.environ.get(WORKSPACE_ENV)
    if env_value:
        path = Path(env_value).expanduser()
        if not path.is_dir():
            raise ConfigurationError(
                f"{WORKSPACE_ENV} points at a non-directory: {path}",
                details={"env": WORKSPACE_ENV, "path": str(path)},
            )
        return path.resolve()
    return find_workspace_root()


def resolve_state_dir(
    workspace: Path,
    *,
    explicit: Path | str | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[Path, str]:
    """Resolve the state directory, returning it with the reason it was chosen.

    Args:
        workspace: Path: Workspace root, consulted only by the final
            workspace-default fallback.
        explicit: Path | str | None: Directory given on the command line. Takes
            precedence over every other source; ``~`` is expanded.
        environ: dict[str, str] | None: Environment mapping to read
            :data:`STATE_DIR_ENV` from. Defaults to ``os.environ``; pass ``{}``
            to ignore the real environment entirely.

    Returns:
        tuple[Path, str]: The resolved directory and a short label naming the
            rule that chose it, e.g. ``"explicit-argument"``.
    """
    env = environ if environ is not None else dict(os.environ)

    if explicit is not None:
        return Path(explicit).expanduser().resolve(), "explicit-argument"

    env_value = env.get(STATE_DIR_ENV)
    if env_value:
        return Path(env_value).expanduser().resolve(), f"environment:{STATE_DIR_ENV}"

    return default_state_dir(workspace).resolve(), "workspace-default"


def resolve_layout(
    *,
    workspace: Path | str | None = None,
    state_dir: Path | str | None = None,
    environ: dict[str, str] | None = None,
) -> Layout:
    """Build the :class:`Layout` for this invocation.

    Args:
        workspace: Path | str | None: Workspace override, forwarded to
            :func:`resolve_workspace`.
        state_dir: Path | str | None: Explicit state directory, which outranks
            the environment variable and the workspace default.
        environ: dict[str, str] | None: Environment mapping used for resolution;
            defaults to ``os.environ``.

    Raises:
        ConfigurationError: The workspace path does not exist or is not a
            directory.
    """
    env = environ if environ is not None else dict(os.environ)
    ws = resolve_workspace(workspace)
    state, source = resolve_state_dir(ws, explicit=state_dir, environ=env)

    notes: list[str] = []
    try:
        state.relative_to(ws)
    except ValueError:
        pass
    else:
        notes.append("state directory lives inside the workspace")
    if source.startswith("environment:"):
        notes.append(f"state directory overridden by {source.split(':', 1)[1]}")

    return Layout(
        workspace=ws,
        state_dir=state,
        source=source,
        package_root=project_root(),
        notes=tuple(notes),
    )
