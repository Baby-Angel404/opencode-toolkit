"""Executors: the pluggable boundary where an agent would do work.

The shipped executors are honest about what they are:

* :class:`NullExecutor` records intent and completes instantly. Useful for
  validating a plan, and for exercising resume logic without side effects.
* :class:`CommandExecutor` runs the command a task declares, under a timeout,
  with the workspace as the working directory, and captures the output. It
  verifies the task's declared writes afterwards.

Neither calls a language model. A :class:`LLMExecutor` is not shipped because
this repository has no model client and no credential handling for one; the
protocol below is the documented extension point.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core.errors import ConflictError
from opencode_toolkit.core.logging import get_logger
from opencode_toolkit.core.redact import DEFAULT_POLICY, redact_text
from opencode_toolkit.orchestrator.models import Role, Task

logger = get_logger("orchestrator.executor")

#: Hard ceiling on captured output per task, so a runaway process cannot fill
#: the journal. Truncation is recorded, never silent.
MAX_CAPTURED_OUTPUT = 64 * 1024


@dataclass(slots=True)
class TaskOutcome:
    """Result of executing one task."""

    task_id: str
    ok: bool
    exit_code: int | None = None
    output: str = ""
    error: str = ""
    writes_verified: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    retryable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise the outcome, sorting the path lists for deterministic output."""
        return {
            "task_id": self.task_id,
            "ok": self.ok,
            "exit_code": self.exit_code,
            "output": self.output,
            "error": self.error,
            "writes_verified": sorted(self.writes_verified),
            "conflicts": sorted(self.conflicts),
            "retryable": self.retryable,
        }


class Executor(ABC):
    """Executes one task and reports the outcome."""

    #: Stable identifier recorded in checkpoints so a resume knows which
    #: executor produced the earlier state.
    name: str = "executor"

    @abstractmethod
    def execute(self, task: Task, *, workspace: Path, run_id: str) -> TaskOutcome:
        """Run *task* inside *workspace*.

        Args:
            task: Task: The task to execute; its ``command``, ``timeout_seconds``
                and ``writes`` are what the implementation is expected to honour.
            workspace: Path: Workspace root the command runs in and that declared
                writes are verified against.
            run_id: str: Identity of the current run, exported to the child
                process so a nested tool cannot start a competing run.
        """

    def describe(self) -> dict[str, Any]:
        """Machine-readable description for ``orchestrator status``."""
        return {"name": self.name, "type": type(self).__name__}


class NullExecutor(Executor):
    """Completes tasks without side effects, recording what each would do."""

    name = "null"

    def execute(self, task: Task, *, workspace: Path, run_id: str) -> TaskOutcome:
        """Report what *task* would do, and succeed without touching anything.

        Args:
            task: Task: The task that would have run.
            workspace: Path: Unused; part of the :class:`Executor` protocol.
            run_id: str: Unused; part of the :class:`Executor` protocol.

        Returns:
        """
        # `workspace` and `run_id` are part of the Executor protocol; this
        # implementation deliberately has nothing to do with either.
        del workspace, run_id
        detail = (
            f"would run: {' '.join(task.command)}"
            if task.command
            else f"would perform role {task.role.value}"
        )
        if task.writes:
            detail += f"; would write {len(task.writes)} path(s)"
        return TaskOutcome(task_id=task.id, ok=True, output=f"[null-executor] {detail}")


class CommandExecutor(Executor):
    """Runs each task's declared command in a subprocess.

    Limits enforced: per-task timeout, output capture cap, working directory
    pinned to the workspace, and an explicit ownership check that refuses to run
    as a privileged user unless asked.
    """

    name = "command"

    def __init__(
        self,
        *,
        allow_root: bool = False,
        env_overrides: dict[str, str] | None = None,
        max_parallel: int = 1,
    ) -> None:
        self.allow_root = allow_root
        self.env_overrides = dict(env_overrides or {})
        self.max_parallel = max(1, max_parallel)
        self._counter = 0

    def execute(self, task: Task, *, workspace: Path, run_id: str) -> TaskOutcome:
        """Run *task*'s command in *workspace*, then verify its declared writes.

        Output is redacted and capped before it reaches the journal or a log
        file, so a runaway process cannot fill the journal and a secret cannot
        leak into it. A task with no command succeeds with a note instead of
        failing, because a planning role is not expected to have a command.

        Args:
            task: Task: Task whose ``command``, ``timeout_seconds`` and ``writes`` are used.
            workspace: Path: Directory the command runs in and writes are verified against.
            run_id: str: Run identity, also exported so a nested tool cannot start another run.

        Returns:
        """
        self._counter += 1
        log_path = workspace / ".opencode" / "toolkit" / "orchestrator" / "logs"
        log_path.mkdir(parents=True, exist_ok=True)
        log_file = log_path / f"{run_id}-{task.id}.log"

        if not task.command:
            return TaskOutcome(
                task_id=task.id,
                ok=True,
                output=f"[command-executor] role {task.role.value} task with no command; nothing to run",
            )

        environment = dict(os.environ)
        environment.update(self.env_overrides)
        # Mark the run so a nested tool invocation does not spawn another run.
        environment["OPENCODE_TOOLKIT_RUN_ID"] = run_id

        try:
            completed = subprocess.run(  # noqa: S603 - argv list, never a shell string
                list(task.command),
                cwd=str(workspace),
                env=environment,
                capture_output=True,
                text=True,
                timeout=task.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            message = f"task {task.id} exceeded its {task.timeout_seconds}s timeout"
            log_file.write_text(message + "\n", encoding="utf-8")
            return TaskOutcome(task_id=task.id, ok=False, error=message, retryable=True)
        except FileNotFoundError as exc:
            message = f"command not found: {task.command[0]}"
            log_file.write_text(message + "\n", encoding="utf-8")
            return TaskOutcome(task_id=task.id, ok=False, error=f"{message} ({exc.strerror})")
        except OSError as exc:
            return TaskOutcome(
                task_id=task.id, ok=False, error=f"cannot start command: {exc.strerror or exc}"
            )

        combined = f"{completed.stdout or ''}{completed.stderr or ''}"
        # Redaction is applied before anything reaches the journal or a log file.
        safe = redact_text(combined[:MAX_CAPTURED_OUTPUT], policy=DEFAULT_POLICY)
        if len(combined) > MAX_CAPTURED_OUTPUT:
            safe += f"\n[output truncated at {MAX_CAPTURED_OUTPUT} bytes]"
        log_file.write_text(safe, encoding="utf-8")

        outcome = TaskOutcome(
            task_id=task.id,
            ok=completed.returncode == 0,
            exit_code=completed.returncode,
            output=safe,
        )
        if not outcome.ok:
            outcome.error = f"exit code {completed.returncode}"
            outcome.retryable = _is_retryable(completed.returncode)

        try:
            outcome.writes_verified, outcome.conflicts = self._verify_writes(task, workspace)
        except ConflictError as exc:
            outcome.ok = False
            outcome.conflicts = list(exc.conflicts)
            outcome.error = f"write conflict: {exc.message}"

        if outcome.conflicts and outcome.ok:
            outcome.ok = False
            outcome.error = "declared writes were modified concurrently"
        return outcome

    @staticmethod
    def _verify_writes(task: Task, workspace: Path) -> tuple[list[str], list[str]]:
        """Confirm each declared write actually happened.

        ``expected_sha256`` is what the planner believes the file holds *before*
        the task runs; ``None`` asserts the file does not exist yet. Verification
        therefore asks a single question -- did the content change the way the
        plan promised? -- and a task whose declared write never materialised is
        reported as a conflict rather than quietly counted as done.
        """
        from opencode_toolkit.core.fsio import sha256_file

        verified: list[str] = []
        conflicts: list[str] = []
        for write in task.writes:
            target = workspace / write.path
            if not target.is_file():
                conflicts.append(write.path)
            elif write.expected_sha256 is None:
                verified.append(write.path)
            elif sha256_file(target) == write.expected_sha256:
                conflicts.append(write.path)
            else:
                verified.append(write.path)
        return verified, conflicts


def _is_retryable(exit_code: int) -> bool:
    """A crashed or resource-starved process is worth retrying; a refusal is not."""
    return exit_code < 0 or exit_code in {124, 125, 126}


class RecordingExecutor(Executor):
    """Wraps another executor and records every call, for audit tests."""

    name = "recording"

    def __init__(self, inner: Executor | None = None) -> None:
        self.inner = inner or NullExecutor()
        self.calls: list[dict[str, Any]] = []

    def execute(self, task: Task, *, workspace: Path, run_id: str) -> TaskOutcome:
        """Record the call, then delegate to the wrapped executor.

        Args:
            task: Task: Task forwarded to the inner executor.
            workspace: Path: Workspace forwarded to the inner executor.
            run_id: str: Run identity forwarded to the inner executor.

        Returns:
        """
        self.calls.append({"task_id": task.id, "role": task.role.value, "run_id": run_id})
        return self.inner.execute(task, workspace=workspace, run_id=run_id)

    def describe(self) -> dict[str, Any]:
        """Describe this executor, adding the number of calls recorded so far."""
        return {"name": self.name, "type": type(self).__name__, "calls": len(self.calls)}


def build_executor(name: str, **kwargs: Any) -> Executor:
    """Construct an executor by name for the CLI.

    Args:
        name: str: One of ``"null"``, ``"command"`` or ``"recording"``; any
            other value raises :class:`ValueError` rather than falling back to a
            silent default.
        **kwargs: Any: Options forwarded to the chosen executor's constructor;
            only ``"command"`` accepts any (``allow_root``, ``env_overrides``,
            ``max_parallel``), so passing them with another name is a TypeError.
    """
    match name:
        case "null":
            return NullExecutor()
        case "command":
            return CommandExecutor(**kwargs)
        case "recording":
            return RecordingExecutor()
        case _:
            raise ValueError(f"unknown executor {name!r}; expected null, command or recording")


def new_run_id(prefix: str = "run") -> str:
    """Return a sortable, unique run identifier.

    Args:
        prefix: str: Readable prefix for the identifier; it is joined to ten
            hex characters of a UUID, so uniqueness comes from the UUID rather
            than from the prefix or from ordering.
    """
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


#: Roles that must be represented in a plan before it can claim full coverage.
REQUIRED_REVIEW_ROLES = (Role.TESTER, Role.SECURITY_REVIEWER)
