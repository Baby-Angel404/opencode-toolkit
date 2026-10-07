"""Task graph model: roles, tasks, writes and statuses.

The ``writes`` list on a task is what makes conflict detection possible. A task
declares the paths it intends to create or modify *before* it runs; two tasks
declaring the same path is a plan error, and a task whose declared file changed
between claim and commit is a conflict. Neither case is resolved silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from opencode_toolkit.core.errors import StateError, UsageError
from opencode_toolkit.core.fsio import sha256_file

PLAN_KIND = "opencode-toolkit/plan"
PLAN_SCHEMA = 1

#: Journal entries are append-only and JSON-lines, one record per line.
JOURNAL_KIND = "opencode-toolkit/journal"


class Role(str, Enum):
    """The five agent roles."""

    PLANNER = "planner"
    CODE_AUTHOR = "code_author"
    TESTER = "tester"
    DOCUMENTATION_MAINTAINER = "documentation_maintainer"
    SECURITY_REVIEWER = "security_reviewer"

    def __str__(self) -> str:
        return self.value


#: Operations each role may perform. Enforced by the coordinator so a Tester
#: cannot write source and a Planner cannot either.
ROLE_CAPABILITIES: dict[Role, frozenset[str]] = {
    Role.PLANNER: frozenset({"plan", "decompose"}),
    Role.CODE_AUTHOR: frozenset({"write", "refactor"}),
    Role.TESTER: frozenset({"test", "verify"}),
    Role.DOCUMENTATION_MAINTAINER: frozenset({"document"}),
    Role.SECURITY_REVIEWER: frozenset({"audit"}),
}

#: Roles permitted to author or modify files. A Tester runs commands but never
#: edits the tree -- that separation is the point of having distinct roles.
WRITE_ROLES = frozenset({Role.CODE_AUTHOR, Role.DOCUMENTATION_MAINTAINER})

#: Roles permitted to execute commands. The Planner is excluded on purpose: it
#: decomposes work and must not have side effects of its own.
EXECUTE_ROLES = frozenset(
    {Role.CODE_AUTHOR, Role.TESTER, Role.DOCUMENTATION_MAINTAINER, Role.SECURITY_REVIEWER}
)


class TaskStatus(str, Enum):
    """Lifecycle of one task."""

    PENDING = "pending"
    BLOCKED = "blocked"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

    def __str__(self) -> str:
        return self.value

    @property
    def is_terminal(self) -> bool:
        """``True`` for statuses a resume will not run again."""
        return self in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED}


@dataclass(frozen=True, slots=True)
class TaskWrite:
    """A path a task intends to write, with the digest known at claim time."""

    path: str
    #: Digest when the file already existed, or ``None`` when it did not.
    expected_sha256: str | None = None

    def verify(self, root: Any) -> bool:
        """Return ``True`` when the on-disk state still matches the claim.

        Args:
            root: Any: Workspace root the relative ``path`` is resolved against;
                it behaves like a ``pathlib.Path``. A ``None`` digest asserts
                the file is still absent -- that is the write-ownership check a
                task must pass before it commits, and it returns ``False`` the
                moment someone else creates the file first.
        """
        target = root / self.path
        if self.expected_sha256 is None:
            return not target.exists()
        return target.is_file() and sha256_file(target) == self.expected_sha256


@dataclass(slots=True)
class Task:
    """One unit of orchestrated work."""

    id: str
    title: str
    role: Role
    depends_on: tuple[str, ...] = ()
    description: str = ""
    command: tuple[str, ...] = ()
    writes: tuple[TaskWrite, ...] = ()
    timeout_seconds: int = 1800
    max_retries: int = 0
    status: TaskStatus = TaskStatus.PENDING
    owner: str = ""
    attempts: int = 0
    exit_code: int | None = None
    started_at: str = ""
    finished_at: str = ""
    notes: list[str] = field(default_factory=list)
    checkpoint_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise the task, flattening each declared write to path and digest."""
        return {
            "id": self.id,
            "title": self.title,
            "role": self.role.value,
            "depends_on": list(self.depends_on),
            "description": self.description,
            "command": list(self.command),
            "writes": [
                {"path": item.path, "expected_sha256": item.expected_sha256} for item in self.writes
            ],
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "status": self.status.value,
            "owner": self.owner,
            "attempts": self.attempts,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "notes": list(self.notes),
            "checkpoint_id": self.checkpoint_id,
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Task:
        """Rebuild a task, defaulting absent fields to the documented values.

        Args:
            document: dict[str, Any]: One entry of a plan document's ``tasks`` list.

        Raises:
            StateError: ``role`` or ``status`` is missing or names an unknown
                member.
        """
        try:
            role = Role(document["role"])
        except (KeyError, ValueError) as exc:
            raise StateError(
                f"task has an invalid role: {exc}", details={"task": document.get("id")}
            ) from exc
        try:
            status = TaskStatus(document.get("status", "pending"))
        except ValueError as exc:
            raise StateError(f"task has an invalid status: {exc}") from exc

        raw_writes = document.get("writes", [])
        writes = tuple(
            TaskWrite(path=str(item["path"]), expected_sha256=item.get("expected_sha256"))
            for item in raw_writes
            if isinstance(item, dict) and "path" in item
        )
        return cls(
            id=str(document["id"]),
            title=str(document.get("title", document["id"])),
            role=role,
            depends_on=tuple(str(item) for item in document.get("depends_on", [])),
            description=str(document.get("description", "")),
            command=tuple(str(item) for item in document.get("command", [])),
            writes=writes,
            timeout_seconds=int(document.get("timeout_seconds", 1800)),
            max_retries=int(document.get("max_retries", 0)),
            status=status,
            owner=str(document.get("owner", "")),
            attempts=int(document.get("attempts", 0)),
            exit_code=document.get("exit_code"),
            started_at=str(document.get("started_at", "")),
            finished_at=str(document.get("finished_at", "")),
            notes=[str(item) for item in document.get("notes", [])],
            checkpoint_id=str(document.get("checkpoint_id", "")),
        )

    def validate(self) -> None:
        """Raise :class:`UsageError` when the task is not runnable as written."""
        if not self.id or not self.id.strip():
            raise UsageError("task id must not be empty", code="orchestrator.invalid_task")
        if not self.title.strip():
            raise UsageError(
                f"task {self.id}: title must not be empty", code="orchestrator.invalid_task"
            )
        if self.command and not self.command[0]:
            raise UsageError(f"task {self.id}: command is empty", code="orchestrator.invalid_task")
        if self.writes and self.role not in WRITE_ROLES:
            raise UsageError(
                f"task {self.id}: role {self.role.value} may not declare file writes",
                code="orchestrator.role_capability_violation",
                details={
                    "task": self.id,
                    "role": self.role.value,
                    "write_roles": sorted(role.value for role in WRITE_ROLES),
                },
            )
        if self.command and self.role not in EXECUTE_ROLES:
            raise UsageError(
                f"task {self.id}: role {self.role.value} may not execute commands",
                code="orchestrator.role_capability_violation",
                details={
                    "task": self.id,
                    "role": self.role.value,
                    "execute_roles": sorted(role.value for role in EXECUTE_ROLES),
                },
            )
        if self.timeout_seconds <= 0:
            raise UsageError(
                f"task {self.id}: timeout_seconds must be positive",
                code="orchestrator.invalid_task",
            )


@dataclass(frozen=True, slots=True)
class Plan:
    """An ordered, validated set of tasks plus its metadata."""

    name: str
    tasks: tuple[Task, ...]
    workspace: str = ""
    description: str = ""
    max_parallel_agents: int = 4
    require_ownership: bool = True

    def by_id(self) -> dict[str, Task]:
        """Index tasks by id; a duplicate id makes the later task win."""
        return {task.id: task for task in self.tasks}

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plan document, stamping kind and schema."""
        return {
            "kind": PLAN_KIND,
            "schema": PLAN_SCHEMA,
            "name": self.name,
            "description": self.description,
            "workspace": self.workspace,
            "max_parallel_agents": self.max_parallel_agents,
            "require_ownership": self.require_ownership,
            "tasks": [task.to_dict() for task in self.tasks],
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Plan:
        """Rebuild a plan after checking kind, schema and task presence.

        Args:
            document: dict[str, Any]: A decoded plan document.

        Raises:
            StateError: The document is not a plan, uses an unsupported schema,
                or carries no tasks.
        """
        if document.get("kind") != PLAN_KIND:
            raise StateError(
                "not an opencode-toolkit plan document",
                code="orchestrator.not_a_plan",
                details={"found_kind": document.get("kind"), "expected": PLAN_KIND},
            )
        schema = document.get("schema")
        if schema != PLAN_SCHEMA:
            raise StateError(
                f"unsupported plan schema {schema!r}; this build understands {PLAN_SCHEMA}",
                code="orchestrator.schema_mismatch",
                details={"schema": schema, "supported": PLAN_SCHEMA},
            )
        raw_tasks = document.get("tasks")
        if not isinstance(raw_tasks, list) or not raw_tasks:
            raise StateError(
                "plan must contain a non-empty 'tasks' list", code="orchestrator.empty_plan"
            )
        tasks = tuple(Task.from_dict(item) for item in raw_tasks)
        return cls(
            name=str(document.get("name", "plan")),
            tasks=tasks,
            workspace=str(document.get("workspace", "")),
            description=str(document.get("description", "")),
            max_parallel_agents=int(document.get("max_parallel_agents", 4)),
            require_ownership=bool(document.get("require_ownership", True)),
        )

    def counts(self) -> dict[str, int]:
        """Task counts by status."""
        counts = {status.value: 0 for status in TaskStatus}
        for task in self.tasks:
            counts[task.status.value] += 1
        return counts
