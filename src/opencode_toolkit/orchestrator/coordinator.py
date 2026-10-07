"""The task coordinator.

Responsibilities:

* validate the plan and its graph before anything runs
* run ready tasks up to the configured parallelism
* enforce per-task timeout, retry and ownership
* detect write conflicts and refuse to clobber
* checkpoint on every state transition
* emit a structured journal record for every decision
* produce an honest result, including the failures

Tasks whose dependencies fail are marked ``BLOCKED``, never silently skipped --
a plan that reports success while half its work never ran is the failure mode
this component exists to prevent.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio, logging
from opencode_toolkit.core.config import OrchestratorPolicy
from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.core.timeutil import utc_now
from opencode_toolkit.orchestrator.checkpoint import Checkpoint, CheckpointStore
from opencode_toolkit.orchestrator.executor import Executor, NullExecutor, TaskOutcome
from opencode_toolkit.orchestrator.graph import DependencyGraph
from opencode_toolkit.orchestrator.models import ROLE_CAPABILITIES, Plan, Task, TaskStatus

logger = logging.get_logger("orchestrator.coordinator")


@dataclass(slots=True)
class ExecutionResult:
    """Outcome of one orchestration run."""

    run_id: str
    plan_name: str
    outcomes: list[TaskOutcome] = field(default_factory=list)
    statuses: dict[str, TaskStatus] = field(default_factory=dict)
    checkpoint_id: str = ""
    conflicts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        """``True`` when every task completed and nothing conflicted."""
        if self.conflicts or self.errors:
            return False
        return all(status is TaskStatus.COMPLETED for status in self.statuses.values())

    def completed(self) -> list[str]:
        """Sorted ids of the tasks that completed."""
        return sorted(
            key for key, status in self.statuses.items() if status is TaskStatus.COMPLETED
        )

    def failed(self) -> list[str]:
        """Sorted ids of the tasks that failed outright."""
        return sorted(key for key, status in self.statuses.items() if status is TaskStatus.FAILED)

    def blocked(self) -> list[str]:
        """Sorted ids of the tasks never run because a dependency failed."""
        return sorted(key for key, status in self.statuses.items() if status is TaskStatus.BLOCKED)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the run, sorting every id list and status map for stable output."""
        return {
            "run_id": self.run_id,
            "plan_name": self.plan_name,
            "ok": self.ok,
            "checkpoint_id": self.checkpoint_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 4),
            "completed": self.completed(),
            "failed": self.failed(),
            "blocked": self.blocked(),
            "conflicts": sorted(set(self.conflicts)),
            "errors": list(self.errors),
            "statuses": {key: value.value for key, value in sorted(self.statuses.items())},
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


class Coordinator:
    """Runs a :class:`~opencode_toolkit.orchestrator.models.Plan` to completion."""

    def __init__(
        self,
        workspace: Path,
        *,
        policy: OrchestratorPolicy | None = None,
        executor: Executor | None = None,
        store: CheckpointStore | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.policy = policy or OrchestratorPolicy()
        self.executor = executor or NullExecutor()
        self.store = store or CheckpointStore(
            self.workspace / ".opencode" / "toolkit" / "orchestrator"
        )

    # -- public API -------------------------------------------------------
    def run(
        self,
        plan: Plan,
        *,
        run_id: str | None = None,
        checkpoint: bool = True,
        resume_from: Checkpoint | None = None,
        max_parallel: int | None = None,
    ) -> ExecutionResult:
        """Execute *plan*, optionally resuming from *resume_from*.

        Tasks run level by level, in dependency order. A task whose dependency
        failed is marked ``BLOCKED``, never ``SKIPPED``, so a partial run is
        visibly incomplete.

        Args:
            plan: Plan: Validated plan to execute. Its graph is built first, so
                an invalid plan raises before anything runs. When
                *resume_from* is given the checkpoint's restored plan is used
                instead and *plan* is ignored.
            run_id: str | None: Identifier for this run; one is generated when
                omitted. A resumed run reuses the checkpoint's run id.
            checkpoint: bool: Write a checkpoint after every status transition so
                an interrupted run can be resumed. ``False`` disables the
                writes; the journal still records every event.
            resume_from: Checkpoint | None: Checkpoint whose completed and failed
                task ids are restored onto the plan, so terminal tasks are not
                run again.
            max_parallel: int | None: Cap on tasks run at once; clamped to the
                plan's ``max_parallel_agents`` and the policy's limit.
        """
        import time

        started = time.perf_counter()
        effective_plan = resume_from.restored_plan() if resume_from is not None else plan
        graph = DependencyGraph.build(effective_plan.tasks)

        run_identifier = run_id or (resume_from.run_id if resume_from else self._new_run_id())
        result = ExecutionResult(
            run_id=run_identifier,
            plan_name=effective_plan.name,
            started_at=utc_now(),
        )
        result.statuses = {task.id: task.status for task in graph.tasks.values()}

        parallelism = self._parallelism(effective_plan, max_parallel)
        self._journal(
            "run_started",
            run_id=run_identifier,
            plan=effective_plan.name,
            tasks=len(graph.tasks),
            depth=graph.depth,
            parallelism=parallelism,
            executor=self.executor.describe(),
            resumed_from=resume_from.identifier if resume_from else None,
        )

        completed: set[str] = {
            task_id for task_id, status in result.statuses.items() if status is TaskStatus.COMPLETED
        }
        failed: set[str] = {
            task_id for task_id, status in result.statuses.items() if status is TaskStatus.FAILED
        }

        level_index = 0
        while level_index < graph.depth:
            level = list(graph.iter_level(level_index))
            pending = [task for task in level if result.statuses.get(task.id) is TaskStatus.PENDING]
            level_index += 1
            if not pending:
                continue

            # A task whose dependency failed is blocked, not skipped.
            runnable: list[Task] = []
            for task in pending:
                if any(dependency in failed for dependency in task.depends_on):
                    result.statuses[task.id] = TaskStatus.BLOCKED
                    result.errors.append(
                        f"task {task.id} blocked: dependency {self._first_failed(task, failed)} failed"
                    )
                    self._journal(
                        "task_blocked",
                        run_id=run_identifier,
                        task=task.id,
                        reason="dependency_failed",
                        depends_on=list(task.depends_on),
                    )
                    if checkpoint:
                        self._checkpoint(effective_plan, run_identifier, result)
                    continue
                runnable.append(task)

            if not runnable:
                continue

            outcomes = self._execute_level(runnable, run_identifier, parallelism)
            for task, outcome in zip(runnable, outcomes, strict=True):
                result.outcomes.append(outcome)
                result.statuses[task.id] = self._apply_outcome(task, outcome)
                if outcome.ok:
                    completed.add(task.id)
                else:
                    failed.add(task.id)
                result.conflicts.extend(outcome.conflicts)
                self._journal(
                    "task_finished",
                    run_id=run_identifier,
                    task=task.id,
                    role=task.role.value,
                    ok=outcome.ok,
                    exit_code=outcome.exit_code,
                    error=outcome.error,
                    conflicts=sorted(outcome.conflicts),
                    output_preview=outcome.output[:400],
                )
                if checkpoint:
                    self._checkpoint(effective_plan, run_identifier, result)

        result.finished_at = utc_now()
        result.duration_seconds = time.perf_counter() - started
        self._journal(
            "run_finished",
            run_id=run_identifier,
            ok=result.ok,
            completed=len(result.completed()),
            failed=len(result.failed()),
            blocked=len(result.blocked()),
            duration_seconds=round(result.duration_seconds, 4),
        )
        return result

    def status(self, plan: Plan | None = None) -> dict[str, Any]:
        """Aggregate orchestrator status for ``opencode orchestrator status``.

        Args:
            plan: Plan | None: Plan to summarise by role and status. ``None``
                omits the ``plan`` key instead of guessing a plan.
        """
        checkpoints = self.store.list_checkpoints()
        latest = checkpoints[0] if checkpoints else None
        plan_view: dict[str, Any] | None = None
        if plan is not None:
            plan_view = {
                "name": plan.name,
                "tasks": len(plan.tasks),
                "by_role": self._by_role(plan),
                "by_status": plan.counts(),
            }
        return {
            "workspace": str(self.workspace),
            "executor": self.executor.describe(),
            "policy": {
                "max_parallel_agents": self.policy.max_parallel_agents,
                "task_timeout_seconds": self.policy.task_timeout_seconds,
                "max_task_retries": self.policy.max_task_retries,
                "require_ownership": self.policy.require_ownership,
                "checkpoint_on_transition": self.policy.checkpoint_on_transition,
            },
            "checkpoint_directory": str(self.store.root),
            "checkpoint_count": len(checkpoints),
            "latest_checkpoint": latest,
            "journal_records": len(self.store.journal()),
            "plan": plan_view,
        }

    def tasks(self, plan: Plan | None = None) -> list[dict[str, Any]]:
        """Task list for ``opencode orchestrator tasks``.

        Args:
            plan: Plan | None: Plan to list. ``None`` falls back to the plan
                stored in the newest checkpoint, and an empty list is returned
                when there is no checkpoint either.
        """
        if plan is None:
            latest = self._latest_plan()
            if latest is None:
                return []
            plan = latest.plan
        by_id = plan.by_id()
        return [
            {
                "id": task.id,
                "title": task.title,
                "role": task.role.value,
                "status": task.status.value,
                "owner": task.owner,
                "depends_on": list(task.depends_on),
                "writes": [write.path for write in task.writes],
                "capabilities": sorted(ROLE_CAPABILITIES[task.role]),
            }
            for task in sorted(plan.tasks, key=lambda item: (len(item.depends_on), item.id))
            if by_id
        ]

    # -- execution --------------------------------------------------------
    def _execute_level(self, tasks: list[Task], run_id: str, parallelism: int) -> list[TaskOutcome]:
        if len(tasks) == 1 or parallelism <= 1:
            return [self._execute_one(task, run_id) for task in tasks]
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as pool:
            futures = {pool.submit(self._execute_one, task, run_id): task for task in tasks}
            ordered: list[TaskOutcome] = []
            for future in concurrent.futures.as_completed(futures):
                task = futures[future]
                try:
                    ordered.append(future.result())
                except Exception as exc:
                    ordered.append(
                        TaskOutcome(
                            task_id=task.id,
                            ok=False,
                            error=f"executor raised {type(exc).__name__}: {exc}",
                        )
                    )
            by_id = {outcome.task_id: outcome for outcome in ordered}
            return [by_id[task.id] for task in tasks]

    def _execute_one(self, task: Task, run_id: str) -> TaskOutcome:
        attempts = max(0, task.max_retries or self.policy.max_task_retries)
        outcome: TaskOutcome | None = None
        for attempt in range(attempts + 1):
            self._journal(
                "task_started",
                run_id=run_id,
                task=task.id,
                role=task.role.value,
                owner=self._owner_for(task),
                attempt=attempt + 1,
                command=list(task.command),
                writes=[write.path for write in task.writes],
            )
            outcome = self.executor.execute(task, workspace=self.workspace, run_id=run_id)
            if outcome.ok or not outcome.retryable or attempt == attempts:
                break
            self._journal(
                "task_retry", run_id=run_id, task=task.id, attempt=attempt + 1, error=outcome.error
            )
        assert outcome is not None
        return outcome

    def _apply_outcome(self, task: Task, outcome: TaskOutcome) -> TaskStatus:
        if outcome.ok:
            return TaskStatus.COMPLETED
        if outcome.conflicts:
            task.notes.append(f"write conflict on {', '.join(sorted(outcome.conflicts))}")
            return TaskStatus.FAILED
        return TaskStatus.FAILED

    # -- helpers ----------------------------------------------------------
    def _parallelism(self, plan: Plan, override: int | None) -> int:
        value = override if override is not None else plan.max_parallel_agents
        return max(1, min(value, self.policy.max_parallel_agents, max(1, len(plan.tasks))))

    def _owner_for(self, task: Task) -> str:
        return task.owner or f"agent:{task.role.value}"

    @staticmethod
    def _first_failed(task: Task, failed: set[str]) -> str:
        return next((dep for dep in task.depends_on if dep in failed), "unknown")

    @staticmethod
    def _by_role(plan: Plan) -> dict[str, int]:
        counts: dict[str, int] = {}
        for task in plan.tasks:
            counts[task.role.value] = counts.get(task.role.value, 0) + 1
        return dict(sorted(counts.items()))

    def _journal(self, event: str, **fields: Any) -> None:
        record = {"event": event, "at": utc_now(), "run_id": fields.pop("run_id", ""), **fields}
        self.store.append_journal(record)

    def _checkpoint(self, plan: Plan, run_id: str, result: ExecutionResult) -> Checkpoint:
        checkpoint = Checkpoint(
            identifier=self.store.new_checkpoint_id(),
            run_id=run_id,
            plan_name=plan.name,
            created_at=utc_now(),
            plan=_plan_with_statuses(plan, result.statuses),
            completed=tuple(result.completed()),
            failed=tuple(result.failed()),
            executor=self.executor.name,
        )
        self.store.save(checkpoint)
        result.checkpoint_id = checkpoint.identifier
        return checkpoint

    def _latest_plan(self) -> Checkpoint | None:
        summaries = self.store.list_checkpoints()
        if not summaries:
            return None
        return self.store.load(str(summaries[0]["id"]))

    @staticmethod
    def _new_run_id() -> str:
        from opencode_toolkit.orchestrator.executor import new_run_id

        return new_run_id()

    def load_plan(self, path: Path) -> Plan:
        """Read a plan document, converting parse failures into usage errors.

        Args:
            path: Path: JSON plan document to read. A missing file, a malformed
                document or an unsupported schema all raise :class:`UsageError`
                with a hint pointing at ``plan-example``.
        """
        if not path.is_file():
            raise UsageError(f"plan file not found: {path}", details={"path": str(path)})
        try:
            return Plan.from_dict(jsonio.read(path))
        except Exception as exc:
            raise UsageError(
                f"cannot load plan {path}: {exc}",
                code="orchestrator.invalid_plan",
                details={"path": str(path)},
                hint="run `opencode orchestrator plan-example > plan.json` and compare against the schema",
            ) from exc


def _plan_with_statuses(plan: Plan, statuses: dict[str, TaskStatus]) -> Plan:
    tasks = []
    for task in plan.tasks:
        task.status = statuses.get(task.id, task.status)
        tasks.append(task)
    return Plan(
        name=plan.name,
        tasks=tuple(tasks),
        workspace=plan.workspace,
        description=plan.description,
        max_parallel_agents=plan.max_parallel_agents,
        require_ownership=plan.require_ownership,
    )
