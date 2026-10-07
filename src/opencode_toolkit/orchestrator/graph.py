"""Dependency graph: validation, cycle detection and ready-set computation.

Validation is total: a plan is checked for unknown dependencies, cycles,
self-dependencies, duplicate ids and write collisions **before** any task runs,
so a malformed plan fails in milliseconds instead of half way through.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.orchestrator.models import Task, TaskStatus


class GraphError(UsageError):
    """The task graph is invalid and cannot be executed."""

    code = "orchestrator.invalid_graph"


@dataclass(frozen=True, slots=True)
class DependencyGraph:
    """A validated DAG of tasks."""

    tasks: dict[str, Task]
    #: Execution levels: tasks in the same level have no dependency between them.
    levels: tuple[tuple[str, ...], ...]

    @classmethod
    def build(cls, tasks: Iterable[Task]) -> DependencyGraph:
        """Validate *tasks* and compute execution levels.

        Args:
            tasks: Iterable[Task]: The plan's tasks. Every task is validated and
                the whole set is checked for duplicate ids, self-dependencies,
                unknown dependencies, write collisions and cycles *before* any
                task runs, so a malformed plan raises :class:`GraphError` here
                rather than failing half way through execution.
        """
        ordered = list(tasks)
        problems: list[str] = []

        by_id: dict[str, Task] = {}
        for task in ordered:
            task.validate()
            if task.id in by_id:
                problems.append(f"duplicate task id: {task.id}")
            by_id[task.id] = task

        for task in ordered:
            if task.id in task.depends_on:
                problems.append(f"task {task.id} depends on itself")
            for dependency in task.depends_on:
                if dependency not in by_id:
                    problems.append(f"task {task.id} depends on unknown task {dependency}")

        # Write collisions: two tasks cannot both author the same path.
        writers: dict[str, str] = {}
        for task in ordered:
            for write in task.writes:
                if write.path in writers:
                    problems.append(
                        f"tasks {writers[write.path]} and {task.id} both write {write.path}"
                    )
                writers[write.path] = task.id

        if problems:
            raise GraphError(
                f"task graph has {len(problems)} problem(s)",
                details={"problems": problems},
            )

        levels = _topological_levels(by_id)
        return cls(tasks=by_id, levels=tuple(tuple(level) for level in levels))

    # -- queries ----------------------------------------------------------
    def ready(
        self, completed: set[str], *, status: dict[str, TaskStatus] | None = None
    ) -> list[Task]:
        """Tasks whose dependencies are all satisfied and which are still pending.

        A task named in *completed* is never returned, so a caller that only has
        the completed set does not re-run finished work.

        Args:
            completed: set[str]: Ids already done. A task in this set is never
                returned, which is what makes resume skip finished work.
            status: dict[str, TaskStatus] | None: Live status overrides by task id
                consulted instead of each task's own ``status`` field. ``None``
                (the default) reads the tasks themselves.
        """
        ready: list[Task] = []
        for task in self.tasks.values():
            if task.id in completed:
                continue
            current = status.get(task.id, task.status) if status else task.status
            if current is not TaskStatus.PENDING:
                continue
            if all(dependency in completed for dependency in task.depends_on):
                ready.append(task)
        ready.sort(key=lambda item: (len(item.depends_on), item.id))
        return ready

    def dependents_of(self, task_id: str) -> list[Task]:
        """Tasks that directly depend on *task_id*.

        Args:
            task_id: str: Id of the task whose immediate dependents are wanted.
                An unknown id yields an empty list rather than an error.
        """
        return [task for task in self.tasks.values() if task_id in task.depends_on]

    def downstream_of(self, task_id: str) -> set[str]:
        """Every task transitively depending on *task_id*.

        Args:
            task_id: str: Root of the reachability walk. It is excluded from the
                result, and a cycle-free graph guarantees termination.
        """
        seen: set[str] = set()
        frontier = [task_id]
        while frontier:
            current = frontier.pop()
            for dependent in self.dependents_of(current):
                if dependent.id not in seen:
                    seen.add(dependent.id)
                    frontier.append(dependent.id)
        return seen

    def iter_level(self, index: int) -> Iterator[Task]:
        """Yield tasks in execution level *index*.

        Args:
            index: int: Zero-based execution level in ``0 <= index < depth``.
                Tasks in one level have no dependency on each other, so the
                coordinator may run them in parallel.
        """
        for task_id in self.levels[index]:
            yield self.tasks[task_id]

    @property
    def depth(self) -> int:
        """Number of execution levels; the coordinator runs them in this order."""
        return len(self.levels)

    def to_dict(self) -> dict[str, object]:
        """Serialise the graph shape: task count, depth and the levels themselves."""
        return {
            "task_count": len(self.tasks),
            "depth": self.depth,
            "levels": [list(level) for level in self.levels],
        }


def _topological_levels(by_id: dict[str, Task]) -> list[list[str]]:
    """Kahn's algorithm, grouped into levels; raises on a cycle."""
    indegree = dict.fromkeys(by_id, 0)
    dependents: dict[str, list[str]] = {task_id: [] for task_id in by_id}
    for task_id, task in by_id.items():
        for dependency in task.depends_on:
            indegree[task_id] += 1
            dependents[dependency].append(task_id)

    ready = sorted(task_id for task_id, degree in indegree.items() if degree == 0)
    levels: list[list[str]] = []
    remaining = len(by_id)
    while ready:
        levels.append(ready)
        remaining -= len(ready)
        nxt: list[str] = []
        for task_id in ready:
            for dependent in sorted(dependents[task_id]):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    nxt.append(dependent)
        ready = sorted(nxt)

    if remaining:
        stuck = sorted(task_id for task_id, degree in indegree.items() if degree > 0)
        raise GraphError(
            "task graph contains a cycle",
            details={"tasks_in_cycle": stuck},
            hint="break the cycle by removing a depends_on edge; orchestration is acyclic by design",
        )
    return levels
