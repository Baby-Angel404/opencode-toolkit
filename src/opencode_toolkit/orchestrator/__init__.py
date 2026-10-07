"""Multi-agent task orchestration.

Five roles -- Planner, Code Author, Tester, Documentation Maintainer and Security
Reviewer -- execute a dependency-ordered task graph with ownership, resource
limits, checkpoints and resumable execution.

Agent execution is pluggable through an :class:`Executor`. The shipped
executors are deterministic and local: one runs declared commands under a
timeout, the other records intent without side effects. **No language model is
called.** Wiring an LLM-backed executor is a supported extension point, and the
documentation says so rather than implying an agent runtime that does not exist.
"""

from __future__ import annotations

from opencode_toolkit.orchestrator.checkpoint import Checkpoint, CheckpointStore
from opencode_toolkit.orchestrator.coordinator import Coordinator, ExecutionResult
from opencode_toolkit.orchestrator.executor import (
    CommandExecutor,
    Executor,
    NullExecutor,
    TaskOutcome,
)
from opencode_toolkit.orchestrator.graph import DependencyGraph, GraphError
from opencode_toolkit.orchestrator.models import (
    Role,
    Task,
    TaskStatus,
    TaskWrite,
)

__all__ = [
    "Checkpoint",
    "CheckpointStore",
    "CommandExecutor",
    "Coordinator",
    "DependencyGraph",
    "ExecutionResult",
    "Executor",
    "GraphError",
    "NullExecutor",
    "Role",
    "Task",
    "TaskOutcome",
    "TaskStatus",
    "TaskWrite",
]
