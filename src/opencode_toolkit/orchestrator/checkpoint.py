"""Checkpoints and the append-only activity journal.

A checkpoint is a complete, atomically-written snapshot of plan state plus the
run identity. Resuming reads the newest checkpoint, restores task statuses, and
continues only the tasks that are not terminal. The journal is JSON-lines and
append-only so an interrupted run leaves a readable history rather than a
corrupt file.

State files are written with mode 0600: an orchestration plan can contain
commands and absolute paths, which is sensitive in a multi-user environment.
"""

from __future__ import annotations

import os
import stat
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio, logging
from opencode_toolkit.core.errors import NotFoundError, StateError
from opencode_toolkit.core.fsio import ensure_dir
from opencode_toolkit.orchestrator.models import JOURNAL_KIND, Plan, TaskStatus

logger = logging.get_logger("orchestrator.checkpoint")

CHECKPOINT_KIND = "opencode-toolkit/checkpoint"
CHECKPOINT_SCHEMA = 1


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A resumable point in a run."""

    identifier: str
    run_id: str
    plan_name: str
    created_at: str
    plan: Plan
    completed: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    executor: str = ""
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a checkpoint document, embedding the full plan."""
        return {
            "kind": CHECKPOINT_KIND,
            "schema": CHECKPOINT_SCHEMA,
            "id": self.identifier,
            "run_id": self.run_id,
            "plan_name": self.plan_name,
            "created_at": self.created_at,
            "executor": self.executor,
            "completed": list(self.completed),
            "failed": list(self.failed),
            "notes": list(self.notes),
            "plan": self.plan.to_dict(),
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Checkpoint:
        """Rebuild a checkpoint after checking kind, schema and plan presence.

        Args:
            document: dict[str, Any]: A decoded checkpoint document.

        Raises:
            StateError: The document is not a checkpoint, uses an unsupported
                schema, or embeds no plan.
        """
        if document.get("kind") != CHECKPOINT_KIND:
            raise StateError(
                "not an orchestrator checkpoint",
                code="orchestrator.bad_checkpoint",
                details={"found_kind": document.get("kind")},
            )
        schema = document.get("schema")
        if schema != CHECKPOINT_SCHEMA:
            raise StateError(
                f"unsupported checkpoint schema {schema!r}; this build understands {CHECKPOINT_SCHEMA}",
                code="orchestrator.schema_mismatch",
                details={"schema": schema, "supported": CHECKPOINT_SCHEMA},
            )
        raw_plan = document.get("plan")
        if not isinstance(raw_plan, dict):
            raise StateError("checkpoint has no embedded plan", code="orchestrator.bad_checkpoint")
        return cls(
            identifier=str(document["id"]),
            run_id=str(document.get("run_id", "")),
            plan_name=str(document.get("plan_name", "")),
            created_at=str(document.get("created_at", "")),
            plan=Plan.from_dict(raw_plan),
            completed=tuple(str(item) for item in document.get("completed", [])),
            failed=tuple(str(item) for item in document.get("failed", [])),
            executor=str(document.get("executor", "")),
            notes=tuple(str(item) for item in document.get("notes", [])),
        )

    def restored_plan(self) -> Plan:
        """Return the plan with statuses from this checkpoint applied."""
        completed = set(self.completed)
        failed = set(self.failed)
        tasks = []
        for task in self.plan.tasks:
            if task.id in completed:
                task.status = TaskStatus.COMPLETED
            elif task.id in failed:
                task.status = TaskStatus.FAILED
            tasks.append(task)
        return Plan(
            name=self.plan.name,
            tasks=tuple(tasks),
            workspace=self.plan.workspace,
            description=self.plan.description,
            max_parallel_agents=self.plan.max_parallel_agents,
            require_ownership=self.plan.require_ownership,
        )


@dataclass(slots=True)
class CheckpointStore:
    """Durable storage for checkpoints and the activity journal."""

    root: Path
    journal_entries: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        ensure_dir(self.root)

    @property
    def journal_path(self) -> Path:
        """Path of the append-only JSON-lines activity journal."""
        return self.root / "journal.jsonl"

    def save(self, checkpoint: Checkpoint) -> Path:
        """Atomically persist *checkpoint* with owner-only permissions.

        The filename carries a monotonic sequence number. Checkpoints written
        within the same second would otherwise sort by their random identifier,
        and ``--checkpoint latest`` could resume from the wrong one.

        Args:
            checkpoint: Checkpoint: State to persist. Its ``run_id`` and
                ``identifier`` go into the filename, and the path is chmod'd
                owner-only because it records the plan and workspace state.
        """
        sequence = self._next_sequence()
        path = (
            self.root / f"{sequence:08d}-{checkpoint.run_id or 'run'}-{checkpoint.identifier}.json"
        )
        jsonio.write(path, checkpoint.to_dict())
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return path

    def _next_sequence(self) -> int:
        highest = 0
        for path in self.root.glob("*.json"):
            head = path.name.split("-", 1)[0]
            if head.isdigit():
                highest = max(highest, int(head))
        return highest + 1

    def list_checkpoints(self) -> list[dict[str, Any]]:
        """Summaries of every checkpoint, newest first."""
        summaries: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("*.json")):
            if path.name == "journal.jsonl":
                continue
            try:
                document = jsonio.read(path)
            except StateError:
                logger.warning("skipping unreadable checkpoint %s", path.name)
                continue
            if document.get("kind") != CHECKPOINT_KIND:
                continue
            summaries.append(
                {
                    "id": document.get("id"),
                    "run_id": document.get("run_id"),
                    "plan_name": document.get("plan_name"),
                    "created_at": document.get("created_at"),
                    "completed": len(document.get("completed", [])),
                    "failed": len(document.get("failed", [])),
                    "sequence": int(path.name.split("-", 1)[0])
                    if path.name.split("-", 1)[0].isdigit()
                    else 0,
                    "path": str(path),
                }
            )
        # Sequence is the write order, which is what "latest" must mean.
        summaries.sort(key=lambda item: item["sequence"], reverse=True)
        return summaries

    def load(self, identifier: str) -> Checkpoint:
        """Load a checkpoint by id, or the newest when *identifier* is ``"latest"``.

        Args:
            identifier: str: Checkpoint id, or ``"latest"``/``""`` for the
                highest sequence number. An id with no matching file raises
                :class:`NotFoundError` listing the ids that do exist.
        """
        if identifier in {"latest", ""}:
            summaries = self.list_checkpoints()
            if not summaries:
                raise NotFoundError(
                    "no checkpoints found",
                    code="orchestrator.no_checkpoint",
                    details={"directory": str(self.root)},
                    hint="run `opencode orchestrator checkpoint` after a plan has been executed",
                )
            path = Path(str(summaries[0]["path"]))
        else:
            matches = sorted(self.root.glob(f"*-*-{identifier}.json"))
            if not matches:
                matches = [self.root / f"{identifier}.json"]
            path = next((item for item in matches if item.is_file()), matches[0])
            if not path.is_file():
                raise NotFoundError(
                    f"no checkpoint with id {identifier!r}",
                    code="orchestrator.no_checkpoint",
                    details={
                        "id": identifier,
                        "available": [item["id"] for item in self.list_checkpoints()],
                    },
                )
        return Checkpoint.from_dict(jsonio.read(path))

    # -- journal ----------------------------------------------------------
    def append_journal(self, record: dict[str, Any]) -> None:
        """Append one journal record as a single line.

        Args:
            record: dict[str, Any]: Fields to journal. It is copied, not mutated,
                so the caller's dict is unchanged, and ``kind`` defaults to the
                journal kind when absent.
        """
        payload = dict(record)
        payload.setdefault("kind", JOURNAL_KIND)
        line = jsonio.dump_compact(payload) + "\n"
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        self.journal_entries += 1

    def journal(
        self, *, run_id: str | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        """Read journal records, optionally filtered by run, newest last.

        Args:
            run_id: str | None: Only return records for this run. Records with no
                ``run_id`` are kept; ``None`` disables filtering.
            limit: int | None: Keep at most this many of the *newest* records.
        """
        if not self.journal_path.is_file():
            return []
        records: list[dict[str, Any]] = []
        with self.journal_path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    document = jsonio.loads(line, source=str(self.journal_path))
                except StateError:
                    # A torn final line from an interrupted write; the rest stands.
                    logger.warning(
                        "journal contains an unparsable record; stopping the replay there"
                    )
                    break
                if run_id is not None and document.get("run_id") not in {None, run_id}:
                    continue
                records.append(document)
        if limit is not None:
            records = records[-limit:]
        return records

    def iter_journal(self, *, run_id: str | None = None) -> Iterator[dict[str, Any]]:
        """Stream journal records without loading the whole file.

        Args:
            run_id: str | None: Only yield records for this run; ``None``
                disables filtering. Passed through to :meth:`journal`.
        """
        yield from self.journal(run_id=run_id)

    def new_checkpoint_id(self) -> str:
        """Return a fresh checkpoint id; uniqueness comes from the UUID, not ordering."""
        return uuid.uuid4().hex[:12]
