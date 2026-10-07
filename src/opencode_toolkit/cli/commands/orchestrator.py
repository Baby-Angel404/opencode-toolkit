"""``opencode orchestrator`` -- multi-agent task orchestration."""

from __future__ import annotations

import argparse
from pathlib import Path

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.orchestrator.coordinator import Coordinator, ExecutionResult
from opencode_toolkit.orchestrator.executor import (
    CommandExecutor,
    Executor,
    NullExecutor,
    RecordingExecutor,
)
from opencode_toolkit.orchestrator.models import ROLE_CAPABILITIES, Plan, Role


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "orchestrator",
        help="plan, run and resume multi-agent task graphs",
        description=(
            "Five roles -- planner, code author, tester, documentation maintainer, security "
            "reviewer -- execute a dependency-ordered task graph with ownership, resource "
            "limits, checkpoints and resumable execution. Tasks whose dependencies fail are "
            "reported as blocked, never silently skipped."
        ),
    )
    sub = parser.add_subparsers(dest="orchestrator_command", metavar="<subcommand>")

    status = sub.add_parser("status", help="orchestrator status and checkpoint inventory")
    status.add_argument("--plan", default=None, metavar="PATH", help="plan document to summarise")

    tasks = sub.add_parser("tasks", help="list tasks from a plan or the latest checkpoint")
    tasks.add_argument("--plan", default=None, metavar="PATH")

    run = sub.add_parser("run", help="execute a plan")
    run.add_argument("--plan", required=True, metavar="PATH")
    run.add_argument(
        "--executor",
        choices=["null", "command", "recording"],
        default="null",
        help="null records intent; command runs each task's declared command",
    )
    run.add_argument("--max-parallel", type=int, default=None)
    run.add_argument("--no-checkpoint", action="store_true", help="do not write checkpoints")
    run.add_argument("--run-id", default=None)

    checkpoint = sub.add_parser("checkpoint", help="checkpoint inventory or an explicit save")
    checkpoint.add_argument(
        "--save", action="store_true", help="write a checkpoint for the latest plan"
    )
    checkpoint.add_argument("--id", default="latest", help="checkpoint id to load")

    resume = sub.add_parser("resume", help="resume a run from a checkpoint")
    resume.add_argument("--checkpoint", default="latest", help="checkpoint id (default: latest)")
    resume.add_argument(
        "--plan", default=None, metavar="PATH", help="plan document (default: from checkpoint)"
    )
    resume.add_argument(
        "--executor",
        choices=["null", "command", "recording"],
        default="null",
    )
    resume.add_argument("--max-parallel", type=int, default=None)

    template = sub.add_parser("plan-example", help="print an example plan document")
    template.add_argument("--output", default=None, metavar="PATH")

    sub.add_parser("roles", help="list roles and their capabilities")
    parser.set_defaults(handler=run_orchestrator)


def _executor(name: str) -> Executor:
    match name:
        case "null":
            return NullExecutor()
        case "command":
            return CommandExecutor()
        case "recording":
            return RecordingExecutor(CommandExecutor())
        case _:  # pragma: no cover - argparse constrains the choices
            raise UsageError(f"unknown executor {name!r}")


def _coordinator(context: CliContext, executor: Executor | None = None) -> Coordinator:
    return Coordinator(
        context.workspace,
        policy=context.config.orchestrator,
        executor=executor,
    )


def run_orchestrator(context: CliContext, args: argparse.Namespace) -> int:
    """Dispatch an ``orchestrator`` subcommand.

    Args:
        context: CliContext: Workspace, layout, config and output streams to
            report through.
        args: argparse.Namespace: Parsed ``orchestrator`` options, including the
            selected subcommand and its flags.
    """
    command = getattr(args, "orchestrator_command", None)
    if not command:
        raise UsageError(
            "orchestrator requires a subcommand",
            code="cli.usage",
            details={
                "available": [
                    "status",
                    "tasks",
                    "run",
                    "checkpoint",
                    "resume",
                    "plan-example",
                    "roles",
                ]
            },
        )
    handlers = {
        "status": _cmd_status,
        "tasks": _cmd_tasks,
        "run": _cmd_run,
        "checkpoint": _cmd_checkpoint,
        "resume": _cmd_resume,
        "plan-example": _cmd_plan_example,
        "roles": _cmd_roles,
    }
    return handlers[command](context, args)


def _cmd_status(context: CliContext, args: argparse.Namespace) -> int:
    coordinator = _coordinator(context)
    plan = coordinator.load_plan(Path(args.plan)) if args.plan else None
    payload = coordinator.status(plan)
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
        return exit_codes.OK
    print("Orchestrator status", file=context.stdout)
    print(f"  workspace        {payload['workspace']}", file=context.stdout)
    print(f"  executor         {payload['executor']['type']}", file=context.stdout)
    print(f"  checkpoints      {payload['checkpoint_count']}", file=context.stdout)
    print(f"  journal records  {payload['journal_records']}", file=context.stdout)
    latest = payload.get("latest_checkpoint")
    if latest:
        print(
            f"  latest           {latest['id']} ({latest['completed']} completed, {latest['failed']} failed)",
            file=context.stdout,
        )
    print("\nLimits", file=context.stdout)
    for key, value in payload["policy"].items():
        print(f"  {key:<28} {value}", file=context.stdout)
    if payload.get("plan"):
        print("\nPlan", file=context.stdout)
        print(f"  name             {payload['plan']['name']}", file=context.stdout)
        print(f"  tasks            {payload['plan']['tasks']}", file=context.stdout)
        print(f"  by role          {payload['plan']['by_role']}", file=context.stdout)
    return exit_codes.OK


def _cmd_tasks(context: CliContext, args: argparse.Namespace) -> int:
    coordinator = _coordinator(context)
    plan = coordinator.load_plan(Path(args.plan)) if args.plan else None
    rows = coordinator.tasks(plan)
    if context.output_format == JSON:
        emit_json({"tasks": rows, "count": len(rows)}, context.stdout)
        return exit_codes.OK
    if not rows:
        context.note("no plan available; pass --plan or run a plan first")
        return exit_codes.OK
    print(f"{'ID':<16} {'ROLE':<26} {'STATUS':<11} {'DEPENDS ON':<20} WRITES", file=context.stdout)
    for row in rows:
        depends = ",".join(row["depends_on"]) or "-"
        writes = ",".join(row["writes"]) or "-"
        print(
            f"{row['id'][:15]:<16} {row['role']:<26} {row['status']:<11} "
            f"{depends[:19]:<20} {writes[:40]}",
            file=context.stdout,
        )
    return exit_codes.OK


def _cmd_run(context: CliContext, args: argparse.Namespace) -> int:
    coordinator = _coordinator(context, _executor(args.executor))
    plan = coordinator.load_plan(Path(args.plan))
    if context.dry_run:
        from opencode_toolkit.orchestrator.graph import DependencyGraph

        graph = DependencyGraph.build(plan.tasks)
        print(f"dry run: plan {plan.name!r} is valid", file=context.stdout)
        print(f"  tasks   {len(plan.tasks)}", file=context.stdout)
        print(f"  depth   {graph.depth}", file=context.stdout)
        for index, level in enumerate(graph.levels):
            print(f"  level {index}: {', '.join(level)}", file=context.stdout)
        return exit_codes.OK

    result = coordinator.run(
        plan,
        run_id=args.run_id,
        checkpoint=not args.no_checkpoint,
        max_parallel=args.max_parallel,
    )
    _print_result(context, result)
    return exit_codes.OK if result.ok else exit_codes.FAILURE


def _cmd_resume(context: CliContext, args: argparse.Namespace) -> int:
    coordinator = _coordinator(context, _executor(args.executor))
    try:
        checkpoint = coordinator.store.load(args.checkpoint)
    except Exception as exc:
        raise UsageError(
            f"cannot load checkpoint {args.checkpoint!r}: {exc}",
            code="orchestrator.no_checkpoint",
            details={"checkpoints": [item["id"] for item in coordinator.store.list_checkpoints()]},
        ) from exc

    plan = coordinator.load_plan(Path(args.plan)) if args.plan else checkpoint.plan
    result = coordinator.run(
        plan,
        run_id=checkpoint.run_id,
        resume_from=checkpoint,
        max_parallel=args.max_parallel,
    )
    print(
        f"resumed run {result.run_id} from checkpoint {checkpoint.identifier}", file=context.stdout
    )
    _print_result(context, result)
    return exit_codes.OK if result.ok else exit_codes.FAILURE


def _cmd_checkpoint(context: CliContext, args: argparse.Namespace) -> int:
    coordinator = _coordinator(context)
    if args.save:
        if context.dry_run:
            context.note("dry run: would write a checkpoint")
            return exit_codes.OK
        summaries = coordinator.store.list_checkpoints()
        if not summaries:
            raise UsageError(
                "no run to checkpoint; execute a plan first",
                code="orchestrator.no_checkpoint",
                details={"directory": str(coordinator.store.root)},
            )
        checkpoint = coordinator.store.load(str(summaries[0]["id"]))
        path = coordinator.store.save(checkpoint)
        print(f"wrote checkpoint {path.name}", file=context.stdout)
        return exit_codes.OK

    summaries = coordinator.store.list_checkpoints()
    if context.output_format == JSON:
        emit_json(
            {"count": len(summaries), "checkpoints": summaries},
            context.stdout,
        )
        return exit_codes.OK
    if not summaries:
        context.note("no checkpoints recorded")
        return exit_codes.OK
    print(
        f"{'ID':<16} {'RUN':<22} {'PLAN':<24} {'DONE':>5} {'FAIL':>5} CREATED", file=context.stdout
    )
    for summary in summaries:
        print(
            f"{str(summary['id'])[:15]:<16} {str(summary['run_id'])[:21]:<22} "
            f"{str(summary['plan_name'])[:23]:<24} {summary['completed']:>5} "
            f"{summary['failed']:>5} {summary['created_at']}",
            file=context.stdout,
        )
    return exit_codes.OK


def _cmd_plan_example(context: CliContext, args: argparse.Namespace) -> int:
    from opencode_toolkit.core import jsonio

    document = example_plan(context.workspace)
    text = jsonio.dumps(document, indent=2) + "\n"
    if args.output:
        if context.dry_run:
            context.note(f"dry run: would write {args.output}")
            return exit_codes.OK
        Path(args.output).expanduser().write_text(text, encoding="utf-8")
        print(f"wrote example plan to {args.output}", file=context.stdout)
        return exit_codes.OK
    print(text, end="", file=context.stdout)
    return exit_codes.OK


def example_plan(workspace: Path) -> dict[str, object]:
    """Return a runnable example plan that exercises every role.

    Args:
        workspace: Path: Workspace path recorded in the generated plan.
    """
    plan = Plan(
        name="example-release-check",
        workspace=str(workspace),
        description="Plan the change, implement it, test it, document it and review it.",
        max_parallel_agents=4,
        tasks=(),
    )
    from opencode_toolkit.orchestrator.models import Task, TaskWrite

    tasks = (
        Task(
            id="plan",
            title="Decompose the change into tasks",
            role=Role.PLANNER,
            description="Turn the request into an ordered set of tasks with dependencies.",
        ),
        Task(
            id="implement",
            title="Implement the change",
            role=Role.CODE_AUTHOR,
            depends_on=("plan",),
            command=("python3", "-c", "print('implementing')"),
            writes=(TaskWrite(path="example_output.txt", expected_sha256=None),),
            max_retries=1,
        ),
        Task(
            id="test",
            title="Run the test suite",
            role=Role.TESTER,
            depends_on=("implement",),
            command=("python3", "-c", "print('tests would run here')"),
        ),
        Task(
            id="document",
            title="Update the documentation",
            role=Role.DOCUMENTATION_MAINTAINER,
            depends_on=("implement",),
            description="Reflect the new behaviour in docs/ without touching unrelated prose.",
        ),
        Task(
            id="security-review",
            title="Review for security regressions",
            role=Role.SECURITY_REVIEWER,
            depends_on=("implement",),
            command=(
                "python3",
                "-m",
                "opencode_toolkit",
                "security-audit",
                "src",
                "--fail-on",
                "critical",
            ),
            timeout_seconds=600,
        ),
    )
    plan = Plan(
        name=plan.name,
        workspace=str(workspace),
        description=plan.description,
        max_parallel_agents=plan.max_parallel_agents,
        tasks=tasks,
    )
    return plan.to_dict()


def _cmd_roles(context: CliContext, args: argparse.Namespace) -> int:
    payload = {role.value: sorted(caps) for role, caps in ROLE_CAPABILITIES.items()}
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
        return exit_codes.OK
    print("Roles", file=context.stdout)
    for role, caps in payload.items():
        print(f"  {role:<28} {', '.join(caps)}", file=context.stdout)
    return exit_codes.OK


def _print_result(context: CliContext, result: ExecutionResult) -> None:
    if context.output_format == JSON:
        emit_json(result.to_dict(), context.stdout)
        return
    print(f"\nRun {result.run_id} -- plan {result.plan_name!r}", file=context.stdout)
    print(f"  completed  {len(result.completed())}", file=context.stdout)
    print(f"  failed     {len(result.failed())}", file=context.stdout)
    print(f"  blocked    {len(result.blocked())}", file=context.stdout)
    print(f"  conflicts  {len(result.conflicts)}", file=context.stdout)
    print(f"  duration   {result.duration_seconds:.2f}s", file=context.stdout)
    print(f"  checkpoint {result.checkpoint_id or '(none)'}", file=context.stdout)
    print(f"  outcome    {'OK' if result.ok else 'FAILED'}", file=context.stdout)
    for error in result.errors[:10]:
        print(f"  error      {error}", file=context.stdout)
    for conflict in sorted(set(result.conflicts))[:10]:
        print(f"  conflict   {conflict}", file=context.stdout)
    for outcome in result.outcomes:
        if not outcome.ok:
            print(f"  task {outcome.task_id}: {outcome.error}", file=context.stdout)
