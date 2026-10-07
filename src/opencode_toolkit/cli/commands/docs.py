"""``opencode docs`` -- documentation drift detection and conservative repair."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.errors import ToolkitError, UsageError
from opencode_toolkit.live_docs.drift import (
    default_baseline_path,
    diff_against_baseline,
    load_baseline,
    write_baseline,
)
from opencode_toolkit.live_docs.scanner import ApiSurface, scan_tree
from opencode_toolkit.live_docs.updater import apply_updates, preview_diff


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "docs",
        help="detect documentation drift and repair docstrings conservatively",
        description=(
            "Extract the public API surface and compare it against a stored baseline. "
            "`docs update` rewrites only the Args/Returns blocks of a docstring and preserves "
            "every line of human prose; anything it cannot handle safely is reported as "
            "needs_review rather than rewritten."
        ),
    )
    sub = parser.add_subparsers(dest="docs_command", metavar="<subcommand>")

    check = sub.add_parser("check", help="fail when the documentation has drifted")
    check.add_argument(
        "--path", default=None, metavar="PATH", help="tree to scan (default: the workspace)"
    )
    check.add_argument("--baseline", default=None, metavar="PATH", help="baseline document")
    check.add_argument(
        "--allow-undocumented",
        action="store_true",
        help="treat undocumented public items as non-blocking",
    )

    scan = sub.add_parser("scan", help="scan the public API surface")
    scan.add_argument("--path", default=None, metavar="PATH")
    scan.add_argument("--include-undocumented", action="store_true")
    scan.add_argument("--write-baseline", action="store_true", help="write the baseline document")
    scan.add_argument("--baseline", default=None, metavar="PATH")
    scan.add_argument("--force", action="store_true", help="overwrite an existing baseline")

    diff = sub.add_parser("diff", help="show what `docs update` would change")
    diff.add_argument("--path", default=None, metavar="PATH")

    update = sub.add_parser("update", help="rewrite docstring parameter blocks")
    update.add_argument("--path", default=None, metavar="PATH")
    update.add_argument("--check", action="store_true", help="report only; write nothing")

    parser.set_defaults(handler=run_docs)


def _scan(context: CliContext, args: argparse.Namespace) -> tuple[Path, ApiSurface]:
    target = Path(args.path).expanduser() if getattr(args, "path", None) else context.workspace
    if not target.exists():
        raise UsageError(f"path does not exist: {target}", details={"path": str(target)})
    return target, scan_tree(target)


def _baseline_for(
    context: CliContext, args: argparse.Namespace, target: Path
) -> tuple[Path, list[dict[str, Any]] | None]:
    """Return the baseline location and its entries, or ``None`` when absent.

    A missing baseline is not an error: it is how a project records its first
    snapshot, and ``check`` reports the whole surface as new.
    """
    path = (
        Path(args.baseline).expanduser()
        if getattr(args, "baseline", None)
        else default_baseline_path(target)
    )
    return path, load_baseline(path) if path.is_file() else None


def run_docs(context: CliContext, args: argparse.Namespace) -> int:
    """Dispatch a ``docs`` subcommand.

    Args:
        context: CliContext: Workspace, layout, config and output streams to
            report through.
        args: argparse.Namespace: Parsed ``docs`` options, including the
            selected subcommand and its flags.
    """
    command = getattr(args, "docs_command", None)
    if not command:
        raise UsageError(
            "docs requires a subcommand",
            code="cli.usage",
            details={"available": ["check", "scan", "diff", "update"]},
        )
    handlers = {"check": _cmd_check, "scan": _cmd_scan, "diff": _cmd_diff, "update": _cmd_update}
    return handlers[command](context, args)


def _cmd_check(context: CliContext, args: argparse.Namespace) -> int:
    target, surface = _scan(context, args)
    path, baseline = _baseline_for(context, args, target)
    report = diff_against_baseline(surface, baseline, baseline_path=path)

    if context.output_format == JSON:
        emit_json(report.to_dict(), context.stdout)
    else:
        print(f"Documentation drift: {target}", file=context.stdout)
        print(f"  public items   {surface.counts().get('total', 0)}", file=context.stdout)
        print(f"  baseline       {path if baseline is not None else '(none)'}", file=context.stdout)
        counts = report.by_kind()
        if counts:
            print("\n  drift by kind", file=context.stdout)
            for kind, count in counts.items():
                print(f"    {kind:<20} {count}", file=context.stdout)
        if report.items:
            print("\n  items", file=context.stdout)
            for item in report.items[: args_limit(context)]:
                print(f"    {item.kind:<14} {item.qualified_name}", file=context.stdout)
                print(f"      {item.file}:{item.line} -- {item.detail}", file=context.stdout)
        else:
            print("\n  No drift.", file=context.stdout)

    blocking = report.by_kind()
    blocking.pop("removed", None)
    if args.allow_undocumented:
        blocking.pop("undocumented", None)
    if blocking:
        return exit_codes.FAILURE
    return exit_codes.OK


def args_limit(context: CliContext) -> int:
    """How many drift items to print before truncating.

    Args:
        context: CliContext: Context whose ``verbose`` flag selects the larger
            limit.
    """
    return 200 if context.verbose else 40


def _cmd_scan(context: CliContext, args: argparse.Namespace) -> int:
    target, surface = _scan(context, args)
    path, baseline = _baseline_for(context, args, target)

    if args.write_baseline:
        if context.dry_run:
            context.note(f"dry run: would write baseline to {path}")
            return exit_codes.OK
        try:
            write_baseline(path, surface, force=bool(args.force))
        except ToolkitError as exc:
            context.error(str(exc))
            if exc.hint:
                context.note(f"  hint: {exc.hint}")
            return exit_codes.CONFLICT
        print(f"wrote baseline to {path}", file=context.stdout)
        return exit_codes.OK

    items = surface.undocumented if args.include_undocumented else surface.items
    if context.output_format == JSON:
        emit_json(surface.to_dict(), context.stdout)
        return exit_codes.OK

    counts = surface.counts()
    print(f"API surface: {target}", file=context.stdout)
    print(f"  files scanned   {surface.files_scanned}", file=context.stdout)
    for kind, count in sorted(counts.items()):
        print(f"  {kind:<16} {count}", file=context.stdout)
    if surface.parse_errors:
        print("\n  parse problems:", file=context.stdout)
        for error in surface.parse_errors:
            print(f"    {error['file']}: {error['error']}", file=context.stdout)

    print("\n  undocumented:", file=context.stdout)
    for item in surface.undocumented:
        print(f"    {item.file}:{item.line}  {item.qualified_name}", file=context.stdout)
    print("\n  partially documented:", file=context.stdout)
    for item in surface.partial:
        missing = ", ".join(item.undocumented_parameters())
        print(
            f"    {item.file}:{item.line}  {item.qualified_name}  missing: {missing}",
            file=context.stdout,
        )
    del items, baseline
    return exit_codes.OK


def _cmd_diff(context: CliContext, args: argparse.Namespace) -> int:
    target, surface = _scan(context, args)
    diffs = preview_diff(target, surface.items)
    if context.output_format == JSON:
        emit_json({"files": diffs, "file_count": len(diffs)}, context.stdout)
        return exit_codes.OK
    if not diffs:
        print("No docstring changes would be made.", file=context.stdout)
        return exit_codes.OK
    for entry in diffs:
        if entry["error"]:
            print(f"--- {entry['file']}: {entry['error']}", file=context.stdout)
            continue
        print(entry["diff"], end="", file=context.stdout)
    return exit_codes.OK


def _cmd_update(context: CliContext, args: argparse.Namespace) -> int:
    target, surface = _scan(context, args)
    write = not args.check and not context.dry_run
    result = apply_updates(target, surface.items, write=write)
    payload = result.to_dict()

    if context.output_format == JSON:
        emit_json(payload, context.stdout)
    else:
        verb = "updated" if write else "would update"
        print(f"{verb} {len(result.changed)} file(s)", file=context.stdout)
        for item in result.files:
            if item.status == "unchanged":
                continue
            marker = {"updated": verb, "needs_review": "needs review"}[item.status]
            print(f"  {marker:<14} {item.file}  {item.reason}", file=context.stdout)
            for name in item.functions_updated:
                print(f"      refreshed Args/Returns for {name}", file=context.stdout)
        if result.needs_review:
            print(
                f"\n{len(result.needs_review)} file(s) need a human; prose is never rewritten "
                "automatically when the section structure is not recognised",
                file=context.stdout,
            )
    return exit_codes.OK
