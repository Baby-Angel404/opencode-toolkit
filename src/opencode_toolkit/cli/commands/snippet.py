"""``opencode snippet`` -- the verified snippet registry."""

from __future__ import annotations

import argparse
from pathlib import Path

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.errors import ConflictError, UsageError
from opencode_toolkit.snippet_verified.models import Snippet, SnippetCategory, SnippetStatus
from opencode_toolkit.snippet_verified.registry import (
    SnippetRegistry,
    catalogue_markdown,
    default_registry,
    registry_stats,
)


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "snippet",
        help="browse and install reviewed production snippets",
        description=(
            "Every snippet carries a status, a compatibility statement, security notes that "
            "name the real failure modes, and the edge cases it handles. Installing a snippet "
            "never overwrites an existing file without an explicit --force."
        ),
    )
    sub = parser.add_subparsers(dest="snippet_command", metavar="<subcommand>")

    listing = sub.add_parser("list", help="list snippets")
    listing.add_argument("--status", choices=[item.value for item in SnippetStatus], default=None)
    listing.add_argument(
        "--category", choices=[item.value for item in SnippetCategory], default=None
    )
    listing.add_argument("--language", default=None)
    listing.add_argument("--markdown", action="store_true", help="render the catalogue as Markdown")

    search = sub.add_parser("search", help="search snippets")
    search.add_argument("query", help="text to search for")
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--show-code", action="store_true", help="include the implementation")

    inspect = sub.add_parser("inspect", help="show one snippet in full")
    inspect.add_argument("id", help="snippet id")

    add = sub.add_parser("add", help="write a snippet to a file")
    add.add_argument("id", help="snippet id")
    add.add_argument("path", help="destination file")
    add.add_argument("--force", action="store_true", help="overwrite an existing file")

    verify = sub.add_parser("verify", help="check whether a file still contains a snippet")
    verify.add_argument("id", help="snippet id")
    verify.add_argument("path", help="file to check")

    parser.set_defaults(handler=run_snippet)


def _registry() -> SnippetRegistry:
    return default_registry()


def run_snippet(context: CliContext, args: argparse.Namespace) -> int:
    """Dispatch a ``snippet`` subcommand.

    Args:
        context: CliContext: Workspace, layout, config and output streams to
            report through.
        args: argparse.Namespace: Parsed ``snippet`` options, including the
            selected subcommand and its flags.
    """
    command = getattr(args, "snippet_command", None)
    if not command:
        raise UsageError(
            "snippet requires a subcommand",
            code="cli.usage",
            details={"available": ["list", "search", "inspect", "add", "verify"]},
        )
    handlers = {
        "list": _cmd_list,
        "search": _cmd_search,
        "inspect": _cmd_inspect,
        "add": _cmd_add,
        "verify": _cmd_verify,
    }
    return handlers[command](context, args)


def _filter(registry: SnippetRegistry, args: argparse.Namespace) -> list[Snippet]:
    items = registry.all()
    if getattr(args, "status", None):
        items = [item for item in items if item.status.value == args.status]
    if getattr(args, "category", None):
        items = [item for item in items if item.category.value == args.category]
    if getattr(args, "language", None):
        items = [item for item in items if item.language == args.language]
    return items


def _cmd_list(context: CliContext, args: argparse.Namespace) -> int:
    registry = _registry()
    items = _filter(registry, args)
    if args.markdown:
        print(catalogue_markdown(registry), file=context.stdout)
        return exit_codes.OK
    if context.output_format == JSON:
        emit_json(
            {"stats": registry_stats(registry), "snippets": [item.to_dict() for item in items]},
            context.stdout,
        )
        return exit_codes.OK

    print(f"Verified snippets ({len(items)} of {len(registry)})", file=context.stdout)
    print(
        f"{'ID':<44} {'LANG':<11} {'STATUS':<12} {'VER':<7} CATEGORY",
        file=context.stdout,
    )
    for item in items:
        print(
            f"{item.id:<44} {item.language:<11} {item.status.value:<12} "
            f"{item.version:<7} {item.category.value}",
            file=context.stdout,
        )
    return exit_codes.OK


def _cmd_search(context: CliContext, args: argparse.Namespace) -> int:
    hits = _registry().search(args.query, limit=args.limit)
    if context.output_format == JSON:
        emit_json(
            {"query": args.query, "hit_count": len(hits), "hits": [hit.to_dict() for hit in hits]},
            context.stdout,
        )
        return exit_codes.OK if hits else exit_codes.FAILURE

    if not hits:
        print(f"no snippets matched {args.query!r}", file=context.stdout)
        return exit_codes.FAILURE
    print(f"{len(hits)} match(es) for {args.query!r}", file=context.stdout)
    for hit in hits:
        print(
            f"\n  {hit.snippet.id}  [{hit.snippet.status.value}] ({hit.reason})",
            file=context.stdout,
        )
        print(f"    {hit.snippet.summary}", file=context.stdout)
        if args.show_code:
            print(f"    {hit.snippet.implementation}", file=context.stdout)
    return exit_codes.OK


def _cmd_inspect(context: CliContext, args: argparse.Namespace) -> int:
    snippet = _registry().get(args.id)
    if context.output_format == JSON:
        emit_json(snippet.to_dict(include_code=True), context.stdout)
        return exit_codes.OK

    print(f"{snippet.id}", file=context.stdout)
    print(f"  language    {snippet.language}", file=context.stdout)
    print(f"  version     {snippet.version}", file=context.stdout)
    print(f"  status      {snippet.status.value}", file=context.stdout)
    print(f"  category    {snippet.category.value}", file=context.stdout)
    print(f"  lines       {snippet.line_count}", file=context.stdout)
    if snippet.tested_against:
        print(f"  tested      {', '.join(snippet.tested_against)}", file=context.stdout)
    print(f"\n{snippet.summary}", file=context.stdout)

    def block(title: str, entries: tuple[str, ...]) -> None:
        if entries:
            print(f"\n{title}", file=context.stdout)
            for entry in entries:
                print(f"  - {entry}", file=context.stdout)

    block("Security notes", snippet.security_notes)
    block("Edge cases handled", snippet.edge_cases)
    block("Maintenance", snippet.maintenance_notes)
    if snippet.dependencies:
        block("Dependencies", snippet.dependencies)
    print("\nImplementation", file=context.stdout)
    print(snippet.implementation, file=context.stdout)
    return exit_codes.OK


def _cmd_add(context: CliContext, args: argparse.Namespace) -> int:
    registry = _registry()
    target = Path(args.path).expanduser()
    if context.dry_run:
        snippet = registry.get(args.id)
        print(f"dry run: would write {snippet.line_count} lines to {target}", file=context.stdout)
        return exit_codes.OK

    try:
        result = registry.materialise(args.id, target, overwrite=bool(args.force))
    except ConflictError as error:
        if context.output_format == JSON:
            emit_json(
                {"status": "conflict", "id": args.id, "path": str(target), **error.to_dict()},
                context.stdout,
            )
        else:
            context.error(error.message)
            context.note(f"  hint: {error.hint}")
            if error.details.get("conflicts"):
                context.note("  existing file digest is recorded by `snippet verify`")
        return exit_codes.CONFLICT

    if context.output_format == JSON:
        emit_json({"status": "written", **result}, context.stdout)
    else:
        verb = "overwrote" if not result["created"] else "wrote"
        print(f"{verb} {target}", file=context.stdout)
        print(f"  snippet  {result['id']} ({result['status']})", file=context.stdout)
        if result["previous_sha256"]:
            print(f"  previous sha256 {result['previous_sha256']}", file=context.stdout)
    return exit_codes.OK


def _cmd_verify(context: CliContext, args: argparse.Namespace) -> int:
    result = _registry().verify(args.id, Path(args.path).expanduser())
    if context.output_format == JSON:
        emit_json(result, context.stdout)
    else:
        state = (
            "present and unmodified"
            if result["matches"]
            else ("present but modified" if result["present"] else "not installed here")
        )
        print(f"{result['id']} in {result['path']}: {state}", file=context.stdout)
        if result["present"] and not result["header_present"]:
            context.note("  the provenance header is gone; this file was edited after installation")
    return exit_codes.OK if result["matches"] else exit_codes.FAILURE
