"""``opencode sync`` -- encrypted workflow snapshots."""

from __future__ import annotations

import argparse
import os

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.errors import NetworkError, UsageError
from opencode_toolkit.workflow_sync import crypto
from opencode_toolkit.workflow_sync.conflicts import ConflictReport, diff_snapshots
from opencode_toolkit.workflow_sync.models import SyncReport
from opencode_toolkit.workflow_sync.queue import OfflineQueue
from opencode_toolkit.workflow_sync.store import (
    DEFAULT_TRACKED,
    SnapshotStore,
    default_tag,
    validate_tag,
)
from opencode_toolkit.workflow_sync.sync import unavailable_transport


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "sync",
        help="encrypted workflow snapshots, restore, conflict detection and offline queue",
        description=(
            "Capture and restore project state. Snapshots are sealed with PBKDF2-HMAC-SHA256 "
            "key derivation and an authenticated cipher, and restore uses three-way conflict "
            "detection so a conflicting file is never overwritten silently."
        ),
    )
    sub = parser.add_subparsers(dest="sync_command", metavar="<subcommand>")

    save = sub.add_parser("save", help="capture the current state as a new snapshot")
    _add_snapshot_args(save)
    save.add_argument("--tag", default=None, help="snapshot tag (default: timestamped)")
    save.add_argument(
        "--description", default="", help="human description stored with the snapshot"
    )
    save.add_argument(
        "--track",
        action="append",
        default=[],
        metavar="PATH",
        help="path to capture, relative to the workspace (repeatable; default: the standard set)",
    )
    save.add_argument(
        "--no-encrypt",
        action="store_true",
        help="store without encryption; the report states that it did so",
    )

    restore = sub.add_parser("restore", help="restore a snapshot, refusing to clobber conflicts")
    _add_snapshot_args(restore)
    restore.add_argument("tag", help="snapshot to restore")
    restore.add_argument(
        "--base",
        dest="base_tag",
        default=None,
        help="snapshot the working tree was last synced from (default: recorded pointer)",
    )
    restore.add_argument(
        "--force",
        action="store_true",
        help="overwrite conflicting paths; the report lists what was overridden",
    )

    listing = sub.add_parser("list", help="list snapshots, newest first")
    listing.add_argument("--limit", type=int, default=None)

    status = sub.add_parser("status", help="store status and queued operations")
    status.add_argument("--show-queue", action="store_true", help="list the offline queue in full")

    conflict = sub.add_parser("conflict", help="report conflicts without changing anything")
    _add_snapshot_args(conflict)
    conflict.add_argument(
        "tag", nargs="?", default=None, help="incoming snapshot (default: the newest one)"
    )
    conflict.add_argument("--base", dest="base_tag", default=None)

    push = sub.add_parser("push", help="copy a snapshot to another directory")
    _add_snapshot_args(push)
    push.add_argument("tag", help="snapshot to push")
    push.add_argument("--remote", required=True, help="destination directory")

    pull = sub.add_parser("pull", help="copy a snapshot from another directory")
    _add_snapshot_args(pull)
    pull.add_argument("tag", help="snapshot to pull")
    pull.add_argument("--remote", required=True, help="source directory")

    parser.set_defaults(handler=run_sync)


def _add_snapshot_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--passphrase",
        default=None,
        help="passphrase for encryption; prefer --passphrase-env to keep it out of shell history",
    )
    parser.add_argument(
        "--passphrase-env",
        default=None,
        metavar="VARIABLE",
        help="read the passphrase from this environment variable",
    )


def _resolve_passphrase(args: argparse.Namespace) -> str | None:
    passphrase: str | None = getattr(args, "passphrase", None)
    if passphrase:
        return passphrase
    name = getattr(args, "passphrase_env", None)
    if name:
        value = os.environ.get(name, "")
        if not value:
            raise UsageError(
                f"environment variable {name} is empty",
                code="sync.passphrase_missing",
                details={"variable": name},
            )
        return value
    # Interactive prompting is deliberately not attempted: a non-interactive CI
    # run must fail with a clear message rather than hang on a hidden prompt.
    return None


def _store(context: CliContext) -> SnapshotStore:
    return SnapshotStore(context.layout.snapshots, context.config.sync)


def run_sync(context: CliContext, args: argparse.Namespace) -> int:
    """Dispatch a ``sync`` subcommand.

    Args:
        context: CliContext: Workspace, layout, config and output streams to
            report through.
        args: argparse.Namespace: Parsed ``sync`` options, including the
            selected subcommand and its flags.
    """
    command = getattr(args, "sync_command", None)
    if not command:
        raise UsageError(
            "sync requires a subcommand",
            code="cli.usage",
            details={
                "available": ["save", "restore", "list", "status", "conflict", "push", "pull"]
            },
        )
    handlers = {
        "save": _cmd_save,
        "restore": _cmd_restore,
        "list": _cmd_list,
        "status": _cmd_status,
        "conflict": _cmd_conflict,
        "push": _cmd_push,
        "pull": _cmd_pull,
    }
    return handlers[command](context, args)


def _cmd_save(context: CliContext, args: argparse.Namespace) -> int:
    store = _store(context)
    passphrase = _resolve_passphrase(args)
    encrypt = not args.no_encrypt
    if args.dry_run:
        context.note(
            f"dry run: would capture {', '.join(args.track or DEFAULT_TRACKED)} from {context.workspace}"
        )
        return exit_codes.OK

    tracked = tuple(args.track) if args.track else DEFAULT_TRACKED
    _snapshot, report = store.save(
        context.workspace,
        tag=args.tag or default_tag(),
        description=args.description,
        tracked=tracked,
        encrypt=encrypt,
        passphrase=passphrase,
    )
    return _render_report(context, report)


def _cmd_restore(context: CliContext, args: argparse.Namespace) -> int:
    store = _store(context)
    passphrase = _resolve_passphrase(args)
    base = args.base_tag or store.last_applied()
    if context.dry_run:
        report = diff_snapshots(
            store.load(base, passphrase=passphrase) if base else None,
            None,
            store.load(args.tag, passphrase=passphrase),
        )
        _render_conflicts(context, report, dry_run=True)
        return exit_codes.CONFLICT if report.has_conflicts else exit_codes.OK

    report, result = store.restore(
        context.workspace,
        args.tag,
        passphrase=passphrase,
        base_tag=base,
        force=bool(args.force),
    )
    if context.output_format == JSON:
        emit_json({"conflicts": report.to_dict(), "result": result.to_dict()}, context.stdout)
    else:
        _render_conflicts(context, report)
        _print_result(context, result)
    return exit_codes.OK if result.ok else exit_codes.CONFLICT


def _cmd_list(context: CliContext, args: argparse.Namespace) -> int:
    store = _store(context)
    entries = store.list_snapshots()
    if args.limit:
        entries = entries[: args.limit]
    if context.output_format == JSON:
        emit_json(
            {"store": str(store.root), "snapshots": entries, "count": len(entries)}, context.stdout
        )
        return exit_codes.OK
    if not entries:
        context.note("no snapshots yet; create one with `opencode sync save`")
        return exit_codes.OK
    print(f"{'TAG':<28} {'CREATED':<22} {'FILES':>6} {'BYTES':>10}  ENC", file=context.stdout)
    for entry in entries:
        print(
            f"{entry['tag'][:27]:<28} {entry['created_at']:<22} "
            f"{entry['item_count']:>6} {entry['total_bytes']:>10}  "
            f"{'yes' if entry['encrypted'] else 'no'}",
            file=context.stdout,
        )
    return exit_codes.OK


def _cmd_status(context: CliContext, args: argparse.Namespace) -> int:
    store = _store(context)
    queue = OfflineQueue(context.layout.queue)
    status = store.status()
    pending = queue.pending()
    payload = status.to_dict()
    payload["queue"] = {
        "path": str(queue.root),
        "pending": len(pending),
        "entries": [entry.to_dict() for entry in pending] if args.show_queue else [],
    }
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
        return exit_codes.OK

    print("Sync status", file=context.stdout)
    print(f"  store           {status.store_path}", file=context.stdout)
    print(f"  snapshots       {status.snapshot_count}", file=context.stdout)
    print(
        f"  latest          {status.latest_tag or '(none)'} at {status.latest_created_at or '-'}",
        file=context.stdout,
    )
    print(f"  last applied    {store.last_applied() or '(none recorded)'}", file=context.stdout)
    print(f"  queued ops      {len(pending)}", file=context.stdout)
    print(f"  cipher          {status.cipher}", file=context.stdout)
    print(
        f"  kdf             pbkdf2-hmac-sha256 x{context.config.sync.kdf_iterations}",
        file=context.stdout,
    )
    print(f"  ciphers present {', '.join(crypto.available_ciphers())}", file=context.stdout)
    for note in status.notes:
        context.note(f"  note: {note}")
    if args.show_queue and pending:
        print("\nQueued operations", file=context.stdout)
        for entry in pending:
            print(
                f"  {entry.created_at}  {entry.operation:<8} {entry.tag}  "
                f"attempts={entry.attempts} {entry.last_error}",
                file=context.stdout,
            )
    return exit_codes.OK


def _cmd_conflict(context: CliContext, args: argparse.Namespace) -> int:
    store = _store(context)
    passphrase = _resolve_passphrase(args)
    snapshots = store.list_snapshots()
    tag = args.tag or (snapshots[0]["tag"] if snapshots else None)
    if not tag:
        raise UsageError(
            "no snapshot to compare against",
            code="sync.nothing_tracked",
            details={"hint": "create one with `opencode sync save`"},
        )
    validate_tag(tag)
    incoming = store.load(tag, passphrase=passphrase)
    base_tag = args.base_tag or store.last_applied()
    base = store.load(base_tag, passphrase=passphrase) if base_tag else None
    current = store.snapshot_of(context.workspace, [item.path for item in incoming.items])
    report = diff_snapshots(base, current, incoming)
    if context.output_format == JSON:
        emit_json(report.to_dict(), context.stdout)
    else:
        _render_conflicts(context, report)
    return exit_codes.CONFLICT if report.has_conflicts else exit_codes.OK


def _cmd_push(context: CliContext, args: argparse.Namespace) -> int:
    from opencode_toolkit.workflow_sync.sync import push

    store = _store(context)
    queue = OfflineQueue(context.layout.queue)
    try:
        transport = unavailable_transport(args.remote, create=True)
    except NetworkError as exc:
        # The destination exists but cannot be reached right now: queue the
        # operation so it is not lost. A *missing* destination is a usage error
        # and propagates, because queueing it would hide a typo indefinitely.
        entry = queue.enqueue("push", args.tag, {"remote": str(args.remote)})
        context.warn(f"remote unavailable ({exc}); operation queued as {entry.identifier}")
        return exit_codes.NETWORK if not context.dry_run else exit_codes.OK

    # The transport reads the sealed manifest to learn which blobs must travel,
    # so an encrypted snapshot needs the passphrase here too.
    result = push(store, args.tag, transport, passphrase=_resolve_passphrase(args))
    payload = {
        "action": "push",
        "tag": result.tag,
        "transport": result.transport,
        "transferred": result.transferred,
        "already_present": result.already_present,
        "note": result.note,
        "queued": False,
    }
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
    else:
        print(
            f"{'transferred' if result.transferred else 'already present'}: {result.tag}",
            file=context.stdout,
        )
        print(f"  remote: {result.transport}", file=context.stdout)
        if result.note:
            context.note(f"  {result.note}")
    return exit_codes.OK


def _cmd_pull(context: CliContext, args: argparse.Namespace) -> int:
    from opencode_toolkit.workflow_sync.sync import pull

    store = _store(context)
    passphrase = _resolve_passphrase(args)
    transport = unavailable_transport(args.remote)
    snapshot = pull(store, args.tag, transport, passphrase=passphrase)
    payload = {
        "action": "pull",
        "tag": snapshot.tag,
        "items": len(snapshot.items),
        "encrypted": snapshot.encrypted,
        "transport": transport.name,
    }
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
    else:
        print(
            f"pulled {snapshot.tag}: {len(snapshot.items)} file(s) from {transport.name}",
            file=context.stdout,
        )
    return exit_codes.OK


# -- rendering ------------------------------------------------------------


def _render_report(context: CliContext, report: SyncReport) -> int:
    if context.output_format == JSON:
        emit_json(report.to_dict(), context.stdout)
    else:
        _print_result(context, report)
    return exit_codes.OK


def _print_result(context: CliContext, report: SyncReport) -> None:
    print(f"{report.action}: {report.tag}", file=context.stdout)
    print(f"  files tracked   {len(report.applied)}", file=context.stdout)
    print(f"  encrypted       {'yes' if report.encrypted else 'no'}", file=context.stdout)
    if report.conflicts:
        print(f"  conflicts       {len(report.conflicts)}", file=context.stdout)
        for path in report.conflicts:
            print(f"    - {path}", file=context.stdout)
    for note in report.notes:
        print(f"  note            {note}", file=context.stdout)
    for error in report.errors:
        print(f"  error           {error}", file=context.stdout)


def _render_conflicts(context: CliContext, report: ConflictReport, *, dry_run: bool = False) -> int:
    summary = report.summary()
    heading = "Conflict analysis (dry run)" if dry_run else "Conflict analysis"
    print(f"\n{heading}", file=context.stdout)
    print(f"  paths examined  {summary['paths_examined']}", file=context.stdout)
    print(f"  conflicts       {summary['conflict_count']}", file=context.stdout)
    for state, count in sorted(summary["counts"].items()):
        print(f"    {state:<24} {count}", file=context.stdout)
    if report.conflicts:
        print("\n  conflicting paths:", file=context.stdout)
        for path in report.conflicts:
            state = report.states[path]
            print(f"    - {path}  [{state.value}]", file=context.stdout)
        if not dry_run:
            print(
                "\n  Nothing was written. Resolve these, or re-run with --force to overwrite.",
                file=context.stdout,
            )
    else:
        print("\n  No conflicts.", file=context.stdout)
    return exit_codes.OK
