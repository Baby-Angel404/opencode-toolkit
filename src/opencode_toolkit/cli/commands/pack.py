"""``opencode pack`` -- verifiable offline packages."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.config import PackPolicy
from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.core.version import detect_version
from opencode_toolkit.offline_pack.builder import (
    PackBuilder,
    inspect_pack,
    update_manifest,
)
from opencode_toolkit.offline_pack.licenses import LICENSE_POLICY
from opencode_toolkit.offline_pack.manifest import KNOWN_COMPONENTS


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "pack",
        help="build, verify, inspect and update verifiable offline packages",
        description=(
            "A pack is a deterministic ZIP with a manifest of per-file SHA-256 digests. "
            "`pack verify` recomputes every digest from the archive itself. Third-party code is "
            "bundled only when its licence permits redistribution; anything unknown is excluded "
            "and recorded as excluded."
        ),
    )
    sub = parser.add_subparsers(dest="pack_command", metavar="<subcommand>")

    build = sub.add_parser("build", help="build an offline pack")
    _add_component_args(build)
    build.add_argument("--output", default=None, metavar="PATH", help="archive path")
    build.add_argument(
        "--name", default=None, help="pack name (default: opencode-toolkit-<version>)"
    )
    build.add_argument(
        "--include-dependencies",
        action="store_true",
        help="attempt to bundle development dependencies whose licence permits redistribution",
    )
    build.add_argument("--no-docs", action="store_true", help="exclude docs/ and examples/")
    build.add_argument(
        "--incremental-base",
        default=None,
        metavar="ARCHIVE",
        help="build an incremental pack on top of a verified base pack",
    )

    verify = sub.add_parser("verify", help="verify every digest in a pack")
    verify.add_argument("archive", help="pack archive to verify")
    verify.add_argument(
        "--json", dest="as_json", action="store_true", help="emit JSON regardless of --format"
    )

    inspect = sub.add_parser("inspect", help="summarise a pack without extracting it")
    inspect.add_argument("archive", help="pack archive to inspect")

    update = sub.add_parser("update", help="re-emit a pack with a refreshed manifest")
    update.add_argument("archive", help="pack archive to refresh")
    update.add_argument("--output", default=None, metavar="PATH", help="output path")

    sub.add_parser("licenses", help="show the curated third-party licence policy")
    parser.set_defaults(handler=run_pack)


def _add_component_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--component",
        dest="components",
        action="append",
        default=[],
        choices=[*KNOWN_COMPONENTS, "all"],
        help="component to include (repeatable; default: all). 'core' is always included.",
    )


def run_pack(context: CliContext, args: argparse.Namespace) -> int:
    """Dispatch a ``pack`` subcommand.

    Args:
        context: CliContext: Workspace, layout, config and output streams to
            report through.
        args: argparse.Namespace: Parsed ``pack`` options, including the
            selected subcommand and its flags.
    """
    command = getattr(args, "pack_command", None)
    if not command:
        raise UsageError(
            "pack requires a subcommand",
            code="cli.usage",
            details={"available": ["build", "verify", "inspect", "update", "licenses"]},
        )
    handlers = {
        "build": _cmd_build,
        "verify": _cmd_verify,
        "inspect": _cmd_inspect,
        "update": _cmd_update,
        "licenses": _cmd_licenses,
    }
    return handlers[command](context, args)


def _policy(context: CliContext, args: argparse.Namespace) -> PackPolicy:
    policy = context.config.pack
    if getattr(args, "no_docs", False):
        policy = PackPolicy(
            include_docs=False,
            include_dependencies=policy.include_dependencies,
            exclude_patterns=policy.exclude_patterns,
            verify_on_build=policy.verify_on_build,
        )
    return policy


def _cmd_build(context: CliContext, args: argparse.Namespace) -> int:
    version = detect_version(context.workspace)
    builder = PackBuilder(context.workspace, policy=_policy(context, args), version=version)
    components = args.components or list(KNOWN_COMPONENTS)
    output = Path(args.output).expanduser() if args.output else None

    if context.dry_run:
        selected = builder.resolve_components(components)
        files = builder.select_files(selected)
        print(f"dry run: would build a pack with {len(files)} files", file=context.stdout)
        print(f"  components  {', '.join(selected)}", file=context.stdout)
        print(
            f"  output      {output or f'dist/opencode-toolkit-{version}-offline.zip'}",
            file=context.stdout,
        )
        return exit_codes.OK

    base = Path(args.incremental_base).expanduser() if args.incremental_base else None
    result = builder.build(
        components=components,
        output=output,
        include_dependencies=bool(args.include_dependencies),
        incremental_base=base,
        archive_name=args.name,
    )
    payload = result.to_dict()

    if context.output_format == JSON:
        emit_json(payload, context.stdout)
    else:
        print(f"Built {result.archive}", file=context.stdout)
        print(f"  version      {result.manifest.version}", file=context.stdout)
        print(
            f"  components   {', '.join(sorted(result.manifest.components))}", file=context.stdout
        )
        print(f"  files        {len(result.manifest.entries)}", file=context.stdout)
        print(f"  bytes        {result.manifest.total_bytes}", file=context.stdout)
        print(f"  digest       {result.manifest.content_digest()}", file=context.stdout)
        print(f"  verified     {'yes' if result.ok else 'NO'}", file=context.stdout)
        if result.manifest.incremental:
            print(f"  base version {result.manifest.base_version}", file=context.stdout)
        if payload["excluded"]:
            print("\n  Excluded dependencies:", file=context.stdout)
            for item in payload["excluded"]:
                print(f"    - {item['name']}: {item['reason']}", file=context.stdout)
    return exit_codes.OK if result.ok else exit_codes.INTEGRITY


def _cmd_verify(context: CliContext, args: argparse.Namespace) -> int:
    from opencode_toolkit.offline_pack.manifest import verify_archive

    archive = Path(args.archive).expanduser()
    if not archive.is_file():
        raise UsageError(
            f"pack archive not found: {archive}",
            details={"path": str(archive)},
            hint="build one with `opencode pack build`",
        )
    report = verify_archive(archive)
    if context.output_format == JSON or args.as_json:
        emit_json(report.to_dict(), context.stdout)
    else:
        print(f"Verifying {archive}", file=context.stdout)
        print(f"  version        {report.version}", file=context.stdout)
        print(f"  components     {', '.join(sorted(report.components))}", file=context.stdout)
        print(f"  entries        {report.entries_checked} verified", file=context.stdout)
        print(f"  content digest {report.manifest_digest}", file=context.stdout)
        for label, items in (
            ("missing", report.missing),
            ("mismatched", report.mismatched),
            ("unexpected", report.unexpected),
            ("errors", report.errors),
        ):
            if items:
                print(f"  {label}:", file=context.stdout)
                for item in items:
                    print(f"    - {item}", file=context.stdout)
        print(f"\n  RESULT: {'VERIFIED' if report.ok else 'FAILED'}", file=context.stdout)
    return exit_codes.OK if report.ok else exit_codes.INTEGRITY


def _cmd_inspect(context: CliContext, args: argparse.Namespace) -> int:
    archive = Path(args.archive).expanduser()
    if not archive.is_file():
        raise UsageError(f"pack archive not found: {archive}", details={"path": str(archive)})
    payload = inspect_pack(archive)
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
        return exit_codes.OK
    print(f"{payload['name']} {payload['version']}", file=context.stdout)
    print(f"  archive        {payload['archive']}", file=context.stdout)
    print(f"  created        {payload['created_at']}", file=context.stdout)
    print(f"  incremental    {payload['incremental']}", file=context.stdout)
    print(
        f"  files          {payload['entry_count']} ({payload['total_bytes']} bytes)",
        file=context.stdout,
    )
    print(f"  digest         {payload['content_digest']}", file=context.stdout)
    print("\n  by component", file=context.stdout)
    for name, count in payload["entries_by_component"].items():
        print(
            f"    {name:<24} {count} files, {payload['bytes_by_component'][name]} bytes",
            file=context.stdout,
        )
    if payload["excluded"]:
        print("\n  excluded", file=context.stdout)
        for item in payload["excluded"]:
            print(f"    {item['name']}: {item['reason']}", file=context.stdout)
    for licence in payload["licenses"]:
        print(f"\n  licence: {licence['spdx']} ({licence['reference']})", file=context.stdout)
    return exit_codes.OK


def _cmd_update(context: CliContext, args: argparse.Namespace) -> int:
    archive = Path(args.archive).expanduser()
    if not archive.is_file():
        raise UsageError(f"pack archive not found: {archive}", details={"path": str(archive)})
    output = (
        Path(args.output).expanduser()
        if args.output
        else archive.with_name(f"{archive.stem}-updated{archive.suffix}")
    )
    if context.dry_run:
        context.note(f"dry run: would refresh {archive} into {output}")
        return exit_codes.OK
    result = update_manifest(archive, output)
    if context.output_format == JSON:
        emit_json(result.to_dict(), context.stdout)
    else:
        print(f"Updated pack written to {output}", file=context.stdout)
        print(f"  entries    {len(result.manifest.entries)}", file=context.stdout)
        print(f"  verified   {'yes' if result.ok else 'NO'}", file=context.stdout)
    return exit_codes.OK if result.ok else exit_codes.INTEGRITY


def _cmd_licenses(context: CliContext, args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {
        "runtime_dependencies": 0,
        "policy": [
            {
                **record.to_dict(),
                "excluded_because": None if record.may_redistribute else record.redistribution,
            }
            for record in sorted(LICENSE_POLICY.values(), key=lambda item: item.name)
        ],
        "note": (
            "The toolkit has no runtime third-party dependencies, so a default pack bundles "
            "only first-party code. Dependencies not listed here are never bundled."
        ),
    }
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
        return exit_codes.OK
    print(f"Curated licence policy ({len(payload['policy'])} entries)", file=context.stdout)
    for record in payload["policy"]:
        marker = "bundlable" if record["may_redistribute"] else "EXCLUDED"
        print(f"  {record['name']:<34} {record['spdx']:<20} {marker}", file=context.stdout)
    context.note(f"\n{payload['note']}")
    return exit_codes.OK
