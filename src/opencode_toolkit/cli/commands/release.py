"""``opencode release`` -- gate, artefacts, version and changelog."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Any

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.errors import ConfigurationError, UsageError
from opencode_toolkit.release.artifacts import build_artifacts, verify_artifacts
from opencode_toolkit.release.changelog import (
    clear_fragments,
    load_fragments,
    write_changelog,
    write_fragment,
)
from opencode_toolkit.release.gate import (
    CHECK_NAMES,
    CheckStatus,
    GateResult,
    ReleaseGate,
    load_gate,
    new_gate,
    record,
)
from opencode_toolkit.release.version import (
    bump_version,
    current_version,
    next_prerelease,
    update_version_files,
)

#: Gate location, relative to the already-resolved state directory
#: (``<workspace>/.opencode/toolkit`` by default). Joining the full
#: ``.opencode/toolkit/...`` path here would nest it twice.
GATE_RELPATH = Path("release-gate.json")
DEFAULT_ARTIFACT_DIR = Path("dist")


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "release",
        help="release gate, artefacts, version bump and changelog",
        description=(
            "The release gate records every mandatory check. Only PASS permits a release: "
            "FAIL, UNKNOWN, NOT_RUN and SKIPPED all block. Publishing reads this gate and "
            "refuses on anything but an approved decision."
        ),
    )
    sub = parser.add_subparsers(dest="release_command", metavar="<subcommand>")

    gate = sub.add_parser("gate", help="show or update the release gate")
    gate.add_argument("--path", default=None, metavar="PATH", help="gate document")
    gate.add_argument("--init", action="store_true", help="create a gate with every check NOT_RUN")
    gate.add_argument(
        "--set",
        dest="assignments",
        action="append",
        default=[],
        metavar="NAME=STATUS[:detail]",
        help="record a check (repeatable), e.g. --set UNIT_TEST=PASS:'142 passed'",
    )
    gate.add_argument(
        "--allow-skip",
        action="append",
        default=[],
        metavar="NAME",
        help="permit a named check to be SKIPPED (repeatable)",
    )

    artifacts = sub.add_parser("artifacts", help="build release artefacts with real checksums")
    artifacts.add_argument("--output", default=None, metavar="PATH", help="output directory")
    artifacts.add_argument("--no-wheel", action="store_true", help="skip the wheel build")
    artifacts.add_argument("--no-pack", action="store_true", help="skip the offline pack")

    verify = sub.add_parser("verify-artifacts", help="re-verify an artefacts directory")
    verify.add_argument("--output", default=None, metavar="PATH")

    bump = sub.add_parser("bump", help="bump the semantic version in pyproject.toml")
    bump.add_argument(
        "level", choices=["major", "minor", "patch"], help="which component to increment"
    )
    bump.add_argument(
        "--prerelease", default=None, metavar="LABEL", help="apply a pre-release label, e.g. rc.1"
    )

    changelog = sub.add_parser("changelog", help="render CHANGELOG.md from structured fragments")
    changelog.add_argument(
        "--release",
        default=None,
        metavar="VERSION",
        help="render a released section for this version",
    )
    changelog.add_argument("--clear", action="store_true", help="delete fragments after rendering")

    fragment = sub.add_parser("fragment", help="record a change fragment")
    fragment.add_argument(
        "change_type", help="added, changed, deprecated, removed, fixed or security"
    )
    fragment.add_argument("description", help="what changed, in the imperative mood")
    fragment.add_argument("--area", default="", help="component or area affected")
    fragment.add_argument("--breaking", action="store_true")

    sbom = sub.add_parser("sbom", help="print the CycloneDX SBOM")
    sbom.add_argument(
        "--summary", action="store_true", help="print counts instead of the full document"
    )

    sub.add_parser("preflight", help="verify the gate permits a release, and why not")
    parser.set_defaults(handler=run_release)


def _gate_path(context: CliContext, args: argparse.Namespace) -> Path:
    if getattr(args, "path", None):
        return Path(args.path).expanduser()
    return context.layout.state_dir / GATE_RELPATH


def run_release(context: CliContext, args: argparse.Namespace) -> int:
    """Dispatch a ``release`` subcommand.

    Args:
        context: CliContext: Workspace, layout, config and output streams to
            report through.
        args: argparse.Namespace: Parsed ``release`` options, including the
            selected subcommand and its flags.
    """
    command = getattr(args, "release_command", None)
    if not command:
        raise UsageError(
            "release requires a subcommand",
            code="cli.usage",
            details={
                "available": [
                    "gate",
                    "artifacts",
                    "verify-artifacts",
                    "bump",
                    "changelog",
                    "fragment",
                    "sbom",
                    "preflight",
                ]
            },
        )
    handlers = {
        "gate": _cmd_gate,
        "artifacts": _cmd_artifacts,
        "verify-artifacts": _cmd_verify_artifacts,
        "bump": _cmd_bump,
        "changelog": _cmd_changelog,
        "fragment": _cmd_fragment,
        "sbom": _cmd_sbom,
        "preflight": _cmd_preflight,
    }
    return handlers[command](context, args)


def _commit(context_workspace: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(context_workspace),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _parse_assignment(text: str) -> tuple[str, CheckStatus, str]:
    if "=" not in text:
        raise UsageError(
            f"malformed --set {text!r}; expected NAME=STATUS[:detail]",
            code="release.bad_assignment",
            details={"expected": "NAME=STATUS[:detail]", "checks": list(CHECK_NAMES)},
        )
    name, _, rest = text.partition("=")
    name = name.strip().upper()
    if name not in CHECK_NAMES:
        raise UsageError(
            f"unknown check {name!r}",
            code="release.unknown_check",
            details={"known": list(CHECK_NAMES)},
        )
    status_text, _, detail = rest.partition(":")
    try:
        status = CheckStatus(status_text.strip().upper())
    except ValueError as exc:
        raise UsageError(
            f"unknown status {status_text!r}",
            code="release.unknown_status",
            details={"valid": [item.value for item in CheckStatus]},
        ) from exc
    return name, status, detail.strip()


def _cmd_gate(context: CliContext, args: argparse.Namespace) -> int:
    path = _gate_path(context, args)
    gate = ReleaseGate(path=path)

    if args.init:
        if path.is_file() and not context.dry_run:
            context.warn(
                f"reinitialising the existing gate at {path}; every check resets to NOT_RUN"
            )
        if context.dry_run:
            context.note("dry run: would initialise the gate")
            return exit_codes.OK
        fresh = new_gate(str(current_version(context.workspace)), commit=_commit(context.workspace))
        if args.allow_skip:
            from opencode_toolkit.release.gate import GatePolicy

            fresh.policy = GatePolicy(
                allow_warnings=fresh.policy.allow_warnings,
                conditionally_skippable=fresh.policy.conditionally_skippable,
                allow_skip=frozenset(args.allow_skip),
            )
        gate.result = fresh
        gate.save()

    for assignment in args.assignments:
        name, status, detail = _parse_assignment(assignment)
        if context.dry_run:
            context.note(f"dry run: would record {name}={status.value}")
            continue
        gate.record(name, status, detail=detail or "recorded from the command line")

    if context.output_format == JSON:
        emit_json(gate.result.to_dict(), context.stdout)
    else:
        print(gate.render(), file=context.stdout)
    return exit_codes.OK


def _cmd_artifacts(context: CliContext, args: argparse.Namespace) -> int:
    output = (
        Path(args.output).expanduser() if args.output else context.workspace / DEFAULT_ARTIFACT_DIR
    )
    if context.dry_run:
        context.note(f"dry run: would build release artefacts into {output}")
        return exit_codes.OK
    artifacts = build_artifacts(
        context.workspace,
        output,
        skip_python_build=bool(args.no_wheel),
        include_pack=not args.no_pack,
        pack_policy=context.config.pack,
    )
    payload = artifacts.to_dict()
    payload["verification"] = verify_artifacts(artifacts)

    if context.output_format == JSON:
        emit_json(payload, context.stdout)
    else:
        print(f"Release artefacts in {output}", file=context.stdout)
        print(f"{'ARTEFACT':<52} {'BYTES':>12}  SHA256", file=context.stdout)
        for artifact in sorted(artifacts.artifacts, key=lambda item: item.name):
            print(
                f"{artifact.name[:51]:<52} {artifact.size:>12}  {artifact.sha256[:32]}...",
                file=context.stdout,
            )
        for line in artifacts.build_log:
            print(f"  {line}", file=context.stdout)
        verification = payload["verification"]
        print(
            f"  re-verification: {'OK' if verification['ok'] else 'FAILED'} "
            f"({verification['checked']} artefact(s) re-read)",
            file=context.stdout,
        )
    return exit_codes.OK if payload["verification"]["ok"] else exit_codes.INTEGRITY


def _required_kinds_from_index(document: dict[str, Any]) -> tuple[str, ...]:
    """Read the required kinds from a build index, falling back to all of them.

    An index written before this field existed is read as a complete release,
    which is the conservative direction: it can fail a partial build, never pass
    an incomplete one.
    """
    from opencode_toolkit.release.artifacts import REQUIRED_ARTIFACT_KINDS

    recorded = document.get("required_kinds")
    if not isinstance(recorded, list) or not all(isinstance(item, str) for item in recorded):
        return REQUIRED_ARTIFACT_KINDS
    return tuple(recorded)


def _cmd_verify_artifacts(context: CliContext, args: argparse.Namespace) -> int:
    from opencode_toolkit.core import jsonio
    from opencode_toolkit.release.artifacts import Artifact, ArtifactSet

    directory = (
        Path(args.output).expanduser() if args.output else context.workspace / DEFAULT_ARTIFACT_DIR
    )
    index = directory / "artifacts.json"
    if not index.is_file():
        raise UsageError(
            f"no artefacts index at {index}",
            code="release.no_artifacts",
            details={"path": str(index)},
            hint="run `opencode release artifacts` first",
        )
    document = jsonio.read(index)
    rebuilt = ArtifactSet(
        version=current_version(directory.parent),
        directory=directory,
        artifacts=[
            Artifact(
                name=item["name"],
                path=directory / item["name"],
                size=item["size"],
                sha256=item["sha256"],
                kind=item["kind"],
                note=item.get("note", ""),
            )
            for item in document.get("artifacts", [])
        ],
        build_log=list(document.get("build_log", [])),
        required_kinds=_required_kinds_from_index(document),
    )
    payload = verify_artifacts(rebuilt)
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
    else:
        print(f"Re-verified {payload['checked']} artefact(s) in {directory}", file=context.stdout)
        for name in payload["missing"]:
            print(f"  MISSING    {name}", file=context.stdout)
        for name in payload["mismatched"]:
            print(f"  MISMATCHED {name}", file=context.stdout)
        for kind in payload["missing_kinds"]:
            print(f"  ABSENT     no artefact of kind {kind!r} was ever built", file=context.stdout)
        for line in payload["failed_build_steps"]:
            print(f"  BUILD LOG  {line}", file=context.stdout)
        print(f"RESULT: {'VERIFIED' if payload['ok'] else 'FAILED'}", file=context.stdout)
    return exit_codes.OK if payload["ok"] else exit_codes.INTEGRITY


def _cmd_bump(context: CliContext, args: argparse.Namespace) -> int:
    current = current_version(context.workspace)
    target = bump_version(current, args.level)
    if args.prerelease:
        target = next_prerelease(target, args.prerelease)
    if context.dry_run:
        print(f"dry run: {current} -> {target}", file=context.stdout)
        return exit_codes.OK
    update_version_files(context.workspace, target, expected_current=current)
    print(f"{current} -> {target}", file=context.stdout)
    print("next: regenerate CHANGELOG.md and re-run the full quality pipeline", file=context.stdout)
    return exit_codes.OK


def _cmd_changelog(context: CliContext, args: argparse.Namespace) -> int:
    fragments = load_fragments(context.workspace)
    if context.dry_run:
        context.note(f"dry run: would render CHANGELOG.md from {len(fragments)} fragment(s)")
        return exit_codes.OK
    path = write_changelog(context.workspace, version=args.release)
    if args.clear and args.release:
        removed = clear_fragments(context.workspace)
        print(f"wrote {path} and removed {removed} released fragment(s)", file=context.stdout)
    else:
        print(f"wrote {path} ({len(fragments)} unreleased fragment(s))", file=context.stdout)
    return exit_codes.OK


def _cmd_fragment(context: CliContext, args: argparse.Namespace) -> int:
    from opencode_toolkit.release.changelog import Fragment

    identifier = f"{args.change_type}-{abs(hash(args.description)) % 10_000_000:07d}"
    fragment = Fragment(
        id=identifier,
        kind=args.change_type,
        area=args.area,
        description=args.description,
        breaking=bool(args.breaking),
    )
    if context.dry_run:
        context.note(f"dry run: would record fragment {identifier}")
        return exit_codes.OK
    path = write_fragment(context.workspace, fragment)
    print(f"recorded {identifier}", file=context.stdout)
    print(f"  {path}", file=context.stdout)
    return exit_codes.OK


def _cmd_sbom(context: CliContext, args: argparse.Namespace) -> int:
    """Print the SBOM, or its dependency counts with --summary."""
    from opencode_toolkit.core import jsonio
    from opencode_toolkit.release.sbom import build_sbom, sbom_summary

    if context.output_format == JSON:
        document = (
            sbom_summary(context.workspace)
            if args.summary
            else jsonio.loads(build_sbom(context.workspace))
        )
        emit_json(document, context.stdout)
        return exit_codes.OK
    if args.summary:
        summary = sbom_summary(context.workspace)
        print(f"{summary['format']}", file=context.stdout)
        print(f"  runtime dependencies      {summary['runtime_dependencies']}", file=context.stdout)
        print(
            f"  development dependencies  {summary['development_dependencies']}",
            file=context.stdout,
        )
        for name in summary["development_components"]:
            print(f"    - {name}", file=context.stdout)
        return exit_codes.OK
    print(build_sbom(context.workspace), end="", file=context.stdout)
    return exit_codes.OK


def _cmd_preflight(context: CliContext, args: argparse.Namespace) -> int:
    path = _gate_path(context, args)
    if not path.is_file():
        raise ConfigurationError(
            f"no release gate at {path}",
            code="release.gate_missing",
            details={"path": str(path)},
            hint="run ./scripts/quality-check, which writes the gate as each stage completes",
        )
    gate = load_gate(path)
    permitted, reason = gate.publish_permitted()
    if context.output_format == JSON:
        emit_json(
            {"permitted": permitted, "reason": reason, "gate": gate.to_dict()}, context.stdout
        )
    else:
        print(gate.render(), file=context.stdout)
        print(f"\npublishing permitted: {'yes' if permitted else 'no'}", file=context.stdout)
    return exit_codes.OK if permitted else exit_codes.FAILURE


def record_gate_status(path: Path, name: str, status: CheckStatus, detail: str) -> None:
    """Update one gate check in place; used by scripts and tests.

    Args:
        path: Path: Gate JSON file; a new gate is created when it is absent.
        name: str: Name of the check to update.
        status: CheckStatus: Outcome recorded for that check.
        detail: str: Free-text detail stored alongside the status.
    """
    gate = load_gate(path) if path.is_file() else new_gate()
    write_gate_json(path, record(gate, name, status, detail=detail))


def write_gate_json(path: Path, gate: GateResult) -> None:
    """Persist *gate* to *path* atomically.

    Args:
        path: Path: Destination file for the serialised gate.
        gate: GateResult: The gate result written to that file.
    """
    from opencode_toolkit.release.gate import write_gate

    write_gate(path, gate)
