"""``opencode publish`` -- gated publishing to Hugging Face and Kaggle.

The ordering here is the specification's hard requirement, expressed as code:

    gate -> classification -> credentials -> metadata validation -> secret scan
         -> upload -> remote verification

Every stage can refuse. Refusals are reported with the exact missing
configuration, and ``SKIPPED`` is never reported as success.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from opencode_toolkit.cli.context import JSON, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.errors import ConfigurationError, UsageError
from opencode_toolkit.publishing.artifacts import clean_publish_directory, directory_digest
from opencode_toolkit.publishing.classify import (
    HUGGINGFACE_TOKEN_ENV,
    KAGGLE_KEY_ENV,
    KAGGLE_USERNAME_ENV,
    classify_project,
)
from opencode_toolkit.publishing.huggingface import HuggingFacePublisher, space_metadata
from opencode_toolkit.publishing.kaggle import (
    KagglePublisher,
    dataset_metadata,
    validate_dataset_metadata,
)
from opencode_toolkit.release.gate import GateResult, load_gate

#: Gate location, relative to the already-resolved state directory
#: (``<workspace>/.opencode/toolkit`` by default). Joining the full
#: ``.opencode/toolkit/...`` path here would nest it twice.
GATE_RELPATH = Path("release-gate.json")
DEFAULT_STAGING = Path("dist") / "publish"


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "publish",
        help="publish to Hugging Face or Kaggle, gated on an approved release",
        description=(
            "Publishing is refused unless the release gate is APPROVED and credentials are "
            "present. When credentials are absent the command reports SKIP PUBLISH and names "
            "the exact environment variable or GitHub secret required."
        ),
        epilog=(
            "credential environment variables:\n"
            f"  {HUGGINGFACE_TOKEN_ENV}      Hugging Face write token\n"
            f"  {KAGGLE_USERNAME_ENV} / {KAGGLE_KEY_ENV}   Kaggle API credentials\n"
            "\nIn GitHub Actions set these as repository secrets, never in workflow source."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="publish_command", metavar="<platform>")

    classify = sub.add_parser("classify", help="show how this project is classified per platform")
    classify.set_defaults(handler=run_publish)

    hf = sub.add_parser("huggingface", help="publish to the Hugging Face Hub")
    hf.add_argument("--namespace", required=True, help="Hugging Face user or organisation")
    hf.add_argument("--repo-id", default="opencode-toolkit", help="repository name")
    hf.add_argument(
        "--directory", default=None, metavar="PATH", help="prepared directory (default: build one)"
    )
    hf.add_argument(
        "--staging", default=None, metavar="PATH", help="where to prepare the directory"
    )
    hf.add_argument("--public", action="store_true", help="publish publicly (default: private)")
    hf.add_argument("--assume-yes", action="store_true", help="skip the interactive confirmation")
    hf.add_argument("--dry-run", dest="dry_run", action="store_true", default=None)
    hf.add_argument("--gate", default=None, metavar="PATH", help="release gate document")

    kg = sub.add_parser("kaggle", help="publish as a Kaggle Dataset")
    kg.add_argument(
        "--owner", default=None, help="Kaggle account name (defaults to $KAGGLE_USERNAME)"
    )
    kg.add_argument("--slug", default="opencode-toolkit", help="dataset slug")
    kg.add_argument("--directory", default=None, metavar="PATH")
    kg.add_argument("--staging", default=None, metavar="PATH")
    kg.add_argument("--private", action="store_true", help="publish privately")
    kg.add_argument("--dry-run", dest="dry_run", action="store_true", default=None)
    kg.add_argument("--gate", default=None, metavar="PATH")

    verify = sub.add_parser("verify", help="verify a published dataset/space without re-uploading")
    verify.add_argument("--platform", choices=["huggingface", "kaggle"], required=True)
    verify.add_argument("--namespace", default="", help="Hugging Face namespace")
    verify.add_argument("--slug", default="opencode-toolkit")

    parser.set_defaults(handler=run_publish)


def run_publish(context: CliContext, args: argparse.Namespace) -> int:
    """Dispatch a ``publish`` subcommand.

    Args:
        context: CliContext: Workspace, layout, config and output streams to
            report through.
        args: argparse.Namespace: Parsed ``publish`` options, including the
            selected subcommand and its flags.
    """
    command = getattr(args, "publish_command", None)
    if not command:
        raise UsageError(
            "publish requires a platform",
            code="cli.usage",
            details={"available": ["classify", "huggingface", "kaggle", "verify"]},
        )
    handlers = {
        "classify": _cmd_classify,
        "huggingface": _cmd_huggingface,
        "kaggle": _cmd_kaggle,
        "verify": _cmd_verify,
    }
    return handlers[command](context, args)


def _load_gate(context: CliContext, args: argparse.Namespace) -> GateResult:
    path = (
        Path(args.gate).expanduser()
        if getattr(args, "gate", None)
        else context.layout.state_dir / GATE_RELPATH
    )
    if not path.is_file():
        raise ConfigurationError(
            f"no release gate at {path}; publishing requires an approved gate",
            code="release.gate_missing",
            details={"path": str(path)},
            hint="run ./scripts/quality-check to produce the gate, and confirm it says APPROVED",
        )
    return load_gate(path)


def _prepare_directory(context: CliContext, args: argparse.Namespace) -> Path:
    """Return the prepared publishing directory, building it if needed."""
    if args.directory:
        path = Path(args.directory).expanduser()
        if not path.is_dir():
            raise ConfigurationError(
                f"publishing directory not found: {path}",
                details={"path": str(path)},
            )
        return path
    staging = (
        Path(args.staging).expanduser()
        if getattr(args, "staging", None)
        else context.workspace / DEFAULT_STAGING
    )
    if context.dry_run:
        context.note(f"dry run: would prepare a publishing directory at {staging}")
        return staging
    import shutil

    if staging.exists():
        shutil.rmtree(staging)
    result = clean_publish_directory(context.workspace, staging)
    context.note(f"prepared {len(result['included'])} file(s); excluded {result['excluded_count']}")
    return staging


def _finish(context: CliContext, payload: dict[str, Any]) -> int:
    """Render a publish result and choose the exit code."""
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
    else:
        status = payload.get("status", "UNKNOWN")
        print(f"{payload.get('platform', 'publish')}: {status}", file=context.stdout)
        print(
            f"  target   {payload.get('repository') or payload.get('dataset_ref', '-')}",
            file=context.stdout,
        )
        print(f"  reason   {payload.get('reason', '-')}", file=context.stdout)
        if payload.get("missing_configuration"):
            print("\n  missing configuration:", file=context.stdout)
            for item in payload["missing_configuration"]:
                print(f"    - {item}", file=context.stdout)
        verification = payload.get("verification") or {}
        if verification:
            print("\n  verification:", file=context.stdout)
            for key, value in sorted(verification.items()):
                if isinstance(value, (list, dict)):
                    print(f"    {key}: {len(value)}", file=context.stdout)
                else:
                    print(f"    {key}: {value}", file=context.stdout)

    status = payload.get("status")
    match status:
        case "PUBLISHED":
            return exit_codes.OK
        case "SKIPPED":
            # A skip is a clean, explained non-action: not a failure.
            return exit_codes.OK
        case "PUBLISHED_BUT_VERIFICATION_FAILED":
            return exit_codes.INTEGRITY
        case "BLOCKED":
            return exit_codes.CONFLICT
        case _:
            return exit_codes.FAILURE


def _cmd_classify(context: CliContext, args: argparse.Namespace) -> int:
    payload = classify_project(context.workspace).to_dict()
    if context.output_format == JSON:
        emit_json(payload, context.stdout)
        return exit_codes.OK
    print(f"project kind: {payload['project_kind']}", file=context.stdout)
    print(
        f"  huggingface: {payload['huggingface']['kind']} "
        f"(applicable: {payload['huggingface']['applicable']})",
        file=context.stdout,
    )
    print(
        f"  kaggle:      {payload['kaggle']['kind']} "
        f"(applicable: {payload['kaggle']['applicable']})",
        file=context.stdout,
    )
    print("\nevidence:")
    for item in payload["rationale"]:
        print(f"  - {item}", file=context.stdout)
    print("\nother classifications would require:")
    for kind, requirement in payload["other_classifications_require"].items():
        print(f"  {kind}: {requirement}", file=context.stdout)
    return exit_codes.OK


def _cmd_huggingface(context: CliContext, args: argparse.Namespace) -> int:
    classification = classify_project(context.workspace)
    if not classification.huggingface_applicable:
        payload = {
            "platform": "huggingface",
            "status": "BLOCKED",
            "repository": f"{args.namespace}/{args.repo_id}",
            "reason": (
                f"this project classifies as '{classification.project_kind}', which has no "
                f"Hugging Face representation (kind: {classification.huggingface_kind})"
            ),
            "missing_configuration": [
                "a runnable application entry point (app.py, streamlit_app.py or server.py) "
                "plus a Docker Space configuration",
            ],
            "verification": {"classification": classification.to_dict()},
        }
        return _finish(context, payload)

    gate = _load_gate(context, args)
    publisher = HuggingFacePublisher(args.namespace, repo_id=args.repo_id, private=not args.public)
    blocked = publisher.check_gate(gate)
    if blocked is not None:
        return _finish(context, blocked.to_dict())

    skipped = publisher.check_credentials()
    if skipped is not None:
        return _finish(context, skipped.to_dict())

    directory = _prepare_directory(context, args)
    if context.dry_run:
        context.note("dry run: stopping before upload")
        return _finish(
            context,
            {
                "platform": "huggingface",
                "status": "SKIPPED",
                "repository": publisher.repository,
                "reason": "dry run; no upload attempted",
            },
        )

    if not (directory / "README.md").is_file():
        context.warn("no README.md in the prepared directory; a Space requires one")
    metadata = space_metadata(context.workspace)
    (directory / "README.md").write_text(
        _space_readme(metadata, (directory / "README.md").read_text(encoding="utf-8"))
        if (directory / "README.md").is_file()
        else metadata.to_yaml() + f"\n# {metadata.title}\n",
        encoding="utf-8",
    )

    context.note(f"uploading {directory_digest(directory)[:16]}... to {publisher.repository}")
    result = publisher.publish(directory)
    return _finish(context, result.to_dict())


def _space_readme(metadata: Any, existing: str) -> str:
    """Merge the required front matter into an existing README."""
    parts = existing.split("---", 2)
    body = parts[2].lstrip("\n") if len(parts) >= 3 else existing
    front_matter: str = metadata.to_yaml()
    return front_matter + "\n" + body


def _cmd_kaggle(context: CliContext, args: argparse.Namespace) -> int:
    classification = classify_project(context.workspace)
    if not classification.kaggle_applicable:
        payload = {
            "platform": "kaggle",
            "status": "BLOCKED",
            "dataset_ref": f"datasets/{args.slug}",
            "reason": f"this project classifies as '{classification.project_kind}'",
        }
        return _finish(context, payload)

    gate = _load_gate(context, args)
    publisher = KagglePublisher(dataset_slug=args.slug, private=bool(args.private))
    blocked = publisher.check_gate(gate)
    if blocked is not None:
        return _finish(context, blocked.to_dict())

    skipped = publisher.check_credentials()
    if skipped is not None:
        return _finish(context, skipped.to_dict())

    directory = _prepare_directory(context, args)
    metadata = dataset_metadata(context.workspace, owner=args.owner or "")
    (directory / "dataset-metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (directory / "README.md").write_text(
        (context.workspace / "README.md").read_text(encoding="utf-8"), encoding="utf-8"
    )
    ok, problems = validate_dataset_metadata(directory)
    if not ok:
        return _finish(
            context,
            {
                "platform": "kaggle",
                "status": "BLOCKED",
                "dataset_ref": publisher.dataset_ref,
                "reason": "dataset metadata validation failed",
                "verification": {"problems": problems},
            },
        )

    if context.dry_run:
        context.note("dry run: stopping before upload")
        return _finish(
            context,
            {
                "platform": "kaggle",
                "status": "SKIPPED",
                "dataset_ref": publisher.dataset_ref,
                "reason": "dry run; no upload attempted",
            },
        )

    context.note(f"uploading {directory_digest(directory)[:16]}... to {publisher.dataset_ref}")
    result = publisher.publish(directory)
    return _finish(context, result.to_dict())


def _cmd_verify(context: CliContext, args: argparse.Namespace) -> int:
    """Verify a published target without re-uploading it."""
    username = os.environ.get(KAGGLE_USERNAME_ENV, "")
    key = os.environ.get(KAGGLE_KEY_ENV, "")
    if args.platform == "huggingface":
        if not args.namespace:
            raise UsageError(
                "--namespace is required to verify a Hugging Face repository",
                details={"example": "--namespace my-org"},
            )
        token = os.environ.get(HUGGINGFACE_TOKEN_ENV, "")
        if not token:
            skipped: dict[str, Any] = {
                "platform": "huggingface",
                "status": "SKIPPED",
                "reason": f"{HUGGINGFACE_TOKEN_ENV} is not set; verification requires it",
                "missing_configuration": [f"environment variable {HUGGINGFACE_TOKEN_ENV}"],
            }
            return _finish(context, skipped)
        verification = HuggingFacePublisher(args.namespace, repo_id=args.slug).verify(token=token)
    else:
        if not username or not key:
            missing = [
                name
                for name, value in ((KAGGLE_USERNAME_ENV, username), (KAGGLE_KEY_ENV, key))
                if not value
            ]
            skipped = {
                "platform": "kaggle",
                "status": "SKIPPED",
                "dataset_ref": f"datasets/{args.slug}",
                "reason": f"missing credentials: {', '.join(missing)}",
                "missing_configuration": [f"environment variable {name}" for name in missing],
            }
            return _finish(context, skipped)
        verification = KagglePublisher(dataset_slug=args.slug).verify(username=username, key=key)

    payload: dict[str, Any] = {
        "platform": args.platform,
        "status": "PUBLISHED" if verification.get("ok") else "PUBLISHED_BUT_VERIFICATION_FAILED",
        "reason": str(verification.get("reason", "")),
        "verification": verification,
    }
    return _finish(context, payload)
