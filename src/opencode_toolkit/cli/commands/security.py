"""``opencode security-audit`` -- multi-language security auditing."""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path

from opencode_toolkit.cli.context import JSON, SARIF, CliContext, emit_json
from opencode_toolkit.core import exit_codes
from opencode_toolkit.core.config import SecurityAuditPolicy
from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.security_audit.engine import AuditEngine, rule_catalogue
from opencode_toolkit.security_audit.models import ScanResult, Severity
from opencode_toolkit.security_audit.reports import render_json, render_sarif, render_text


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = subparsers.add_parser(
        "security-audit",
        help="audit a tree for security risks (Python, JavaScript, TypeScript, Go)",
        description=(
            "Scan a file or directory for hard-coded credentials, injection, unsafe "
            "deserialization, weak crypto, disabled TLS verification and other practical "
            "risk classes. Secret values are never printed; a fingerprint is reported instead."
        ),
        epilog=(
            "exit codes: 0 no finding at or above --fail-on, 1 findings present, "
            "2 bad arguments, 4 unreadable path"
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="file or directory to scan (default: the current directory)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="fail on any finding at medium severity or above, and on scan errors",
    )
    parser.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        default=None,
        help="lowest severity that causes a non-zero exit (default: from configuration)",
    )
    parser.add_argument(
        "--min-severity",
        choices=[severity.value for severity in Severity],
        default=None,
        help="hide findings below this severity from the report",
    )
    parser.add_argument(
        "--rule",
        dest="rules",
        action="append",
        default=None,
        metavar="RULE_ID",
        help="only run these rule ids (repeatable)",
    )
    parser.add_argument(
        "--ignore",
        dest="ignore",
        action="append",
        default=None,
        metavar="RULE_ID",
        help="suppress these rule ids (repeatable)",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="PATTERN",
        help="only scan paths matching this glob (repeatable)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="skip paths matching this glob (repeatable)",
    )
    parser.add_argument(
        "--list-rules", action="store_true", help="print the rule catalogue as JSON and exit"
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="cap the number of findings shown in text output",
    )
    parser.add_argument(
        "--colour",
        "--color",
        dest="colour",
        action="store_true",
        default=None,
        help="force ANSI colour in text output",
    )
    parser.set_defaults(handler=run_audit)


def resolve_policy(context: CliContext, args: argparse.Namespace) -> SecurityAuditPolicy:
    """Combine configuration with command-line overrides.

    Built with :func:`dataclasses.replace` rather than field by field, so a
    policy key added later cannot be silently dropped here -- that bug once made
    ``exclude_paths`` invisible to the CLI while still working in the library.

    Args:
        context: CliContext: Context whose resolved config supplies the
            configured policy.
        args: argparse.Namespace: Parsed ``security-audit`` overrides for
            ``fail_on``, ``strict`` and ignored rule ids.

    Returns:
        SecurityAuditPolicy: The configured policy with the overrides applied.
    """
    policy = context.config.security_audit
    fail_on: tuple[str, ...] = policy.fail_on
    if args.fail_on:
        fail_on = (args.fail_on,)
    if args.strict:
        fail_on = ("medium", "high", "critical")
    ignore = policy.ignore_rule_ids + tuple(args.ignore or ())
    return replace(policy, fail_on=fail_on, ignore_rule_ids=ignore)


def run_audit(context: CliContext, args: argparse.Namespace) -> int:
    """Execute ``opencode security-audit``.

    Args:
        context: CliContext: Workspace, layout, config and output streams the
            findings are reported through.
        args: argparse.Namespace: Parsed ``security-audit`` options, including
            the include/exclude paths and severity overrides.
    """
    if args.list_rules:
        emit_json(rule_catalogue(), context.stdout)
        return exit_codes.OK

    policy = resolve_policy(context, args)
    engine = AuditEngine.from_policy(
        policy,
        strict=bool(args.strict),
        include=args.include or (),
        exclude=args.exclude or (),
        rules=args.rules,
    )

    target = Path(args.path).expanduser()
    if not target.exists():
        raise UsageError(
            f"path does not exist: {target}",
            code="scan.path_missing",
            details={"path": str(target), "workspace": str(context.workspace)},
            hint="pass a path relative to the current directory or an absolute path",
        )

    result = engine.scan(target)
    report = _filter(result, args.min_severity)

    return _emit(context, args, report, policy)


def _filter(result: ScanResult, minimum: str | None) -> ScanResult:
    if minimum is None:
        return result
    return result.filtered(minimum=Severity(minimum))


def _emit(
    context: CliContext, args: argparse.Namespace, report: ScanResult, policy: SecurityAuditPolicy
) -> int:
    colour = args.colour if args.colour is not None else context.stdout.isatty()

    if context.output_format == SARIF:
        render_sarif(report, stream=context.stdout)
        return exit_codes.OK
    if context.output_format == JSON:
        render_json(report, stream=context.stdout)
    else:
        render_text(
            report,
            stream=context.stdout,
            colour=colour,
            verbose=context.verbose,
            max_findings=args.max_findings,
        )

    fail_levels = frozenset(Severity(level) for level in policy.fail_on)

    # Strict mode additionally treats an incomplete scan as a failure: a scan
    # that could not read half the tree has not demonstrated anything.
    if args.strict and report.errors:
        context.warn(
            f"strict mode: {len(report.errors)} scan error(s) count as a failure; "
            "fix the unreadable or malformed files listed above"
        )
        return exit_codes.FAILURE

    if report.failing(fail_levels):
        highest = report.highest_severity()
        context.note(f"highest severity: {highest.value if highest else 'none'}")
        return exit_codes.FAILURE

    if report.errors:
        context.warn(
            f"{len(report.errors)} file(s) could not be fully analysed; the scan is incomplete"
        )
    return exit_codes.OK


__all__ = ["register", "resolve_policy", "run_audit"]
