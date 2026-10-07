"""Report rendering: human text, JSON, and SARIF 2.1.0.

Three consumers with three needs, all produced from the same
:class:`~opencode_toolkit.security_audit.models.ScanResult`:

* **text** -- what a person reads in a terminal
* **json** -- what CI and the release gate consume
* **sarif** -- what GitHub code scanning consumes

SARIF is generated rather than hand-written to 2.1.0, so the structure is
validated by ``opencode docs check`` against the documented schema invariants
rather than trusted.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final, TextIO

from opencode_toolkit.security_audit.models import SARIF_LEVEL, Finding, ScanResult, Severity
from opencode_toolkit.security_audit.rules import rule_by_id

SCHEMA_URI: Final = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION: Final = "2.1.0"
TOOL_NAME: Final = "opencode-security-audit"
INFORMATION_URI: Final = "https://github.com/opencode-toolkit/opencode-toolkit"

_SEVERITY_LABEL: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFORMATIONAL: "INFO",
}

_SEVERITY_COLOUR: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[0;31m",
    Severity.MEDIUM: "\033[0;33m",
    Severity.LOW: "\033[0;36m",
    Severity.INFORMATIONAL: "\033[0;90m",
}
_RESET: Final = "\033[0m"


def render_text(
    result: ScanResult,
    *,
    stream: TextIO,
    colour: bool = False,
    verbose: bool = False,
    max_findings: int | None = None,
) -> None:
    """Write a human-readable text report to *stream*.

    Secret values are never emitted; a secret finding shows its fingerprint only.

    Args:
        result: ScanResult: The scan to report, usually already filtered and gated.
        stream: TextIO: Destination for the rendered text.
        colour: bool: Emit ANSI colour escapes for severity labels.
        verbose: bool: Add the note that secret values are withheld.
        max_findings: int | None: Cap how many findings are listed; ``None`` lists all.
    """
    counts = result.counts_by_severity()
    summary_line = ", ".join(
        f"{counts[severity.value]} {severity.value}"
        for severity in Severity
        if counts[severity.value]
    )

    print(f"Security audit: {result.root}", file=stream)
    print(
        f"Scanned {result.files_scanned} file(s), {result.bytes_scanned} byte(s) "
        f"in {result.duration_seconds:.2f}s against {result.rule_count} rule(s)",
        file=stream,
    )
    if not result.findings:
        print("No findings.", file=stream)
    else:
        print(f"Findings: {len(result.findings)} ({summary_line or 'none'})", file=stream)

    shown = result.findings if max_findings is None else result.findings[:max_findings]
    for finding in shown:
        _render_finding_text(finding, stream=stream, colour=colour)
    if max_findings is not None and len(result.findings) > max_findings:
        remaining = len(result.findings) - max_findings
        print(
            f"... {remaining} further finding(s) omitted; use --format json for the complete set",
            file=stream,
        )

    if result.files_skipped:
        preview = ", ".join(result.files_skipped[:5])
        suffix = (
            f" (+{len(result.files_skipped) - 5} more)" if len(result.files_skipped) > 5 else ""
        )
        print(f"Skipped {len(result.files_skipped)} file(s): {preview}{suffix}", file=stream)

    if result.errors:
        print(f"Completed with {len(result.errors)} scan error(s):", file=stream)
        for error in result.errors[:10]:
            print(f"  - {error['file']}: {error['error']}: {error['detail']}", file=stream)
        if len(result.errors) > 10:
            print(f"  ... {len(result.errors) - 10} more", file=stream)

    if verbose:
        print("Secret values are never printed; fingerprints are shown instead.", file=stream)


def _render_finding_text(finding: Finding, *, stream: TextIO, colour: bool) -> None:
    label = _SEVERITY_LABEL[finding.severity]
    prefix = f"{_SEVERITY_COLOUR[finding.severity]}{label:<8}{_RESET}" if colour else f"{label:<8}"
    print("", file=stream)
    print(
        f"{prefix} {finding.rule_id}  {finding.file}:{finding.line}:{finding.column}", file=stream
    )
    print(f"         {finding.description}", file=stream)
    print(f"         cause:    {finding.root_cause}", file=stream)
    print(f"         impact:   {finding.impact}", file=stream)
    print(f"         fix:      {finding.remediation}", file=stream)
    if finding.fingerprint:
        print(
            f"         secret:   {finding.secret_kind} fingerprint {finding.fingerprint} (value withheld)",
            file=stream,
        )
    if finding.references:
        print(f"         refs:     {', '.join(finding.references)}", file=stream)


def render_json(result: ScanResult, *, stream: TextIO, indent: int | None = 2) -> None:
    """Write the machine-readable JSON report.

    Secret values are never emitted; a secret finding serialises its fingerprint
    only, so the output is safe to archive.

    Args:
        result: ScanResult: The scan to serialise via its ``to_dict`` view.
        stream: TextIO: Destination for the JSON document.
        indent: int | None: Indentation for the JSON; ``None`` writes it compact.
    """
    stream.write(json.dumps(result.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False))
    stream.write("\n")


def render_sarif(result: ScanResult, *, stream: TextIO) -> None:
    """Write a SARIF 2.1.0 log for GitHub code scanning.

    Secret values are never emitted; a secret finding contributes only its
    fingerprint and location, so the log carries no secret material.

    Args:
        result: ScanResult: The scan to convert into SARIF results and rules.
        stream: TextIO: Destination for the SARIF log.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in result.findings:
        rule = rule_by_id(finding.rule_id)
        descriptor = rules.get(finding.rule_id)
        if descriptor is None:
            descriptor = {
                "id": finding.rule_id,
                "name": _rule_name(finding.rule_id),
                "shortDescription": {
                    "text": (rule.description if rule else finding.description)[:1000]
                },
                "fullDescription": {
                    "text": (rule.root_cause if rule else finding.root_cause)[:4000]
                },
                "help": {"text": (rule.remediation if rule else finding.remediation)[:4000]},
                "defaultConfiguration": {"level": SARIF_LEVEL[finding.severity]},
                "properties": {
                    "tags": ["security", *(rule.references if rule else ())],
                    "problem.severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    **({"security-severity": _security_severity(finding.severity)} if rule else {}),
                },
            }
            if rule is not None and rule.cwe:
                descriptor["relationships"] = [
                    {
                        "target": {
                            "id": rule.cwe,
                            "guid": f"CWE-{rule.cwe}",
                            "description": {"text": f"See {rule.cwe}"},
                        }
                    }
                ]
            rules[finding.rule_id] = descriptor

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column),
                                "snippet": {"text": finding.code_location},
                            },
                        }
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": _line_fingerprint(finding)},
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "language": finding.language,
                },
            }
        )

    log: dict[str, Any] = {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": INFORMATION_URI,
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not any(
                            error["error"] == "unreadable" for error in result.errors
                        ),
                        "exitCode": 0,
                    }
                ],
            }
        ],
    }
    stream.write(json.dumps(log, indent=2, sort_keys=True, ensure_ascii=False))
    stream.write("\n")


#: GitHub code scanning maps numeric severities onto this 0.0-10.0 scale.
_SECURITY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFORMATIONAL: "1.0",
}


def _security_severity(severity: Severity) -> str:
    return _SECURITY_SEVERITY[severity]


def _rule_name(rule_id: str) -> str:
    """Derive a human-readable rule name from its identifier."""
    parts = rule_id.split("-", 2)
    if len(parts) == 3:
        return f"{parts[1]}{parts[2]}".title().replace(" ", "")
    return rule_id


def _line_fingerprint(finding: Finding) -> str:
    """Stable per-location identity so GitHub can track a finding across runs."""
    material = f"{finding.rule_id}|{finding.file}|{finding.line}|{finding.code_location}"
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]
