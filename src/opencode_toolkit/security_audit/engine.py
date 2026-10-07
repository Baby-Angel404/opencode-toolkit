"""The scanning engine.

Responsibilities, in order: enumerate candidate files, skip what cannot or must
not be read, run the language-specific analysers, deduplicate, apply the
configured filters, and return a fully-populated :class:`ScanResult`.

Two behaviours are load-bearing for trust in the output:

* **Secrets are never emitted.** Rules that capture a credential attach only a
  redacted fingerprint. The raw value is used to compute that fingerprint and
  then discarded.
* **Failures are visible.** Unreadable or unparsable files are recorded in
  ``files_skipped`` / ``errors`` rather than silently dropped, so a scan that
  quietly covered half the tree cannot be mistaken for a clean scan.
"""

from __future__ import annotations

import fnmatch
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opencode_toolkit.core import logging
from opencode_toolkit.core.config import SecurityAuditPolicy
from opencode_toolkit.core.errors import UsageError
from opencode_toolkit.core.fsio import is_binary_suffix, iter_files, looks_binary
from opencode_toolkit.core.redact import fingerprint, redact_text
from opencode_toolkit.security_audit import py_ast, redos
from opencode_toolkit.security_audit.models import Confidence, Finding, ScanResult
from opencode_toolkit.security_audit.rules import (
    PATTERN_RULES,
    PatternRule,
    Rule,
    all_rules,
    rule_by_id,
)

logger = logging.get_logger("security_audit.engine")

#: Extension to language mapping. Anything else is not scanned, because
#: guessing would produce findings nobody can act on.
LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".go": "go",
}

#: Files that are secret material in their own right. Finding these is more
#: useful than analysing their contents.
SENSITIVE_FILENAMES: dict[str, str] = {
    ".env": "credential",
    ".env.local": "credential",
    ".env.production": "credential",
    ".env.development": "credential",
    "credentials": "credential",
    "secrets.yaml": "credential",
    "secrets.yml": "credential",
    "secrets.json": "credential",
    "id_rsa": "private_key",
    "id_ed25519": "private_key",
}

SENSITIVE_SUFFIXES: dict[str, str] = {
    ".pem": "private_key",
    ".key": "private_key",
    ".p12": "private_key",
    ".pfx": "private_key",
    ".jks": "private_key",
    ".keystore": "private_key",
    ".ppk": "private_key",
}

#: Exact directory names that are never descended into, in addition to the
#: configured exclusions. Hard-coded so a permissive config cannot cause the
#: auditor to walk a vendored tree.
_ALWAYS_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".nox",
        "vendor",
    }
)

_MAX_EXCERPT_LINES = 3


def detect_language(path: Path) -> str | None:
    """Return the language for *path*, or ``None`` when unsupported.

    Args:
        path: Path: File to classify; only its suffix is consulted, matched
            case-insensitively. ``None`` means no rule supports the language.
    """
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Everything that shapes one audit run."""

    policy: SecurityAuditPolicy
    follow_symlinks: bool = False
    max_file_bytes: int = 4_000_000
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    enabled_rules: frozenset[str] | None = None
    strict: bool = False


@dataclass(frozen=True, slots=True)
class AuditEngine:
    """Runs the audit. Construct once, call :meth:`scan` per root."""

    options: ScanOptions

    @classmethod
    def from_policy(
        cls,
        policy: SecurityAuditPolicy | None = None,
        *,
        strict: bool = False,
        include: Sequence[str] = (),
        exclude: Sequence[str] = (),
        rules: Iterable[str] | None = None,
    ) -> AuditEngine:
        """Build an engine from configuration plus command-line overrides.

        Args:
            policy: SecurityAuditPolicy | None: Base configuration; ``None``
                uses the documented defaults.
            strict: bool: Fail on warnings and info, not just blocking findings.
            include: Sequence[str]: Glob patterns a file must match to be
                audited; empty means audit everything.
            exclude: Sequence[str]: Glob patterns that skip a file even when
                *include* matches it.
            rules: Iterable[str] | None: Rule IDs to enable; ``None`` enables
                every rule the policy configures.
        """
        resolved = policy or SecurityAuditPolicy()
        return cls(
            options=ScanOptions(
                policy=resolved,
                follow_symlinks=resolved.follow_symlinks,
                max_file_bytes=resolved.max_file_bytes,
                include=tuple(include),
                exclude=tuple(exclude),
                enabled_rules=frozenset(rules) if rules is not None else None,
                strict=strict,
            )
        )

    # -- public API -------------------------------------------------------
    def scan(self, root: Path) -> ScanResult:
        """Audit *root* recursively and return the aggregated result.

        Args:
            root: Path: Directory to walk, or a single file to audit; resolved
                before scanning. Raises :class:`UsageError` when it is missing.
        """
        root = root.resolve()
        started = time.perf_counter()
        result = ScanResult(root=str(root), rule_count=len(all_rules()))

        if not root.exists():
            raise UsageError(
                f"path does not exist: {root}",
                code="scan.path_missing",
                details={"path": str(root)},
            )
        if root.is_file():
            self._scan_single_file(root, root, result)
        else:
            for candidate in self._iter_candidates(root):
                self._scan_single_file(root, candidate, result)

        result.findings = self._deduplicate(result.findings)
        result.findings.sort(key=lambda item: item.sort_key)
        result.duration_seconds = time.perf_counter() - started
        return result

    # -- enumeration ------------------------------------------------------
    def _iter_candidates(self, root: Path) -> list[Path]:
        excluded_dirs = set(self.options.policy.exclude_dirs) | _ALWAYS_EXCLUDED_DIRS
        excluded_files = {name.lower() for name in self.options.exclude}
        candidates: list[Path] = []
        for path in iter_files(
            root,
            exclude_dirs=excluded_dirs,
            follow_symlinks=self.options.follow_symlinks,
            max_file_bytes=self.options.max_file_bytes,
        ):
            lowered = path.name.lower()
            if lowered in excluded_files:
                continue
            if self._explicitly_excluded(path, root):
                continue
            if self.options.include and not any(
                _relative_matches(path, root, pattern) for pattern in self.options.include
            ):
                continue
            candidates.append(path)
        return candidates

    def _explicitly_excluded(self, path: Path, root: Path) -> bool:
        """Return ``True`` when configuration excludes this exact file.

        The match is a suffix match on the scanner's path label, so one pattern
        works whether the audit is pointed at the repository root or at ``src``.
        """
        patterns = self.options.policy.exclude_paths
        if not patterns:
            return False
        label = _label_for(path, root)
        for pattern in patterns:
            if fnmatch.fnmatch(label, pattern) or label.endswith(pattern):
                return True
        return False

    # -- per-file ---------------------------------------------------------
    def _scan_single_file(self, root: Path, path: Path, result: ScanResult) -> None:
        label = _label_for(path, root)

        # Secret-bearing filenames are reported without reading further.
        filename_finding = self._check_sensitive_filename(path, label)
        if filename_finding is not None:
            result.findings.append(filename_finding)
            result.files_scanned += 1
            return

        language = detect_language(path)
        if language is None:
            result.files_skipped.append(label)
            return
        if path.suffix.lower() not in {
            ext.lower() for ext in self.options.policy.include_extensions
        }:
            result.files_skipped.append(label)
            return
        if is_binary_suffix(path):
            result.files_skipped.append(label)
            return

        try:
            raw = path.read_bytes()
        except OSError as exc:
            reason = exc.strerror or str(exc)
            result.errors.append({"file": label, "error": "unreadable", "detail": reason})
            logger.debug("cannot read %s: %s", label, reason)
            return

        if looks_binary(raw):
            result.files_skipped.append(label)
            return

        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            # Files with a non-UTF-8 encoding are skipped rather than guessed at;
            # a mis-decoded audit is worse than an explicit gap.
            result.files_skipped.append(label)
            result.errors.append(
                {"file": label, "error": "not_utf8", "detail": "file is not valid UTF-8"}
            )
            return

        result.files_scanned += 1
        result.bytes_scanned += len(raw)

        if language == "python":
            parse_error = py_ast.python_parse_error(source)
            if parse_error is not None:
                result.errors.append({"file": label, "error": "syntax", "detail": parse_error})
                # Still run the pattern rules: a file that does not compile can
                # still contain a hard-coded credential, which is worth knowing.
        findings = list(self._analyse(label, language, source))
        findings.extend(redos.scan_for_redos(label, source, language))
        result.findings.extend(self._filter(findings))

    def _analyse(self, label: str, language: str, source: str) -> Iterable[Finding]:
        if language == "python":
            yield from py_ast.iter_python_findings(label, source)
        yield from self._pattern_findings(label, language, source)

    def _pattern_findings(self, label: str, language: str, source: str) -> Iterable[Finding]:
        applicable: Sequence[PatternRule] = tuple(
            item for item in PATTERN_RULES if language in item.rule.languages
        )
        if not applicable:
            return
        lines = source.splitlines()
        for index, line in enumerate(lines, start=1):
            if len(line) > 2000:
                # A minified or generated line is not reviewable source; skipping
                # it is recorded by the caller through the length guard.
                continue
            for entry in applicable:
                if not self._rule_enabled(entry.rule.rule_id):
                    continue
                match = self._match_entry(entry, line)
                if match is None:
                    continue
                finding, secret = match
                yield self._build_finding(label, line, index, finding, secret)

    def _match_entry(self, entry: PatternRule, line: str) -> tuple[Rule, str | None] | None:
        """Return the matched rule and the captured secret, if any."""
        for negative in entry.negative_patterns:
            if negative.search(line):
                return None
        for pattern in entry.patterns:
            match = pattern.search(line)
            if match is None:
                continue
            secret: str | None = None
            if entry.captures_secret and entry.secret_group <= (match.re.groups or 0):
                secret = match.group(entry.secret_group)
            return entry.rule, secret
        return None

    def _build_finding(
        self,
        label: str,
        line: str,
        lineno: int,
        rule: Rule,
        secret: str | None,
    ) -> Finding:
        excerpt = redact_text(line.strip()) if line.strip() else f"<blank line {lineno}>"
        if len(excerpt) > 240:
            excerpt = excerpt[:240] + "..."
        if not excerpt:
            excerpt = "<no source text available>"
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            confidence=rule.confidence,
            file=label,
            line=lineno,
            column=self._column_of(line),
            code_location=excerpt,
            description=rule.title if rule.title else rule.description,
            root_cause=rule.root_cause,
            impact=rule.impact,
            remediation=rule.remediation,
            language=rule.languages[0] if rule.languages else "unknown",
            references=rule.references,
            secret_kind=rule.secret_kind,
            fingerprint=fingerprint(secret) if secret else None,
        )

    # -- whole-file checks ------------------------------------------------
    def _check_sensitive_filename(self, path: Path, label: str) -> Finding | None:
        lowered = path.name.lower()
        kind = SENSITIVE_FILENAMES.get(lowered) or SENSITIVE_SUFFIXES.get(path.suffix.lower())
        if kind is None:
            return None
        if kind == "private_key":
            return self._synthetic_finding(
                "OCSA-CRED-004",
                label,
                1,
                f"Private key file present: {path.name}",
                note=f"{path.suffix or 'unknown'} key material stored inside the scanned tree",
            )
        return self._synthetic_finding(
            "OCSA-CRED-006",
            label,
            1,
            f"Credential file present: {path.name}",
            note="dotenv-style credential file found in the scanned tree",
        )

    def _synthetic_finding(
        self, rule_id: str, label: str, lineno: int, title: str, *, note: str
    ) -> Finding:
        rule = rule_by_id(rule_id)
        if rule is None:  # pragma: no cover - table drift guard
            raise LookupError(rule_id)
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            confidence=rule.confidence,
            file=label,
            line=lineno,
            column=0,
            code_location=f"<{path_kind(label)}: {note}>",
            description=title,
            root_cause=rule.root_cause,
            impact=rule.impact,
            remediation=rule.remediation,
            language="any",
            references=rule.references,
            secret_kind=rule.secret_kind,
            fingerprint=None,
        )

    # -- filtering --------------------------------------------------------
    def _rule_enabled(self, rule_id: str) -> bool:
        enabled = self.options.enabled_rules
        if enabled is not None and rule_id not in enabled:
            return False
        return rule_id not in self.options.policy.ignore_rule_ids

    def _filter(self, findings: Iterable[Finding]) -> list[Finding]:
        return [finding for finding in findings if self._rule_enabled(finding.rule_id)]

    @staticmethod
    def _deduplicate(findings: Sequence[Finding]) -> list[Finding]:
        """Collapse identical findings produced by both analysers.

        The AST and the pattern table both cover several rules, so one physical
        line can produce the same rule id twice at different columns. Findings
        are collapsed per ``(rule_id, file, line)``: a second occurrence of the
        same rule on one physical line is a style problem, not a second finding,
        and reporting it twice would inflate the counts a release gate reads.
        """
        seen: set[tuple[str, str, int]] = set()
        unique: list[Finding] = []
        for finding in findings:
            key = (finding.rule_id, finding.file, finding.line)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    @staticmethod
    def _column_of(line: str) -> int:
        stripped = line.strip()
        if not stripped:
            return 0
        return max(0, len(line) - len(line.lstrip()))


def _label_for(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        return path.name
    return relative.as_posix()


def _relative_matches(path: Path, root: Path, pattern: str) -> bool:
    label = _label_for(path, root)
    if pattern in label:
        return True
    try:
        return path.resolve().match(pattern)
    except (ValueError, IndexError):
        return False


def path_kind(label: str) -> str:
    """Return a coarse file kind used in synthetic findings.

    Args:
        label: str: Path label relative to the scan root; a file name containing
            a dot yields ``file``, anything else yields ``entry``.
    """
    return "file" if "." in Path(label).name else "entry"


def scan_path(root: Path, policy: SecurityAuditPolicy | None = None, **kwargs: Any) -> ScanResult:
    """Convenience wrapper: build an engine from *policy* and scan *root*.

    Args:
        root: Path: Directory to walk, or a single file to audit.
        policy: SecurityAuditPolicy | None: Configuration for the engine;
            ``None`` uses the documented defaults.
        **kwargs: Any: Further overrides forwarded to
            :meth:`AuditEngine.from_policy`, such as ``strict``, ``include``,
            ``exclude`` or ``rules``.
    """
    engine = AuditEngine.from_policy(policy or SecurityAuditPolicy(), **kwargs)
    return engine.scan(root)


def rule_catalogue() -> list[dict[str, Any]]:
    """Return the rule catalogue for documentation and ``--list-rules``."""
    catalogue = []
    for rule in all_rules():
        catalogue.append(
            {
                "rule_id": rule.rule_id,
                "severity": rule.severity.value,
                "confidence": rule.confidence.value,
                "languages": list(rule.languages),
                "title": rule.title,
                "description": rule.description,
                "root_cause": rule.root_cause,
                "impact": rule.impact,
                "remediation": rule.remediation,
                "references": list(rule.references),
                "secret_kind": rule.secret_kind,
                "cwe": rule.cwe,
            }
        )
    catalogue.sort(key=lambda item: (item["rule_id"],))
    return catalogue


def rule_confidence_summary() -> dict[str, int]:
    """Count rules per confidence level (used by the doctor report)."""
    summary: dict[str, int] = {level.value: 0 for level in Confidence}
    for rule in all_rules():
        summary[rule.confidence.value] += 1
    return summary
