"""Publishing directory preparation and secret scanning.

The artefact that gets uploaded must be built from an explicit allow-list of
paths, not from an exclusion list of what looks bad. A denylist is always one
pattern short; an allow-list cannot leak a file that was not deliberately
included.

After the directory is built, a secret scan runs **against the exact bytes that
will be uploaded** -- not against the source tree -- and a single hit aborts the
publish.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core import logging
from opencode_toolkit.core.errors import IntegrityError
from opencode_toolkit.core.fsio import sha256_file
from opencode_toolkit.core.redact import fingerprint, is_allowlisted

logger = logging.get_logger("publishing.artifacts")

#: Never included in a publishing directory, regardless of allow-list.
EXCLUDED_PATTERNS: tuple[str, ...] = (
    ".git/*",
    ".git/**",
    ".venv/*",
    ".venv/**",
    "venv/*",
    "node_modules/*",
    "node_modules/**",
    "__pycache__/*",
    "**/__pycache__/*",
    "*.pyc",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.ppk",
    "id_rsa*",
    "*.kaggle",
    "token",
    "secrets*",
    ".opencode/toolkit/snapshots/*",
    ".opencode/toolkit/queue/*",
    ".pytest_cache/*",
    ".ruff_cache/*",
    ".mypy_cache/*",
    "dist/*",
)

#: Default allow-list: the package, docs, metadata, tests and workflows.
DEFAULT_ALLOWLIST: tuple[str, ...] = (
    "src/*",
    "docs/*",
    "examples/*",
    "tests/*",
    "scripts/*",
    ".github/*",
    ".changes/*",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "CITATION.cff",
    "pyproject.toml",
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
    ".gitignore",
    "SECURITY.md",
)

#: Patterns that indicate a real credential in a text file.
SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----", "private_key"),
    (r"\bhf_[A-Za-z0-9]{20,}", "huggingface_token"),
    (r"\bhf_[A-Za-z0-9]{30,}", "huggingface_token"),
    (r"\bsk-[A-Za-z0-9]{20,}", "api_key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key_id"),
    (r"\bghp_[A-Za-z0-9]{36}\b", "github_token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{50,}", "github_token"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}", "slack_token"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "jwt"),
    (r"\b[0-9a-f]{40}\b", "git_commit_or_sha1"),
    (
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*[\"'][^\"'\s]{16,}[\"']",
        "credential_assignment",
    ),
)

#: Values that match a secret pattern but are obviously not live credentials.
BENIGN_TOKEN_VALUES: frozenset[str] = frozenset(
    {
        "hf_your_token_here",
        "hf_replace_me",
        "your_token_here",
    }
)

MAX_SCAN_BYTES = 2 * 1024 * 1024

#: Directories never scanned. Build output and tool caches routinely echo values
#: from earlier runs -- including the test fixtures that deliberately contain
#: fake credentials -- and reporting those would bury a real finding.
SCAN_EXCLUDED_DIRS: tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    "dist",
    "build",
    ".egg-info",
    # The toolkit's own state directory: generated, .gitignore'd, and full of
    # things that legitimately look like credentials. The release gate records
    # the current commit, and a 40-character hex SHA-1 is what the secret
    # scanner is built to flag -- so scanning the gate that records a commit
    # reports the scanner's own output as a finding.
    ".opencode",
)


@dataclass(slots=True)
class SecretHit:
    """One suspected credential."""

    file: str
    line: int
    kind: str
    redacted: str

    def to_dict(self) -> dict[str, Any]:
        """Return the hit with a redacted value; the credential itself is not carried."""
        return {"file": self.file, "line": self.line, "kind": self.kind, "evidence": self.redacted}


@dataclass(slots=True)
class SecretScanReport:
    """Result of scanning a directory for credentials."""

    root: str
    files_scanned: int = 0
    hits: list[SecretHit] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        """``True`` when the scan found nothing."""
        return not self.hits

    def to_dict(self) -> dict[str, Any]:
        """Return the scan result as JSON-serialisable data."""
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "clean": self.clean,
            "hit_count": len(self.hits),
            "hits": [hit.to_dict() for hit in self.hits],
            "skipped": self.skipped,
        }


def is_excluded(relative: str) -> bool:
    """Return ``True`` when *relative* matches an exclusion pattern.

    Args:
        relative: str: Path relative to the source root, in POSIX form, matched
            with :mod:`fnmatch` against :data:`EXCLUDED_PATTERNS`.
    """
    return any(fnmatch.fnmatch(relative, pattern) for pattern in EXCLUDED_PATTERNS)


def is_allowed(relative: str, allowlist: Iterable[str]) -> bool:
    """Return ``True`` when *relative* matches the allow-list.

    Args:
        relative: str: Path relative to the source root, in POSIX form, matched
            with :mod:`fnmatch` against the patterns in *allowlist*.
        allowlist: Iterable[str]: Glob patterns a file must match to be included;
            every pattern that matches returns ``True``.
    """
    return any(fnmatch.fnmatch(relative, pattern) for pattern in allowlist)


def clean_publish_directory(
    source: Path,
    destination: Path,
    *,
    allowlist: Iterable[str] = DEFAULT_ALLOWLIST,
) -> dict[str, Any]:
    """Build a clean publishing directory from an allow-list.

    Refuses to write into a directory that already contains files, so a previous
    run's leftovers cannot leak into an upload.

    Args:
        source: Path: Existing directory to copy from; every path is read through
            it, and its absence raises :class:`IntegrityError`.
        destination: Path: Empty directory to write the artefact into. An existing
            non-empty directory raises :class:`IntegrityError`.
        allowlist: Iterable[str]: Glob patterns a file must match to be copied;
            files matching no pattern are recorded as excluded and never written.

    Raises:
        IntegrityError: The source is missing, the destination is not empty, or
            the allow-list matched no files.
    """
    source = source.resolve()
    destination = destination.resolve()
    if not source.is_dir():
        raise IntegrityError(
            f"publishing source directory not found: {source}",
            details={"path": str(source)},
        )
    if destination.exists() and any(destination.iterdir()):
        raise IntegrityError(
            f"publishing directory is not empty: {destination}",
            details={"path": str(destination)},
            hint="remove it first; this prevents a previous run's files from being uploaded",
        )

    included: list[str] = []
    excluded: list[str] = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            excluded.append(path.relative_to(source).as_posix() + " (symlink)")
            continue
        relative = path.relative_to(source).as_posix()
        if path.is_dir():
            continue
        if is_excluded(relative) or not is_allowed(relative, allowlist):
            excluded.append(relative)
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        included.append(relative)

    if not included:
        raise IntegrityError(
            "the allow-list matched no files; refusing to publish an empty artefact",
            details={"allowlist_size": len(list(allowlist))},
        )

    logger.info("prepared publishing directory with %d files", len(included))
    return {
        "source": str(source),
        "destination": str(destination),
        "included": sorted(included),
        "excluded_count": len(excluded),
        "excluded_sample": sorted(excluded)[:20],
    }


def scan_for_secrets(root: Path, *, skip_allowlist: Iterable[str] = ()) -> SecretScanReport:
    """Scan every text file under *root* for credential-shaped content.

    Args:
        root: Path: Directory to walk recursively; the directory itself is
            resolved before scanning.
        skip_allowlist: Iterable[str]: Relative paths to leave unscanned, in
            addition to :data:`SCAN_EXCLUDED_DIRS` and :data:`EXCLUDED_PATTERNS`.
    """
    import re

    root = root.resolve()
    report = SecretScanReport(root=str(root))
    patterns = [(re.compile(pattern), kind) for pattern, kind in SECRET_PATTERNS]

    excluded = set(SCAN_EXCLUDED_DIRS)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in set(skip_allowlist):
            continue
        if excluded & set(Path(relative).parts[:-1]):
            continue
        if is_excluded(relative):
            continue
        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                report.skipped.append(f"{relative} (larger than {MAX_SCAN_BYTES} bytes)")
                continue
            data = path.read_bytes()
        except OSError as exc:
            report.skipped.append(f"{relative} ({exc.strerror or exc})")
            continue
        if b"\x00" in data[:4096]:
            report.skipped.append(f"{relative} (binary)")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            report.skipped.append(f"{relative} (not UTF-8)")
            continue

        report.files_scanned += 1
        for number, line in enumerate(text.splitlines(), start=1):
            for pattern, kind in patterns:
                for match in pattern.finditer(line):
                    value = match.group(0)
                    if is_allowlisted(value) or value in BENIGN_TOKEN_VALUES:
                        continue
                    # The evidence is a correlation token, never the matched
                    # text: a credential on a line of its own has no surrounding
                    # key for redact_text to key off, so echoing the match would
                    # put the secret straight back into the report.
                    report.hits.append(
                        SecretHit(
                            file=relative,
                            line=number,
                            kind=kind,
                            redacted=f"***redacted:{kind}:sha256:{fingerprint(match.group(0))}***",
                        )
                    )
    return report


def assert_clean(directory: Path) -> SecretScanReport:
    """Scan *directory* and raise when any credential-shaped content is found.

    Args:
        directory: Path: Prepared publishing directory to scan. A hit raises
            :class:`IntegrityError` carrying redacted evidence only -- the
            matched text is never returned or logged.

    Raises:
        IntegrityError: The scan found at least one hit.
    """
    report = scan_for_secrets(directory)
    if not report.clean:
        raise IntegrityError(
            f"secret scan found {len(report.hits)} potential credential(s) in the publishing directory",
            code="publish.secret_detected",
            details={"hits": [hit.to_dict() for hit in report.hits[:20]]},
            hint="remove the credential from the artefact; do not publish a redacted version of a live secret",
        )
    return report


def directory_digest(root: Path) -> str:
    """A single digest over every file's path and content, for the report.

    Args:
        root: Path: Directory to digest; symlinks and directories are skipped, so
            the value covers regular files only.
    """
    from opencode_toolkit.core.fsio import sha256_bytes

    parts: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        parts.append(f"{path.relative_to(root).as_posix()}:{sha256_file(path)}")
    return sha256_bytes("\n".join(parts).encode("utf-8"))
