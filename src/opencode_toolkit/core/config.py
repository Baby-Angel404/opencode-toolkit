"""Configuration loading and validation.

Configuration lives in ``.opencode/toolkit/config.json`` in the workspace. It is
optional: every field has a default, so the toolkit works with no config file at
all. Unknown keys are a hard error rather than a warning -- a typo in a security
tuning knob must not silently disable it.

Validation collects *all* problems before raising so the user sees the full list
in one run instead of discovering them one restart at a time.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final

from opencode_toolkit.core import jsonio
from opencode_toolkit.core.errors import ConfigurationError
from opencode_toolkit.core.paths import Layout
from opencode_toolkit.core.version import Version

CONFIG_RELPATH: Final = Path(".opencode") / "toolkit" / "config.json"
CONFIG_VERSION: Final = 1

#: Named policies with defaults, so validation is table-driven and documented.
POLICY_DEFAULTS: Final[dict[str, Any]] = {
    "security_audit": {
        "include_extensions": [
            ".py",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            ".go",
        ],
        "exclude_dirs": [
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "__pycache__",
            "dist",
            "build",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
        ],
        "max_file_bytes": 4_000_000,
        "follow_symlinks": False,
        "fail_on": ["critical", "high"],
        "ignore_rule_ids": [],
        "exclude_paths": [],
    },
    "sync": {
        "kdf_iterations": 600_000,
        "kdf_algorithm": "pbkdf2-hmac-sha256",
        "salt_bytes": 16,
        "nonce_bytes": 16,
        "encrypt_by_default": True,
        "redact_env_files": True,
    },
    "orchestrator": {
        "max_parallel_agents": 4,
        "task_timeout_seconds": 1800,
        "max_task_retries": 2,
        "require_ownership": True,
        "checkpoint_on_transition": True,
    },
    "pack": {
        "include_docs": True,
        "include_dependencies": False,
        "exclude_patterns": ["*.pyc", "__pycache__/*", ".git/*"],
        "verify_on_build": True,
    },
    "docs": {
        "docstring_style": "google",
        "require_docstrings_for_public": True,
        "check_cli_commands": True,
    },
    "release": {
        "require_reproducibility": True,
        "allow_prerelease": False,
    },
}

_KNOWN_TOP_LEVEL: Final = {*POLICY_DEFAULTS, "config_version", "project"}


@dataclass(frozen=True, slots=True)
class SecurityAuditPolicy:
    """Scan scope and pass/fail thresholds for the security audit.

    Defaults are deliberately broad: the extension and directory lists decide
    what is scanned at all, so narrowing them silently shrinks the audit. The
    values are validated when the config is loaded, not here.
    """

    include_extensions: tuple[str, ...] = (
        ".py",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".go",
    )
    exclude_dirs: tuple[str, ...] = (
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    )
    max_file_bytes: int = 4_000_000
    follow_symlinks: bool = False
    fail_on: tuple[str, ...] = ("critical", "high")
    ignore_rule_ids: tuple[str, ...] = ()
    #: Individual files excluded from the audit, matched against the path as the
    #: scanner labels it. Used for files that legitimately contain
    #: insecure-looking text as *data* -- this project's own rule catalogue, for
    #: example. Every entry is reported by ``opencode security-audit`` so an
    #: exclusion is never invisible.
    exclude_paths: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> SecurityAuditPolicy:
        """Build a policy from one ``security_audit`` config section.

        Absent keys keep their default, so a partial section is valid; keys with
        the wrong type are rejected earlier by ``_validate_document`` rather than
        being coerced here.

        Args:
            data: dict[str, Any]: The raw ``security_audit`` object from the config document.

        Returns:
        """
        base = cls()
        return replace(
            base,
            include_extensions=tuple(data.get("include_extensions", base.include_extensions)),
            exclude_dirs=tuple(data.get("exclude_dirs", base.exclude_dirs)),
            max_file_bytes=int(data.get("max_file_bytes", base.max_file_bytes)),
            follow_symlinks=bool(data.get("follow_symlinks", base.follow_symlinks)),
            fail_on=tuple(data.get("fail_on", base.fail_on)),
            ignore_rule_ids=tuple(data.get("ignore_rule_ids", base.ignore_rule_ids)),
            exclude_paths=tuple(data.get("exclude_paths", base.exclude_paths)),
        )


@dataclass(frozen=True, slots=True)
class SyncPolicy:
    """Key derivation and at-rest encryption settings for the secret store.

    ``kdf_iterations`` and the salt/nonce sizes have enforced floors (100000
    iterations, 16 bytes each); a config below those raises rather than clamping,
    because a quietly weakened KDF is indistinguishable from the intended one.
    """

    kdf_iterations: int = 600_000
    kdf_algorithm: str = "pbkdf2-hmac-sha256"
    salt_bytes: int = 16
    nonce_bytes: int = 16
    encrypt_by_default: bool = True
    redact_env_files: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> SyncPolicy:
        """Build a policy from one ``sync`` config section.

        Args:
            data: dict[str, Any]: The raw ``sync`` object from the config document.

        Returns:
        """
        base = cls()
        return replace(
            base,
            kdf_iterations=int(data.get("kdf_iterations", base.kdf_iterations)),
            kdf_algorithm=str(data.get("kdf_algorithm", base.kdf_algorithm)),
            salt_bytes=int(data.get("salt_bytes", base.salt_bytes)),
            nonce_bytes=int(data.get("nonce_bytes", base.nonce_bytes)),
            encrypt_by_default=bool(data.get("encrypt_by_default", base.encrypt_by_default)),
            redact_env_files=bool(data.get("redact_env_files", base.redact_env_files)),
        )


@dataclass(frozen=True, slots=True)
class OrchestratorPolicy:
    """Concurrency, timeout and durability limits for multi-agent execution."""

    max_parallel_agents: int = 4
    task_timeout_seconds: int = 1800
    max_task_retries: int = 2
    require_ownership: bool = True
    checkpoint_on_transition: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> OrchestratorPolicy:
        """Build a policy from one ``orchestrator`` config section.

        Args:
            data: dict[str, Any]: The raw ``orchestrator`` object from the config document.

        Returns:
        """
        base = cls()
        return replace(
            base,
            max_parallel_agents=int(data.get("max_parallel_agents", base.max_parallel_agents)),
            task_timeout_seconds=int(data.get("task_timeout_seconds", base.task_timeout_seconds)),
            max_task_retries=int(data.get("max_task_retries", base.max_task_retries)),
            require_ownership=bool(data.get("require_ownership", base.require_ownership)),
            checkpoint_on_transition=bool(
                data.get("checkpoint_on_transition", base.checkpoint_on_transition)
            ),
        )


@dataclass(frozen=True, slots=True)
class PackPolicy:
    """Contents and post-build verification rules for the offline pack.

    ``verify_on_build`` is on by default: a pack that is not re-read from disk
    proves nothing about the bytes a consumer will actually unpack.
    """

    include_docs: bool = True
    include_dependencies: bool = False
    exclude_patterns: tuple[str, ...] = ("*.pyc", "__pycache__/*", ".git/*")
    verify_on_build: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> PackPolicy:
        """Build a policy from one ``pack`` config section.

        Args:
            data: dict[str, Any]: The raw ``pack`` object from the config document.

        Returns:
        """
        base = cls()
        return replace(
            base,
            include_docs=bool(data.get("include_docs", base.include_docs)),
            include_dependencies=bool(data.get("include_dependencies", base.include_dependencies)),
            exclude_patterns=tuple(data.get("exclude_patterns", base.exclude_patterns)),
            verify_on_build=bool(data.get("verify_on_build", base.verify_on_build)),
        )


@dataclass(frozen=True, slots=True)
class DocsPolicy:
    """Which documentation rules ``opencode docs check`` enforces."""

    docstring_style: str = "google"
    require_docstrings_for_public: bool = True
    check_cli_commands: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> DocsPolicy:
        """Build a policy from one ``docs`` config section.

        Args:
            data: dict[str, Any]: The raw ``docs`` object from the config document.

        Returns:
        """
        base = cls()
        return replace(
            base,
            docstring_style=str(data.get("docstring_style", base.docstring_style)),
            require_docstrings_for_public=bool(
                data.get("require_docstrings_for_public", base.require_docstrings_for_public)
            ),
            check_cli_commands=bool(data.get("check_cli_commands", base.check_cli_commands)),
        )


@dataclass(frozen=True, slots=True)
class ReleasePolicy:
    """Release preconditions: reproducibility and prereleases.

    ``require_reproducibility`` controls whether a check this host cannot run
    still blocks the release. It defaults to true, so an unanswered question is
    never mistaken for a passed one; setting it to false is a deliberate decision
    to release without that evidence.

    ``allow_prerelease`` is opt-in because a prerelease published by accident
    looks like a supported version to every consumer who sees it.
    """

    require_reproducibility: bool = True
    allow_prerelease: bool = False

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> ReleasePolicy:
        """Build a policy from one ``release`` config section.

        Args:
            data: dict[str, Any]: The raw ``release`` object from the config document.

        Returns:
        """
        base = cls()
        return replace(
            base,
            require_reproducibility=bool(
                data.get("require_reproducibility", base.require_reproducibility)
            ),
            allow_prerelease=bool(data.get("allow_prerelease", base.allow_prerelease)),
        )


@dataclass(frozen=True, slots=True)
class Config:
    """Fully resolved configuration."""

    config_version: int = CONFIG_VERSION
    project_name: str = "opencode-toolkit"
    security_audit: SecurityAuditPolicy = field(default_factory=SecurityAuditPolicy)
    sync: SyncPolicy = field(default_factory=SyncPolicy)
    orchestrator: OrchestratorPolicy = field(default_factory=OrchestratorPolicy)
    pack: PackPolicy = field(default_factory=PackPolicy)
    docs: DocsPolicy = field(default_factory=DocsPolicy)
    release: ReleasePolicy = field(default_factory=ReleasePolicy)
    source_path: Path | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def exists(self) -> bool:
        """``True`` when the config came from a file rather than defaults."""
        return self.source_path is not None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view including effective values."""
        return {
            "config_version": self.config_version,
            "project_name": self.project_name,
            "source_path": str(self.source_path) if self.source_path else None,
            "security_audit": {
                "include_extensions": list(self.security_audit.include_extensions),
                "exclude_dirs": list(self.security_audit.exclude_dirs),
                "max_file_bytes": self.security_audit.max_file_bytes,
                "follow_symlinks": self.security_audit.follow_symlinks,
                "fail_on": list(self.security_audit.fail_on),
                "ignore_rule_ids": list(self.security_audit.ignore_rule_ids),
                "exclude_paths": list(self.security_audit.exclude_paths),
            },
            "sync": {
                "kdf_iterations": self.sync.kdf_iterations,
                "kdf_algorithm": self.sync.kdf_algorithm,
                "salt_bytes": self.sync.salt_bytes,
                "nonce_bytes": self.sync.nonce_bytes,
                "encrypt_by_default": self.sync.encrypt_by_default,
                "redact_env_files": self.sync.redact_env_files,
            },
            "orchestrator": {
                "max_parallel_agents": self.orchestrator.max_parallel_agents,
                "task_timeout_seconds": self.orchestrator.task_timeout_seconds,
                "max_task_retries": self.orchestrator.max_task_retries,
                "require_ownership": self.orchestrator.require_ownership,
                "checkpoint_on_transition": self.orchestrator.checkpoint_on_transition,
            },
            "pack": {
                "include_docs": self.pack.include_docs,
                "include_dependencies": self.pack.include_dependencies,
                "exclude_patterns": list(self.pack.exclude_patterns),
                "verify_on_build": self.pack.verify_on_build,
            },
            "docs": {
                "docstring_style": self.docs.docstring_style,
                "require_docstrings_for_public": self.docs.require_docstrings_for_public,
                "check_cli_commands": self.docs.check_cli_commands,
            },
            "release": {
                "require_reproducibility": self.release.require_reproducibility,
                "allow_prerelease": self.release.allow_prerelease,
            },
        }


def config_path_for(layout: Layout) -> Path:
    """Return the conventional config path inside *layout*'s workspace.

    Args:
        layout: Layout: Resolved layout whose ``workspace`` anchors the path.
            The path is derived whether or not a config file exists there.
    """
    return layout.workspace / CONFIG_RELPATH


def _validate_document(document: Any, *, source: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(document, dict):
        return [f"{source}: top level must be a JSON object"]

    unknown = sorted(set(document) - _KNOWN_TOP_LEVEL)
    if unknown:
        problems.append(
            f"{source}: unknown top-level key(s): {', '.join(unknown)}; "
            f"valid keys are {', '.join(sorted(_KNOWN_TOP_LEVEL))}"
        )

    version_value = document.get("config_version", CONFIG_VERSION)
    if not isinstance(version_value, int):
        problems.append(f"{source}: 'config_version' must be an integer")
    elif version_value != CONFIG_VERSION:
        problems.append(
            f"{source}: unsupported config_version {version_value}; this build understands {CONFIG_VERSION}"
        )

    project_name = document.get("project", "opencode-toolkit")
    if not isinstance(project_name, str) or not project_name.strip():
        problems.append(f"{source}: 'project' must be a non-empty string")

    for section, defaults in POLICY_DEFAULTS.items():
        payload = document.get(section)
        if payload is None:
            continue
        if not isinstance(payload, dict):
            problems.append(f"{source}: '{section}' must be a JSON object")
            continue
        unknown_section = sorted(set(payload) - set(defaults))
        if unknown_section:
            problems.append(
                f"{source}: unknown key(s) in '{section}': {', '.join(unknown_section)}; "
                f"valid keys are {', '.join(sorted(defaults))}"
            )
        for key, value in payload.items():
            expected = defaults.get(key)
            if expected is None:
                continue
            if isinstance(expected, bool):
                if not isinstance(value, bool):
                    problems.append(f"{source}: '{section}.{key}' must be true or false")
            elif isinstance(expected, int):
                if isinstance(value, bool) or not isinstance(value, int):
                    problems.append(f"{source}: '{section}.{key}' must be an integer")
                elif value <= 0:
                    problems.append(f"{source}: '{section}.{key}' must be greater than zero")
            elif isinstance(expected, str) and not isinstance(value, str):
                problems.append(f"{source}: '{section}.{key}' must be a string")
            elif isinstance(expected, list) and (
                not isinstance(value, list) or not all(isinstance(item, str) for item in value)
            ):
                problems.append(f"{source}: '{section}.{key}' must be a list of strings")

    problems.extend(_validate_semantics(document, source=source))
    return problems


def _validate_semantics(document: dict[str, Any], *, source: str) -> list[str]:
    problems: list[str] = []
    valid_severities = {"critical", "high", "medium", "low", "informational"}
    audit = document.get("security_audit")
    if isinstance(audit, dict):
        fail_on = audit.get("fail_on")
        if isinstance(fail_on, list):
            for severity in fail_on:
                if isinstance(severity, str) and severity.lower() not in valid_severities:
                    problems.append(
                        f"{source}: security_audit.fail_on contains unknown severity {severity!r}; "
                        f"valid values are {', '.join(sorted(valid_severities))}"
                    )

    sync = document.get("sync")
    if isinstance(sync, dict):
        algorithm = sync.get("kdf_algorithm", "pbkdf2-hmac-sha256")
        if isinstance(algorithm, str) and algorithm != "pbkdf2-hmac-sha256":
            problems.append(
                f"{source}: sync.kdf_algorithm {algorithm!r} is not supported; "
                "only 'pbkdf2-hmac-sha256' is implemented"
            )
        iterations = sync.get("kdf_iterations", 600_000)
        if (
            isinstance(iterations, int)
            and not isinstance(iterations, bool)
            and iterations < 100_000
        ):
            problems.append(
                f"{source}: sync.kdf_iterations {iterations} is below the enforced floor of 100000"
            )
        for key in ("salt_bytes", "nonce_bytes"):
            value = sync.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value < 16:
                problems.append(f"{source}: sync.{key} must be at least 16 bytes")

    orchestrator = document.get("orchestrator")
    if isinstance(orchestrator, dict):
        parallel = orchestrator.get("max_parallel_agents", 4)
        if isinstance(parallel, int) and not isinstance(parallel, bool) and parallel < 1:
            problems.append(f"{source}: orchestrator.max_parallel_agents must be at least 1")

    docs = document.get("docs")
    if isinstance(docs, dict):
        style = docs.get("docstring_style", "google")
        if isinstance(style, str) and style not in {"google", "numpy", "rst"}:
            problems.append(
                f"{source}: docs.docstring_style {style!r} is not supported; "
                "expected one of google, numpy, rst"
            )

    return problems


def load_config(layout: Layout, *, overrides: dict[str, Any] | None = None) -> Config:
    """Load, merge and validate configuration for *layout*.

    Raises :class:`ConfigurationError` listing **every** problem found, so a
    malformed file can be fixed in a single edit.

    Args:
        layout: Layout: Resolved layout naming the workspace whose
            conventional config path is read. A missing file is not an error;
            defaults are used instead.
        overrides: dict[str, Any] | None: Highest-precedence values, merged over
            the file. Sections present in both are merged key-by-key rather than
            replaced wholesale; every merged value is validated, so an override
            cannot bypass the schema checks.
    """
    path = config_path_for(layout)
    document: dict[str, Any] = {}
    used_path: Path | None = None

    if path.is_file():
        document = jsonio.read(path)
        used_path = path

    merged = dict(document)
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            section = dict(merged[key])
            section.update(value)
            merged[key] = section
        else:
            merged[key] = value

    problems = _validate_document(merged, source=str(path) if used_path else "<defaults>")
    if problems:
        raise ConfigurationError(
            f"invalid configuration ({len(problems)} problem(s))",
            details={"problems": problems, "path": str(path)},
            hint="fix every listed problem; the toolkit refuses to start on partial configuration",
        )

    return Config(
        config_version=int(merged.get("config_version", CONFIG_VERSION)),
        project_name=str(merged.get("project", "opencode-toolkit")),
        security_audit=SecurityAuditPolicy.from_mapping(merged.get("security_audit", {})),
        sync=SyncPolicy.from_mapping(merged.get("sync", {})),
        orchestrator=OrchestratorPolicy.from_mapping(merged.get("orchestrator", {})),
        pack=PackPolicy.from_mapping(merged.get("pack", {})),
        docs=DocsPolicy.from_mapping(merged.get("docs", {})),
        release=ReleasePolicy.from_mapping(merged.get("release", {})),
        source_path=used_path,
        raw=merged,
    )


def default_config_document() -> dict[str, Any]:
    """Return the documented default configuration document."""
    document: dict[str, Any] = {
        "config_version": CONFIG_VERSION,
        "project": "opencode-toolkit",
    }
    for section, defaults in POLICY_DEFAULTS.items():
        document[section] = jsonio.loads(jsonio.dump_compact(defaults))
    return document


def version_guard(config: Config, *, tool_version: Version | None = None) -> None:
    """Warn (loudly) when configuration targets a newer schema than this build.

    Args:
        config: Config: Configuration whose ``config_version`` is checked
            against this build's :data:`CONFIG_VERSION`.
        tool_version: Version | None: Version treated as "this build"; detected
            from ``pyproject.toml`` when ``None``. Accepted so tests can pin the
            comparison.
    """
    if tool_version is None:
        from opencode_toolkit.core.version import detect_version

        tool_version = detect_version()
    if config.config_version > CONFIG_VERSION:
        raise ConfigurationError(
            f"configuration schema v{config.config_version} is newer than this build "
            f"(understands v{CONFIG_VERSION}); upgrade opencode-toolkit",
            details={"config_version": config.config_version, "supported": CONFIG_VERSION},
        )
