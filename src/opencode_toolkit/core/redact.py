"""Secret redaction.

Reports must be shareable, so discovered secret *values* are never emitted. The
audit rules classify each match, attach a ``secret_kind`` label, and this module
replaces the value with a stable fingerprint that is still useful for
de-duplicating the same credential across a codebase:

    AWS_SECRET_ACCESS_KEY = "AKIA...7f3c"   ->  value: "***redacted:aws_secret_access_key:sha256:ab12cd34***"

The fingerprint is a truncated HMAC-free SHA-256 of the *value*, which is not a
recoverable secret and does not allow dictionary attacks on short secrets any
more than a plain hash would -- it exists purely for correlation. When
``include_fingerprint`` is disabled a constant marker is emitted instead.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

REDACTED: Final = "***redacted***"
_FINGERPRINT_LEN: Final = 8

#: Values that are structural rather than secret must never be redacted, or the
#: report becomes useless. Matched case-insensitively against the *whole* value.
_ALLOW_VALUES: Final[frozenset[str]] = frozenset(
    {
        "",
        "true",
        "false",
        "null",
        "none",
        "nil",
        "undefined",
        "changeme",
        "todo",
        "xxx",
        "placeholder",
        "example",
        "dummy",
        "test",
        "your_token_here",
        "<redacted>",
    }
)

#: Values that are shaped like placeholders even though they are not in
#: ``_ALLOW_VALUES`` verbatim. ``your_password_here``, ``REPLACE_ME`` and
#: ``example-token`` all name a slot rather than hold a credential, and flagging
#: them trains people to ignore the rule.
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:"
    r"(?:your|my|the|some|insert|replace)[_-]?"
    r"(?:[a-z0-9]+[_-])*"
    r"(?:token|password|passwd|secret|key|credential|apikey|api[_-]?key)"
    r"(?:[_-]?(?:here|value|goes[_-]?here|placeholder))?"
    r"|x{3,}|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}"
    r"|(?:replace|insert|change)[_-]?me"
    r")$"
)

#: Environment-variable names that must be masked when a ``.env`` style file is
#: reported as a whole (used by the file-level rule, not value-level rules).
ENV_NAME_PATTERN: Final = re.compile(
    r"^[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*$"
)


def is_allowlisted(value: str) -> bool:
    """Return ``True`` when *value* is a placeholder rather than a credential.

    Surrounding whitespace is ignored and the comparison covers both the fixed
    allowlist in :data:`_ALLOW_VALUES` and placeholder-shaped values such as
    ``your_token_here`` or ``REPLACE_ME``.

    Args:
        value: str: Candidate secret value, as written in the source.
    """
    candidate = value.strip()
    if candidate.lower() in _ALLOW_VALUES:
        return True
    return bool(_PLACEHOLDER_RE.match(candidate))


def fingerprint(value: str, *, length: int = _FINGERPRINT_LEN) -> str:
    """Return a short, non-reversible correlation token for *value*.

    Args:
        value: str: Secret value to fingerprint; encoded leniently, so
            undecodable input still yields a stable digest.
        length: int: Number of leading hex characters to keep. The digest is
            truncated to at most 64 characters, its full length.
    """
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
    return digest[:length]


def redact_value(
    value: str,
    kind: str = "secret",
    *,
    keep_fingerprint: bool = True,
    max_length: int = 8,
) -> str:
    """Return a report-safe representation of *value*.

    Placeholder values pass through unchanged so authors can see that a slot
    exists without the report flagging an empty assignment.

    Args:
        value: str: Secret value to render safely.
        kind: str: Label describing the credential class, e.g. ``"token"`` or
            ``"password"``; included in the output so a report can distinguish
            two fingerprints of different kinds.
        keep_fingerprint: bool: When ``False``, emit the constant
            :data:`REDACTED` marker with no correlation token.
        max_length: int: Number of hex characters in the fingerprint.

    Returns:
        str: *value* unchanged when allowlisted, otherwise a
            ``***redacted:<kind>:sha256:<digest>***`` string.
    """
    if is_allowlisted(value):
        return value
    if not keep_fingerprint:
        return REDACTED
    return f"{REDACTED[:-3]}:{kind}:sha256:{fingerprint(value, length=max_length)}***"


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    """Controls how aggressively values are masked in user-visible output."""

    keep_fingerprint: bool = True
    max_value_length: int = 8

    def mask(self, value: str, kind: str = "secret") -> str:
        """Mask a single value according to this policy.

        Args:
            value: str: Secret value to render safely.
            kind: str: Label for the credential class, forwarded to
                :func:`redact_value`.
        """
        return redact_value(value, kind, keep_fingerprint=self.keep_fingerprint)

    def clamp(self, text: str) -> str:
        """Clamp an untrusted snippet to a bounded length before display.

        Args:
            text: str: Untrusted snippet; returned unchanged when it already
                fits, otherwise truncated and suffixed with ``"..."``.

        The limit is ``max(16, max_value_length * 4)`` characters.
        """
        limit = max(16, self.max_value_length * 4)
        if len(text) <= limit:
            return text
        return text[:limit] + "..."


DEFAULT_POLICY: Final = RedactionPolicy()


def redact_text(text: str, *, policy: RedactionPolicy = DEFAULT_POLICY) -> str:
    """Redact anything that looks like an inline credential assignment.

    Used as a last-pass guard before a snippet of user code is placed in a
    report, catching credentials the value-level rules did not classify.

    Three shapes are masked: credential assignments (``API_KEY = "..."``), bare
    ``Bearer``/``Basic`` authorisation values, and passwords embedded in URLs.
    Matches whose value is allowlisted are left alone.

    Args:
        text: str: Free-form text to scan; only the matched values are replaced,
            all surrounding content is preserved verbatim.
        policy: RedactionPolicy: Masking policy, defaulting to
            :data:`DEFAULT_POLICY`.
    """
    # Names that always denote a credential. `aws_access_key_id` and
    # `authorization` are present because an audit report is exactly the place
    # those two turn up; omitting them leaked a value while testing this module.
    assignment = re.compile(
        # The leading guard is a negative lookbehind rather than `\b`, because a
        # credential name is usually a *suffix*: `DATABASE_PASSWORD`, `GITHUB_TOKEN`
        # and `X_API_KEY` all fail a `\b` check, since `_` is a word character.
        r"(?i)(?<![A-Za-z0-9])("
        r"aws_secret_access_key|aws_access_key_id|secret_access_key|access_key_id|"
        r"api[_-]?key|apikey|access[_-]?token|auth[_-]?token|authorization|"
        r"client[_-]?secret|private[_-]?key|password|passwd|pwd|session[_-]?(?:id|cookie)|cookie|"
        # Bare names. `TOKEN = "..."` and `secret = "..."` are the two most
        # common assignment shapes in real code and were previously missed.
        r"token|secret|bearer[_-]?token|github[_-]?token|slack[_-]?token|npm[_-]?token"
        r")\b\s*[:=]\s*[\"']?"
        # An optional `Bearer `/`Basic ` prefix is part of the credential, not part
        # of the name. Without consuming it here the value group would capture
        # the six-character word "Bearer" and leave the token itself exposed.
        r"(?:(?:bearer|basic)\s+)?"
        r"([^\s\"',;]{6,})[\"']?"
    )
    # A bare `Bearer <token>` with no assignment, which is how an Authorization
    # header value most often appears in a copied snippet.
    bearer = re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})")
    # An inline password inside a URL or DSN. The *variable name* is often
    # innocuous (`DATABASE_URL`), so only the credential pattern can catch this.
    dsn = re.compile(r'(?i)\b([a-z][a-z0-9+.-]*)://([^\s:@/"\']+):([^\s@"\']{3,})@')

    def _replace(match: re.Match[str]) -> str:
        name, value = match.group(1), match.group(2)
        if is_allowlisted(value):
            return match.group(0)
        masked = policy.mask(value, kind=_kind_for(name))
        return match.group(0).replace(value, masked)

    def _replace_bearer(match: re.Match[str]) -> str:
        scheme, value = match.group(1), match.group(2)
        return f"{scheme} {policy.mask(value, kind='token')}"

    def _replace_dsn(match: re.Match[str]) -> str:
        scheme, user, password = match.group(1), match.group(2), match.group(3)
        return f"{scheme}://{user}:{policy.mask(password, kind='password')}@"

    text = assignment.sub(_replace, text)
    text = bearer.sub(_replace_bearer, text)
    return dsn.sub(_replace_dsn, text)


def _kind_for(name: str) -> str:
    """Map a credential-bearing identifier to the label shown in a report."""
    lowered = name.lower().replace("-", "_")
    if "private" in lowered:
        return "private_key"
    if lowered == "pwd" or "password" in lowered or "passwd" in lowered:
        return "password"
    if (
        "token" in lowered
        or "bearer" in lowered
        or "authorization" in lowered
        or "session" in lowered
    ):
        return "token"
    if "cookie" in lowered:
        return "cookie"
    if "secret" in lowered:
        return "client_secret"
    if "access_key" in lowered:
        return "access_key_id"
    return "api_key"


def redact_env_assignments(
    lines: list[str], *, policy: RedactionPolicy = DEFAULT_POLICY
) -> list[str]:
    """Mask the values of credential-shaped environment assignments.

    Blank lines, comments and assignments whose name does not match
    :data:`ENV_NAME_PATTERN` are passed through unchanged.

    Args:
        lines: list[str]: Lines of a ``.env`` style file, each returned as-is or
            as a masked ``NAME=value`` string.
        policy: RedactionPolicy: Masking policy, defaulting to
            :data:`DEFAULT_POLICY`.
    """
    output: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            output.append(line)
            continue
        name, sep, value = stripped.partition("=")
        if sep and ENV_NAME_PATTERN.match(name.strip()):
            output.append(
                f"{name.strip()}={policy.mask(value.strip(), kind=_kind_for(name.strip()))}"
            )
        else:
            output.append(line)
    return output
