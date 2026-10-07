"""Rule metadata and the pattern rule table.

Each :class:`Rule` carries everything a consumer needs: the identifiers, the
severity and confidence, and the prose that makes a finding actionable. Rules
are separated from matching logic so the catalogue can be audited, documented
and unit-tested on its own.

Pattern rules operate on individual source lines and use bounded, anchored
patterns. They deliberately avoid the "any long base64 blob is a secret" style
check that produces unusable noise; a pattern rule must have a recognisable
*context* (an assignment to a credential-shaped name, a known dangerous API) to
fire.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import Pattern
from typing import Final

from opencode_toolkit.security_audit.models import Confidence, Severity


@dataclass(frozen=True, slots=True)
class Rule:
    """Static metadata describing one check."""

    rule_id: str
    severity: Severity
    confidence: Confidence
    languages: tuple[str, ...]
    title: str
    description: str
    root_cause: str
    impact: str
    remediation: str
    references: tuple[str, ...] = ()
    secret_kind: str | None = None
    cwe: str | None = None


@dataclass(frozen=True, slots=True)
class PatternRule:
    """A rule plus the line patterns that trigger it."""

    rule: Rule
    patterns: tuple[Pattern[str], ...]
    #: When set, only lines matching this guard are considered (used to cut
    #: false positives such as ``verify=True`` matching ``verify=False``).
    negative_patterns: tuple[Pattern[str], ...] = field(default=())
    #: Secret rules capture the credential in group 1 so the value can be
    #: fingerprinted and redacted rather than reported.
    captures_secret: bool = False
    #: Group index holding the secret; defaults to 1.
    secret_group: int = 1


PY = "python"
JS = "javascript"
TS = "typescript"
GO = "go"
JS_LANGS = (JS, TS)


def _rule(
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    languages: tuple[str, ...],
    title: str,
    description: str,
    root_cause: str,
    impact: str,
    remediation: str,
    *,
    references: tuple[str, ...] = (),
    secret_kind: str | None = None,
    cwe: str | None = None,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        languages=languages,
        title=title,
        description=description,
        root_cause=root_cause,
        impact=impact,
        remediation=remediation,
        references=references,
        secret_kind=secret_kind,
        cwe=cwe,
    )


_RULES: list[Rule] = []


def register(rule: Rule) -> Rule:
    """Add *rule* to the global catalogue and return it.

    Args:
        rule: Rule: The rule to register; its ``rule_id`` must not already exist.
    """
    if any(existing.rule_id == rule.rule_id for existing in _RULES):
        raise ValueError(f"duplicate rule id: {rule.rule_id}")
    _RULES.append(rule)
    return rule


def all_rules() -> tuple[Rule, ...]:
    """Return every registered rule."""
    return tuple(_RULES)


def rule_by_id(rule_id: str) -> Rule | None:
    """Look up a rule by identifier.

    Args:
        rule_id: str: Identifier to find, e.g. ``OCSA-CRED-001``.
    """
    for rule in _RULES:
        if rule.rule_id == rule_id:
            return rule
    return None


def rules_for_language(language: str) -> tuple[Rule, ...]:
    """Return rules applicable to *language*.

    Args:
        language: str: Language to filter on, e.g. ``python`` or ``typescript``.
    """
    return tuple(rule for rule in _RULES if language in rule.languages)


# --------------------------------------------------------------------------
# Credential exposure
# --------------------------------------------------------------------------

_CREDENTIAL_NAME = (
    r"(?:aws_)?(?:secret|private|client|access|api|auth|signing)[_-]?(?:key|token|secret)"
)
# Describes credential *names*; it is a detection pattern, not a credential.
_GENERIC_CREDENTIAL_NAME = (
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
)
_ASSIGN = r"(?:=|:)"

register(
    _rule(
        "OCSA-CRED-001",
        Severity.CRITICAL,
        Confidence.HIGH,
        ("python",),
        "Hard-coded credential in source",
        "A credential-shaped name is assigned a literal string value.",
        "Credentials are committed to version control instead of being read from the environment or a secret manager.",
        "Anyone with repository read access obtains the credential; the value is also present in every clone and in git history after removal.",
        "Remove the literal, load the value from the environment or a secret manager, and rotate the exposed credential -- deletion alone does not undo exposure.",
        references=("CWE-798", "CWE-259"),
        secret_kind="credential",
        cwe="CWE-798",
    )
)

register(
    _rule(
        "OCSA-CRED-002",
        Severity.CRITICAL,
        Confidence.HIGH,
        ("javascript", "typescript"),
        "Hard-coded credential in source",
        "A credential-shaped property or variable is assigned a literal string value.",
        "The secret is bundled into the client artefact where it can be extracted by any consumer.",
        "The credential grants the holder whatever access the original principal had, indefinitely, until rotated.",
        "Move the value to a server-side environment variable or secret manager and rotate it; client-side code can never hold a durable secret.",
        references=("CWE-798",),
        secret_kind="credential",
        cwe="CWE-798",
    )
)

register(
    _rule(
        "OCSA-CRED-003",
        Severity.CRITICAL,
        Confidence.HIGH,
        ("go",),
        "Hard-coded credential in source",
        "A credential-shaped variable is assigned a string literal.",
        "Secrets are embedded in the binary at build time.",
        "The credential is recoverable from the shipped artefact and from the source history.",
        "Read the value from the environment or a secret manager at start-up and rotate the exposed credential.",
        references=("CWE-798",),
        secret_kind="credential",
        cwe="CWE-798",
    )
)

register(
    _rule(
        "OCSA-CRED-004",
        Severity.CRITICAL,
        Confidence.HIGH,
        ("python", "javascript", "typescript", "go"),
        "Private key material embedded in source",
        "A PEM-encoded private key header appears in a source file.",
        "Private key material was pasted into source instead of being loaded from protected storage.",
        "Anyone with repository access can impersonate the holder, sign artefacts, or decrypt traffic protected by that key.",
        "Remove the key, load keys from a secret manager or a mounted secret, and revoke and reissue the key pair.",
        references=("CWE-321",),
        secret_kind="private_key",
        cwe="CWE-321",
    )
)

register(
    _rule(
        "OCSA-CRED-005",
        Severity.HIGH,
        Confidence.HIGH,
        ("python", "javascript", "typescript", "go"),
        "Credential embedded in a connection string",
        "A URL or DSN literal carries an inline username:password pair.",
        "Database and broker endpoints are hard-coded together with their credentials.",
        "The connection string leaks the credential to anyone who reads logs, error messages, or the source.",
        "Build the DSN from separate host, user and password values read from the environment; never log the assembled string.",
        references=("CWE-798",),
        secret_kind="password",
        cwe="CWE-798",
    )
)

register(
    _rule(
        "OCSA-CRED-006",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("python", "javascript", "typescript", "go"),
        "Secret-bearing environment file present in the tree",
        "A dotenv-style file is tracked by the scanner and contains credential-shaped assignments.",
        "A .env file was created inside the repository instead of being provided per-environment and git-ignored.",
        "Environment secrets for one deployment leak into version control and every clone.",
        "Add .env to .gitignore, remove it from tracking, and rotate every value it contained.",
        references=("CWE-798",),
        secret_kind="credential",
        cwe="CWE-798",
    )
)

# --------------------------------------------------------------------------
# Code execution
# --------------------------------------------------------------------------

register(
    _rule(
        "OCSA-EXEC-001",
        Severity.CRITICAL,
        Confidence.HIGH,
        ("python",),
        "Dynamic code execution with eval()",
        "eval() is called on a runtime value.",
        "Untrusted or insufficiently validated data is interpreted as Python source.",
        "Arbitrary code execution in the process context, including filesystem and network access.",
        "Replace eval with ast.literal_eval for data, or a dispatch table for behaviour; if eval is unavoidable, restrict the namespace and validate the input first.",
        references=("CWE-95",),
        cwe="CWE-95",
    )
)

register(
    _rule(
        "OCSA-EXEC-002",
        Severity.CRITICAL,
        Confidence.HIGH,
        ("python",),
        "Dynamic code execution with exec()",
        "exec() is called on a runtime value.",
        "Untrusted data is executed as Python statements.",
        "Arbitrary code execution with the full privileges of the process.",
        "Remove exec(); use explicit function dispatch or a plugin loader that only accepts known entry points.",
        references=("CWE-95",),
        cwe="CWE-95",
    )
)

register(
    _rule(
        "OCSA-EXEC-003",
        Severity.CRITICAL,
        Confidence.HIGH,
        ("javascript", "typescript"),
        "Dynamic code execution with eval() or Function()",
        "eval() or new Function() compiles a string into executable code.",
        "Server or user supplied strings are compiled and run directly.",
        "Arbitrary JavaScript execution; in a browser this is equivalent to XSS, on a server it is server-side code execution.",
        "Remove the dynamic compilation. Use JSON.parse for data, an explicit map for dispatch, or a schema validator.",
        references=("CWE-95",),
        cwe="CWE-95",
    )
)

register(
    _rule(
        "OCSA-EXEC-004",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("python",),
        "Subprocess invoked through a shell",
        "A subprocess is launched with shell=True, so its arguments are parsed by the shell.",
        "Shell metacharacters in any interpolated value are interpreted by /bin/sh.",
        "Command injection: an attacker who controls any part of the command string can execute additional commands.",
        "Pass an argument list without shell=True, so the process is executed directly and no shell parsing occurs.",
        references=("CWE-78",),
        cwe="CWE-78",
    )
)

register(
    _rule(
        "OCSA-EXEC-005",
        Severity.HIGH,
        Confidence.HIGH,
        ("javascript", "typescript"),
        "Shell command assembled from interpolated values",
        "child_process.exec/execSync receives a template literal or concatenation.",
        "Untrusted input is concatenated into a shell command string.",
        "Command injection through shell metacharacters in the interpolated value.",
        "Use execFile/spawn with an argument array, never a concatenated shell string; validate values against an allow-list.",
        references=("CWE-78",),
        cwe="CWE-78",
    )
)

register(
    _rule(
        "OCSA-EXEC-006",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("go",),
        "Shell invocation via sh -c",
        "exec.Command is called with an explicit shell interpreter.",
        "Arguments are re-parsed by a shell instead of being passed as a vector.",
        "Command injection if any argument contains shell metacharacters.",
        "Call exec.Command directly with the binary and a slice of arguments; reserve sh -c for cases where the command string is fully trusted.",
        references=("CWE-78",),
        cwe="CWE-78",
    )
)

# --------------------------------------------------------------------------
# Injection: SQL, command, code
# --------------------------------------------------------------------------

register(
    _rule(
        "OCSA-INJ-001",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("python",),
        "SQL query built by string formatting",
        "A query is executed with a string built using an f-string, %, .format() or concatenation.",
        "User input is concatenated into SQL text rather than bound as a parameter.",
        "SQL injection: an attacker can alter the statement, read other rows, or modify data depending on driver privileges.",
        "Use parameter placeholders (cursor.execute('... WHERE id = ?', (value,))) and never interpolate values into query text.",
        references=("CWE-89",),
        cwe="CWE-89",
    )
)

register(
    _rule(
        "OCSA-INJ-002",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("javascript", "typescript"),
        "SQL query built by string concatenation",
        "A query string is assembled with + or a template literal and passed to a database driver.",
        "Query text is built from untrusted values instead of using bound parameters.",
        "SQL injection through any user-controlled fragment of the query.",
        "Use parameterised queries (? or $1 placeholders) with a driver that supports them.",
        references=("CWE-89",),
        cwe="CWE-89",
    )
)

register(
    _rule(
        "OCSA-INJ-003",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("go",),
        "SQL query built by string formatting",
        "A query is built with fmt.Sprintf and concatenated values.",
        "Values are interpolated into SQL text rather than passed as query arguments.",
        "SQL injection through any user-controlled fragment.",
        "Use db.Query(query, args...) with $1 placeholders and pass values as arguments.",
        references=("CWE-89",),
        cwe="CWE-89",
    )
)

register(
    _rule(
        "OCSA-INJ-004",
        Severity.MEDIUM,
        Confidence.HIGH,
        ("javascript", "typescript"),
        "Unescaped HTML sink",
        "A value is written into innerHTML, outerHTML, insertAdjacentHTML or document.write.",
        "Data is rendered as markup instead of text.",
        "Cross-site scripting: an attacker who controls the value can execute script in the victim's session.",
        "Assign to textContent, or sanitise with a maintained library before assigning to an HTML sink. Never mark untrusted content as trusted.",
        references=("CWE-79",),
        cwe="CWE-79",
    )
)

register(
    _rule(
        "OCSA-INJ-005",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("javascript", "typescript"),
        "React dangerouslySetInnerHTML without sanitisation",
        "dangerouslySetInnerHTML is used; the safety depends entirely on the caller sanitising the value.",
        "React's escaping is bypassed for the supplied HTML.",
        "XSS if the value ever contains user-controlled markup.",
        "Sanitise with DOMPurify before passing HTML, or render the value as text.",
        references=("CWE-79",),
        cwe="CWE-79",
    )
)

register(
    _rule(
        "OCSA-INJ-006",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("go",),
        "Unescaped template.HTML conversion",
        "A string is converted with template.HTML, marking it as pre-trusted markup.",
        "The Go template auto-escaping guarantee is deliberately disabled for that value.",
        "XSS when the string contains attacker-controlled markup.",
        "Return the value as a plain string so template escaping applies, or sanitise it with a vetted library.",
        references=("CWE-79",),
        cwe="CWE-79",
    )
)

register(
    _rule(
        "OCSA-INJ-007",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("python",),
        "XML parsed without disabling entity expansion safeguards",
        "An XML parser is constructed with resolve_entities enabled, or defusedxml is bypassed via lxml defaults.",
        "The parser will expand entity references, which is the basis of XXE and billion-laughs attacks.",
        "Local file disclosure, SSRF, or memory exhaustion depending on the parser configuration.",
        "Use defusedxml, or construct the parser with resolve_entities=False, no_network=True, and forbid DOCTYPE declarations.",
        references=("CWE-611", "CWE-776"),
        cwe="CWE-611",
    )
)

# --------------------------------------------------------------------------
# Path traversal and file handling
# --------------------------------------------------------------------------

register(
    _rule(
        "OCSA-PATH-001",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("python",),
        "Archive extracted without member validation",
        "extractall() is called on a tar/zip object without filtering members.",
        "Archive member names are trusted, so ../ sequences escape the destination directory.",
        "Arbitrary file overwrite outside the extraction target (zip-slip / tar-slip).",
        "Reject members whose resolved path is outside the destination, reject absolute paths and symlinks, and use tarfile's filter= argument where available.",
        references=("CWE-22",),
        cwe="CWE-22",
    )
)

register(
    _rule(
        "OCSA-PATH-002",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("python",),
        "Path constructed from an unvalidated value",
        "A filesystem path is built by joining a value that did not come from a literal.",
        "The path is not resolved and checked to be inside the intended root.",
        "Path traversal: ../ sequences let a caller read or write files outside the intended directory.",
        "Resolve the candidate and verify it is a child of the intended root before opening, and reject absolute paths and symlinks.",
        references=("CWE-22",),
        cwe="CWE-22",
    )
)

register(
    _rule(
        "OCSA-PATH-003",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("go",),
        "Filesystem path built from an unvalidated value",
        "filepath.Join is applied to a value that did not come from a literal.",
        "The resulting path is not verified to remain inside the intended root.",
        "Path traversal allowing reads or writes outside the intended directory.",
        "After joining, call filepath.Clean and check the result with filepath.IsLocal or a prefix check against the allowed root.",
        references=("CWE-22",),
        cwe="CWE-22",
    )
)

register(
    _rule(
        "OCSA-FILE-001",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("python",),
        "Insecure temporary file creation",
        "mktemp() or a predictable name is used for a temporary file.",
        "The file name is predictable or the creation is not exclusive, creating a race window.",
        "Symlink attacks and race conditions allow an attacker to read or replace the file contents.",
        "Use tempfile.NamedTemporaryFile(delete=False) or mkstemp, which create the file exclusively with safe permissions.",
        references=("CWE-377",),
        cwe="CWE-377",
    )
)

register(
    _rule(
        "OCSA-FILE-002",
        Severity.MEDIUM,
        Confidence.HIGH,
        ("python", "javascript", "typescript", "go"),
        "Overly permissive file mode",
        "A file or directory is created with mode 0777 (or its platform equivalent).",
        "World-writable permissions are applied, usually by copying a umask-independent literal mode.",
        "Any local user can read or modify the file, which matters most for credentials and sockets.",
        "Use the narrowest mode that works: 0600 for secrets, 0644 for public data, 0755 for executables; rely on the process umask for directories.",
        references=("CWE-732",),
        cwe="CWE-732",
    )
)

# --------------------------------------------------------------------------
# Transport security
# --------------------------------------------------------------------------

register(
    _rule(
        "OCSA-TLS-001",
        Severity.HIGH,
        Confidence.HIGH,
        ("python", "javascript", "typescript"),
        "TLS certificate verification disabled",
        "Verification is explicitly turned off for an outbound connection.",
        "The client accepts any certificate, removing authentication from the TLS handshake.",
        "Trivial machine-in-the-middle interception of all traffic on that connection.",
        "Remove the override. If a private CA is required, install the CA bundle and keep verification enabled.",
        references=("CWE-295",),
        cwe="CWE-295",
    )
)

register(
    _rule(
        "OCSA-TLS-002",
        Severity.HIGH,
        Confidence.HIGH,
        ("go",),
        "TLS certificate verification disabled",
        "tls.Config is built with InsecureSkipVerify set to true.",
        "The Go TLS client is configured to skip certificate and hostname verification.",
        "Machine-in-the-middle interception of traffic on that connection.",
        "Set InsecureSkipVerify to false and configure a custom CA pool or the system roots as appropriate.",
        references=("CWE-295",),
        cwe="CWE-295",
    )
)

register(
    _rule(
        "OCSA-TLS-003",
        Severity.HIGH,
        Confidence.HIGH,
        ("javascript", "typescript"),
        "Node TLS verification disabled process-wide",
        "NODE_TLS_REJECT_UNAUTHORIZED is assigned the string '0'.",
        "Verification is disabled for every TLS connection made by the process, not just one call.",
        "All outbound TLS traffic can be intercepted; the effect is global and hard to spot in review.",
        "Remove the assignment and install the correct CA certificate in the trust store instead.",
        references=("CWE-295",),
        cwe="CWE-295",
    )
)

register(
    _rule(
        "OCSA-TLS-004",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("go",),
        "Obsolete TLS version permitted",
        "tls.Config declares MinVersion below TLS 1.2.",
        "Deprecated protocol versions remain negotiable.",
        "Downgrade attacks against clients that still accept older TLS versions.",
        "Set MinVersion to at least tls.VersionTLS12, preferably VersionTLS13.",
        references=("CWE-326",),
        cwe="CWE-326",
    )
)

# --------------------------------------------------------------------------
# Cryptography
# --------------------------------------------------------------------------

register(
    _rule(
        "OCSA-CRYPTO-001",
        Severity.MEDIUM,
        Confidence.HIGH,
        ("python", "javascript", "typescript", "go"),
        "Broken hash algorithm used",
        "MD5 or SHA-1 is selected for a security purpose.",
        "Both algorithms have practical collision attacks and must not be used for integrity or signatures.",
        "Forged or colliding artefacts; where used for signatures, an attacker can produce two inputs with the same digest.",
        "Use SHA-256 or stronger. Keep MD5 only for non-security checksums of non-adversarial data, and say so in a comment if retained.",
        references=("CWE-327", "CWE-328"),
        cwe="CWE-327",
    )
)

register(
    _rule(
        "OCSA-CRYPTO-002",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("python", "javascript", "typescript", "go"),
        "Non-cryptographic randomness used for a security value",
        "The general-purpose random module generates a token, key, nonce or salt.",
        "The generator is predictable and not designed for security use.",
        "Attackers who observe a few outputs can reconstruct the generator state and predict future secrets.",
        "Use the secrets module (secrets.token_*, secrets.choice), crypto.randomBytes, or crypto/rand.",
        references=("CWE-338",),
        cwe="CWE-338",
    )
)

register(
    _rule(
        "OCSA-CRYPTO-003",
        Severity.HIGH,
        Confidence.HIGH,
        ("python",),
        "Password hashing below recommended work factor",
        "hashlib.pbkdf2_hmac is called with fewer than 100000 iterations.",
        "The work factor makes offline brute-force of a stolen hash far cheaper than intended.",
        "Stolen password hashes become practical to crack, recovering user passwords reused elsewhere.",
        "Use at least 600000 iterations for PBKDF2-HMAC-SHA256, or switch to a memory-hard KDF (argon2, scrypt).",
        references=("CWE-916",),
        cwe="CWE-916",
    )
)

register(
    _rule(
        "OCSA-CRYPTO-004",
        Severity.HIGH,
        Confidence.HIGH,
        ("python",),
        "Unsafe deserialization with pickle or shelve",
        "pickle.load(s), pickle.loads or shelve.open is used on data that may not be trusted.",
        "Pickle streams execute arbitrary reduction callables during deserialization.",
        "Remote code execution in the process context with no further conditions.",
        "Use JSON for data interchange. If arbitrary Python objects are required, sign the pickle with hmac and verify before loading.",
        references=("CWE-502",),
        cwe="CWE-502",
    )
)

register(
    _rule(
        "OCSA-CRYPTO-005",
        Severity.HIGH,
        Confidence.HIGH,
        ("javascript", "typescript"),
        "Unsafe deserialization of a function-containing object",
        "node-serialize or yaml.load with the unsafe schema is used on external input.",
        "The format can encode executable functions or arbitrary types.",
        "Remote code execution when the input is attacker controlled.",
        "Use JSON.parse, or yaml.load with the 'safe' schema in js-yaml; reject function-bearing payloads.",
        references=("CWE-502",),
        cwe="CWE-502",
    )
)

register(
    _rule(
        "OCSA-CRYPTO-006",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("python",),
        "YAML loaded without a safe loader",
        "yaml.load is called without SafeLoader (or yaml.unsafe_load is used explicitly).",
        "The default loader can construct arbitrary Python objects from the document.",
        "Arbitrary code execution or object injection through a crafted YAML document.",
        "Use yaml.safe_load, or yaml.load(..., Loader=yaml.SafeLoader).",
        references=("CWE-502",),
        cwe="CWE-502",
    )
)

# --------------------------------------------------------------------------
# Authentication and authorization
# --------------------------------------------------------------------------

register(
    _rule(
        "OCSA-AUTH-001",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("javascript", "typescript"),
        "Token verified with algorithms disabled or not verified at all",
        "jwt.verify is called with algorithms:['none'] or the token is only decoded.",
        "Signature verification is skipped, so the token content is attacker controlled.",
        "Authentication bypass: anyone can mint a token claiming any identity or role.",
        "Pin the expected algorithm explicitly (algorithms:['RS256']) and always verify the signature and the expiry.",
        references=("CWE-347", "CWE-287"),
        cwe="CWE-347",
    )
)

register(
    _rule(
        "OCSA-AUTH-002",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("python",),
        "Authorization comparison using == on a secret or signature",
        "A secret, HMAC or signature is compared with the equality operator.",
        "String comparison short-circuits on the first differing byte, leaking timing information.",
        "The comparison timing reveals the correct value byte by byte, enabling online recovery of the secret.",
        "Use hmac.compare_digest, or secrets.compare_digest, for constant-time comparison.",
        references=("CWE-208",),
        cwe="CWE-208",
    )
)

register(
    _rule(
        "OCSA-AUTH-003",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("javascript", "typescript", "go"),
        "Wildcard CORS combined with credentials",
        "Access-Control-Allow-Origin is set to '*' while credentials are allowed, or the origin is reflected without validation.",
        "The policy does not restrict which origins may send authenticated requests.",
        "Any website can make authenticated cross-origin requests to the API and read the responses.",
        "Allow-list the exact trusted origins and echo only a matched origin; never combine a wildcard with credentials.",
        references=("CWE-942",),
        cwe="CWE-942",
    )
)

# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------

register(
    _rule(
        "OCSA-VALID-001",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("python",),
        "Validation performed with assert",
        "assert is used to enforce a security-relevant precondition.",
        "Assertions are removed when Python runs with -O, so the check silently disappears in optimised deployments.",
        "The invalid condition that the assertion was meant to block is no longer detected.",
        "Raise an explicit exception instead; keep asserts for internal invariants and test assertions only.",
        references=("CWE-617",),
        cwe="CWE-617",
    )
)

register(
    _rule(
        "OCSA-VALID-002",
        Severity.LOW,
        Confidence.HIGH,
        ("python",),
        "Exception handler swallows all errors",
        "A bare except or a broad except without re-raising catches programming errors as well as expected failures.",
        "Failure modes are hidden, so callers continue with invalid state.",
        "Security checks inside the try block are silently bypassed when they raise.",
        "Catch the specific exception you handle, and either re-raise or record the failure explicitly.",
        references=("CWE-390",),
        cwe="CWE-390",
    )
)

register(
    _rule(
        "OCSA-VALID-003",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("javascript", "typescript"),
        "Prototype pollution sink",
        "__proto__ or the constructor prototype is assigned from a runtime value.",
        "An attacker-supplied key is written into the object prototype chain.",
        "Inherited properties can be injected globally, changing behaviour of unrelated objects and bypassing checks.",
        "Reject __proto__, constructor and prototype keys from untrusted input, and create objects with Object.create(null) where appropriate.",
        references=("CWE-1321",),
        cwe="CWE-1321",
    )
)

register(
    _rule(
        "OCSA-VALID-004",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        ("javascript", "typescript", "python", "go"),
        "Regular expression with nested unbounded quantifiers",
        "A pattern contains a quantified group that itself contains a quantifier, a classic catastrophic-backtracking shape.",
        "The engine explores exponentially many ways to match a failing input.",
        "Denial of service: a short crafted input consumes CPU for minutes or hours (ReDoS).",
        "Rewrite the pattern to avoid nested quantifiers, make the inner part non-repeating, or bound the input length before matching.",
        references=("CWE-1333",),
        cwe="CWE-1333",
    )
)

# --------------------------------------------------------------------------
# Supply chain and hygiene
# --------------------------------------------------------------------------

register(
    _rule(
        "OCSA-SUPPLY-001",
        Severity.HIGH,
        Confidence.HIGH,
        ("javascript", "typescript"),
        "Package fetched from an insecure registry",
        "A URL uses plain http:// against a package registry or tarball host.",
        "Dependencies are downloaded over an unauthenticated channel.",
        "A network attacker can substitute an arbitrary package, achieving code execution at install time.",
        "Use https:// exclusively; for registries, configure a trusted registry explicitly.",
        references=("CWE-829",),
        cwe="CWE-829",
    )
)

register(
    _rule(
        "OCSA-SUPPLY-002",
        Severity.HIGH,
        Confidence.MEDIUM,
        ("javascript", "typescript"),
        "Dynamic module resolution from a runtime value",
        "require(...) or import(...) is called with a non-literal specifier.",
        "The resolved module is chosen at runtime from data.",
        "If the value can be influenced, a malicious or unexpected module is loaded and executed.",
        "Require an explicit, statically declared module and validate the value against an allow-list map.",
        references=("CWE-829",),
        cwe="CWE-829",
    )
)

register(
    _rule(
        "OCSA-SUPPLY-003",
        Severity.MEDIUM,
        Confidence.HIGH,
        ("python", "javascript", "typescript", "go"),
        "Unverified third-party download at runtime",
        "A URL is fetched with a command that performs the download as a side effect.",
        "The fetched content is executed or installed without an integrity check.",
        "Remote code execution if the download endpoint is compromised or the connection is intercepted.",
        "Verify a published checksum or signature before executing downloaded content, and pin the version.",
        references=("CWE-494",),
        cwe="CWE-494",
    )
)

register(
    _rule(
        "OCSA-SUPPLY-005",
        Severity.INFORMATIONAL,
        Confidence.MEDIUM,
        ("python", "javascript", "typescript", "go"),
        "Security suppression annotation",
        "A nosec or noqa annotation suppresses a security or lint rule at this location.",
        "A developer-suppression marker disables a check that would otherwise fire.",
        "Not a vulnerability by itself, but it removes the only signal the check produced and must be reviewed deliberately.",
        "Require a written justification next to the annotation and review it during code review; treat new suppressions as findings.",
        references=("CWE-16",),
        cwe="CWE-16",
    )
)


# --------------------------------------------------------------------------
# Pattern rule table
# --------------------------------------------------------------------------


def _rid(rule_id: str) -> Rule:
    """Fetch a just-registered rule by id, failing loudly if the table drifts."""
    rule = rule_by_id(rule_id)
    if rule is None:  # pragma: no cover - guards against table edits
        raise LookupError(f"pattern table references unknown rule id: {rule_id}")
    return rule


def _compile(*patterns: str) -> tuple[Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


# Anchored credential assignment: name, assignment, quote, value, quote.
_PY_SECRET_ASSIGN = (
    rf"^\s*(?:{_CREDENTIAL_NAME}|{_GENERIC_CREDENTIAL_NAME})"
    rf"\s*{_ASSIGN}\s*(?P<q>['\"])(?P<v>[^'\"\s]{{8,}})(?P=q)\s*$"
)
_JS_SECRET_ASSIGN = (
    rf"(?:^|[^.\w])(?:const|let|var)?\s*(?:{_CREDENTIAL_NAME}|{_GENERIC_CREDENTIAL_NAME})\b"
    rf"\s*[:=]\s*(?P<q>['\"])(?P<v>[^'\"$\s]{{8,}})(?P=q)"
)
_GO_SECRET_ASSIGN = (
    rf"(?:{_CREDENTIAL_NAME}|{_GENERIC_CREDENTIAL_NAME})\s*(?::=|=)\s*\"(?P<v>[^\"\s]{{8,}})\""
)

PATTERN_RULES: Final[tuple[PatternRule, ...]] = (
    PatternRule(
        rule=_rid("OCSA-CRED-001"),
        patterns=_compile(_PY_SECRET_ASSIGN),
        captures_secret=True,
    ),
    PatternRule(
        rule=_rid("OCSA-CRED-002"),
        patterns=_compile(_JS_SECRET_ASSIGN),
        captures_secret=True,
    ),
    PatternRule(
        rule=_rid("OCSA-CRED-003"),
        patterns=_compile(_GO_SECRET_ASSIGN),
        captures_secret=True,
    ),
    PatternRule(
        rule=_rid("OCSA-CRED-004"),
        patterns=_compile(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----"),
    ),
    PatternRule(
        rule=_rid("OCSA-CRED-005"),
        patterns=_compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|ldap)://[^\s:@/]+:"
            r"(?P<v>[^\s@'\"]{3,})@",
            r"\bhttps?://[^\s:/@]+:(?P<v>[^\s@'\"]{3,})@",
        ),
        captures_secret=True,
    ),
    PatternRule(
        rule=_rid("OCSA-EXEC-004"),
        patterns=_compile(r"\bshell\s*=\s*True\b"),
    ),
    PatternRule(
        rule=_rid("OCSA-EXEC-005"),
        patterns=_compile(
            r"\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*[`\"'][^`\"']*\$\{",
            r"\bexecSync\s*\(\s*\w+\s*\+",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-EXEC-006"),
        patterns=_compile(
            r"exec\.Command(?:Context)?\s*\(\s*\"(?:/bin/)?(?:ba|z|k)?sh\"\s*,\s*\"-c\""
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-INJ-002"),
        patterns=_compile(
            r"(?:query|execute)\s*\(\s*[`\"'][^`\"']*(?:SELECT|INSERT|UPDATE|DELETE)[^`\"']*"
            r"(?:\+\s*\w+|\$\{[^}]+\}\s*[+`]|[+`]\s*\$\{[^}]+\})",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-INJ-003"),
        patterns=_compile(
            r"fmt\.Sprintf\s*\(\s*\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*%[sv]",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-INJ-004"),
        patterns=_compile(
            r"\.innerHTML\s*(?:\+)?=",
            r"\.outerHTML\s*(?:\+)?=",
            r"\.insertAdjacentHTML\s*\(",
            r"\bdocument\.write(?:ln)?\s*\(",
        ),
        negative_patterns=_compile(r"=\s*[\"'`]\s*[\"'`]\s*;"),
    ),
    PatternRule(
        rule=_rid("OCSA-INJ-005"),
        patterns=_compile(r"dangerouslySetInnerHTML"),
    ),
    PatternRule(
        rule=_rid("OCSA-INJ-006"),
        patterns=_compile(r"template\.HTML\s*\("),
    ),
    PatternRule(
        rule=_rid("OCSA-PATH-001"),
        patterns=_compile(r"\.extractall\s*\(|extractall\s*\("),
        negative_patterns=_compile(r"(?:filter|members)\s*="),
    ),
    PatternRule(
        rule=_rid("OCSA-FILE-001"),
        patterns=_compile(r"\btempfile\.mktemp\s*\(", r"\bmktemp\s*\("),
    ),
    PatternRule(
        rule=_rid("OCSA-FILE-002"),
        patterns=_compile(
            r"(?:chmod|Chmod)\s*\([^,)]*,\s*0?777\b",
            r"(?<![&|])\b0o?777\b",
        ),
        negative_patterns=_compile(
            r"&\s*0o?777",
            # Rule-catalogue prose describing the mode, not code applying it.
            r"mode\s+0?777\b",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-TLS-001"),
        patterns=_compile(
            r"\bverify\s*=\s*False\b",
            r"\brejectUnauthorized\s*:\s*false\b",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*[\"']?0[\"']?",
            r"_create_unverified_context\s*\(",
            r"ssl\._create_unverified_context\s*\(",
        ),
        negative_patterns=_compile(r"^\s*#"),
    ),
    PatternRule(
        rule=_rid("OCSA-TLS-002"),
        patterns=_compile(r"InsecureSkipVerify\s*:\s*true\b"),
    ),
    PatternRule(
        rule=_rid("OCSA-TLS-003"),
        patterns=_compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']0[\"']"),
    ),
    PatternRule(
        rule=_rid("OCSA-TLS-004"),
        patterns=_compile(
            r"MinVersion\s*:\s*(?:tls\.VersionSSL30|tls\.VersionTLS10|tls\.VersionTLS11)\b",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-CRYPTO-001"),
        patterns=_compile(
            r"\bhashlib\.(?:md5|sha1)\s*\(",
            r"createHash\s*\(\s*[\"'](?:md5|sha1)[\"']",
            r"crypto\.createHash\(\s*['\"](?:md5|sha1)['\"]",
            r"\bmd5\.(?:New|Sum)\s*\(",
            r"\bsha1\.(?:New|Sum)\s*\(",
        ),
        negative_patterns=_compile(r"^\s*#"),
    ),
    PatternRule(
        rule=_rid("OCSA-CRYPTO-002"),
        patterns=_compile(
            r"\bMath\.random\s*\(\s*\)[^;\n]*(?:token|secret|key|salt|nonce|otp|nonce)",
            r"\brand\.(?:Intn|Int|Float64)\s*\([^)]*\)[^\n]*(?:Token|Secret|Key|Nonce|OTP)",
        ),
        negative_patterns=_compile(r"^\s*#"),
    ),
    PatternRule(
        rule=_rid("OCSA-CRYPTO-003"),
        patterns=_compile(r"pbkdf2_hmac\s*\([^)]*,\s*\d{2,6}\s*\)"),
    ),
    PatternRule(
        rule=_rid("OCSA-CRYPTO-004"),
        patterns=_compile(
            r"\bpickle\.loads?\s*\(",
            r"\bpickle\.Unpickler\s*\(",
            r"\bshelve\.open\s*\(",
            r"\bdill\.loads?\s*\(",
        ),
        negative_patterns=_compile(r"^\s*#"),
    ),
    PatternRule(
        rule=_rid("OCSA-CRYPTO-005"),
        patterns=_compile(
            r"\bnode-serialize\b",
            r"\byaml\.load\s*\((?![^)]*safe)",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-CRYPTO-006"),
        patterns=_compile(
            r"\byaml\.load\s*\((?![^)]*(?:SafeLoader|safe_load))",
            r"\byaml\.unsafe_load\s*\(",
            r"\byaml\.full_load\s*\(",
        ),
        negative_patterns=_compile(r"^\s*#"),
    ),
    PatternRule(
        rule=_rid("OCSA-AUTH-001"),
        patterns=_compile(
            r"algorithms\s*:\s*\[\s*[\"']none[\"']\s*\]",
            r"jwt\.decode\s*\((?![^)]*verify)",
            r"verify\s*:\s*false\s*[,}]",
        ),
        negative_patterns=_compile(r"^\s*//"),
    ),
    PatternRule(
        rule=_rid("OCSA-AUTH-003"),
        patterns=_compile(
            r"Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*[\"']",
            r"AccessControlAllowOrigin\s*:\s*\"\*\"",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-VALID-003"),
        patterns=_compile(
            r"\[\s*[\"']__proto__[\"']\s*\]\s*=",
            r"\.?__proto__\s*=\s*",
            r"Object\.assign\s*\(\s*\w+\.constructor\.prototype",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-SUPPLY-001"),
        patterns=_compile(
            r"\"registry\"\s*:\s*\"http://",
            r"https?://[^\s\"']+\.tgz[\"']?",
            r"[\"']url[\"']\s*:\s*[\"']http://",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-SUPPLY-002"),
        patterns=_compile(
            r"require\s*\(\s*(?![\"'])",
            r"\bimport\s*\(\s*(?![\"'])",
        ),
        negative_patterns=_compile(r"require\s*\(\s*path\.|\bimport\s*\(\s*specifier"),
    ),
    PatternRule(
        rule=_rid("OCSA-SUPPLY-003"),
        patterns=_compile(
            r"\bcurl\b[^\n|]*\|\s*(?:ba)?sh\b",
            r"\bwget\b[^\n|]*\|\s*(?:ba)?sh\b",
            r"\biwr\b[^\n|]*\|\s*iex\b",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-EXEC-003"),
        patterns=_compile(
            r"(?:^|[^.\w])eval\s*\(",
            r"new\s+Function\s*\(",
        ),
        negative_patterns=_compile(r"^\s*(?://|/\*|\*)"),
    ),
    PatternRule(
        rule=_rid("OCSA-INJ-001"),
        patterns=_compile(
            r"(?:execute|executemany|raw)\s*\(\s*(?:f|rf|fr)[\"']"
            r"[^\"']*\{[^}]+\}[\"']",
            r"(?:execute|executemany)\s*\([^\"']*[\"'][^\"']*\+[^\"']*",
            r"(?:execute|executemany)\s*\([^\"']*%\s*\(",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-PATH-003"),
        patterns=_compile(
            r"filepath\.(?:Join|Open|OpenFile|ReadFile|WriteFile|Create)\s*\(\s*\w+\s*,",
        ),
    ),
    PatternRule(
        rule=_rid("OCSA-SUPPLY-005"),
        patterns=_compile(r"#\s*(?:nosec|noqa(?::\s*S\d+)?|bandit:skip|lint:ignore)\b"),
    ),
)
