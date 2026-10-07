"""Structural analysis of Python source.

Regexes cannot distinguish ``eval(cfg_value)`` from ``eval("2 + 2")``, nor
``verify=False`` passed deliberately from one left over from a debug session.
Walking the AST lets the scanner make those distinctions, which is why the
findings from this module carry ``HIGH`` confidence where the pattern table has
to settle for ``MEDIUM``.

The analyser is deliberately total: a file that fails to parse produces a
scan-level error entry rather than an exception, because a syntax error in one
file must not abort a repository-wide audit.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

from opencode_toolkit.core.redact import fingerprint, is_allowlisted, redact_text
from opencode_toolkit.security_audit.models import Confidence, Finding, Severity
from opencode_toolkit.security_audit.rules import rule_by_id

#: Names that strongly suggest a value is a credential. Substring matching is
#: used deliberately but with a curated vocabulary: a word as generic as "auth"
#: is excluded because it matches identifiers such as ``CODE_AUTHOR`` and
#: ``ROLE_AUTHORS``, which produce pure noise.
_SECRET_NAME_HINTS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "access_key",
        "accesskey",
        "secret_key",
        "private_key",
        "client_secret",
        "credentials",
        "passphrase",
    }
)

#: Name suffixes that denote a *reference* to something rather than the secret
#: itself: an environment variable name, a header name, a file suffix. Assigning
#: a string literal to one of these is never a credential leak.
_REFERENCE_NAME_SUFFIXES: Final[tuple[str, ...]] = (
    "_ENV",
    "_ENVIRON",
    "_VARIABLE",
    "_HEADER",
    "_NAME",
    "_NAMES",
    "_PATH",
    "_PATHS",
    "_FILE",
    "_SUFFIX",
    "_SUFFIXES",
    "_PREFIX",
    "_EXT",
    "_SCHEME",
    "_KEY_NAME",
    "_ALGORITHM",
    "_ITERATIONS",
)

#: A value shaped like an identifier or an environment variable name, for
#: example ``"HUGGINGFACE_TOKEN"``. A string literal that is itself a *name* is
#: metadata, not a secret, however credential-shaped the variable holding it is.
_REFERENCE_VALUE_RE: Final = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")

#: Path helpers that normalise a caller-supplied path.
_PATH_NORMALISERS: Final[frozenset[str]] = frozenset(
    {
        "os.path.join",
        "os.path.abspath",
        "os.path.realpath",
        "posixpath.join",
        "ntpath.join",
        "pathlib.Path",
    }
)

#: Call names whose return value is a security token when the surrounding name
#: or function is token-shaped. Kept separate from the token-shaped *names* above
#: so `random.random()` used for jitter is not reported.
_RANDOM_CALLS: Final[frozenset[str]] = frozenset(
    {"random", "randint", "randrange", "choice", "choices", "getrandbits", "shuffle", "sample"}
)

#: Names that indicate a value is a secret, a token or a unique identifier.
_TOKEN_NAME_HINTS: Final[frozenset[str]] = frozenset(
    {"token", "nonce", "otp", "salt", "secret", "apikey", "api_key", "session_id", "request_id"}
)

#: Names that make an http/https URL unambiguous when combined with a password.
_URL_NAME_HINTS: Final[frozenset[str]] = frozenset(
    {"url", "dsn", "uri", "database_url", "connection"}
)


def _names_from_target(node: ast.expr) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.Tuple | ast.List):
        collected: list[str] = []
        for element in node.elts:
            collected.extend(_names_from_target(element))
        return collected
    if isinstance(node, ast.Starred):
        return _names_from_target(node.value)
    return []


def _dotted(node: ast.expr) -> str:
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _is_constant_str(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_reference_name(name: str) -> bool:
    """Return ``True`` when *name* denotes a reference, not a secret value."""
    return name.upper().endswith(_REFERENCE_NAME_SUFFIXES)


def _is_reference_value(value: str) -> bool:
    """Return ``True`` when *value* is itself an identifier-shaped name."""
    return bool(_REFERENCE_VALUE_RE.match(value))


def _secret_confident(name: str) -> bool:
    """Return ``True`` when a literal assigned to *name* is worth reporting."""
    lowered = name.lower()
    if any(hint in lowered for hint in _SECRET_NAME_HINTS):
        return not _is_reference_name(name)
    # A short bare word such as `token` or `password` with no underscore.
    return lowered in _SECRET_NAME_HINTS and not _is_reference_name(name)


def _call_name(node: ast.Call) -> str:
    """Return the dotted name of the called function, e.g. ``os.path.join``."""
    return _dotted(node.func)


@dataclass(slots=True)
class _LineLookup:
    """Source lines with a bounded, redacted excerpt helper."""

    lines: list[str]

    def excerpt(self, lineno: int, *, context: int = 0) -> tuple[int, str]:
        index = lineno - 1
        start = max(0, index - context)
        end = min(len(self.lines), index + 1 + context)
        body = "\n".join(self.lines[start:end])
        return index + 1, redact_text(body.strip())


class _PythonAstAuditor(ast.NodeVisitor):
    """Collects structural findings from one module."""

    def __init__(self, file_label: str, lines: list[str], language: str = "python") -> None:
        self.file = file_label
        self.language = language
        self.lookup = _LineLookup(lines)
        self.findings: list[Finding] = []
        #: Statements of the innermost enclosing function/module, used to decide
        #: whether a path was already validated for containment.
        self._scope: list[ast.stmt] = []
        #: Name of the innermost enclosing function, used by name-shaped rules.
        self._function_name: str = ""

    # -- helpers ----------------------------------------------------------
    def _emit(
        self,
        rule_id: str,
        node: ast.AST,
        *,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        description_suffix: str = "",
        detail: str = "",
        secret: str | None = None,
    ) -> None:
        rule = rule_by_id(rule_id)
        if rule is None:  # pragma: no cover - table drift guard
            return
        lineno = getattr(node, "lineno", 0)
        column = getattr(node, "col_offset", 0)
        _line, excerpt = self.lookup.excerpt(lineno)
        description = (
            rule.description
            if not description_suffix
            else f"{rule.description} {description_suffix}"
        )
        if detail:
            description = f"{description} ({detail})"
        self.findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=severity or rule.severity,
                confidence=confidence or rule.confidence,
                file=self.file,
                line=lineno,
                column=column,
                code_location=excerpt,
                description=description,
                root_cause=rule.root_cause,
                impact=rule.impact,
                remediation=rule.remediation,
                language=self.language,
                references=rule.references,
                secret_kind=rule.secret_kind,
                fingerprint=fingerprint(secret) if secret else None,
            )
        )

    # -- assignments ------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        value = node.value
        for name in _names_from_target(node.targets[0]) if node.targets else []:
            if _is_token_name(name) and _contains_random_call(value):
                self._emit(
                    "OCSA-CRYPTO-002",
                    node,
                    detail=f"{name!r} is derived from the non-cryptographic random module",
                )
        literal = _string_literal(value)
        if literal is not None and not is_allowlisted(literal):
            for target in node.targets:
                for name in _names_from_target(target):
                    if self._is_credential_literal(name, literal):
                        self._emit(
                            "OCSA-CRED-001",
                            node,
                            confidence=Confidence.HIGH,
                            detail=f"assigned to {name!r}",
                            secret=literal,
                        )
                    elif "@" in literal and (
                        name.lower().endswith(("url", "dsn", "uri")) or "://" in literal
                    ):
                        self._check_url_credential(node, name, literal)
        # Annotated assignment form: name: type = "literal"
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        # `return str(random.randint(...))` from a function called make_token is
        # the common shape, so both the enclosing name and the returned
        # expression have to be inspected -- neither alone is decisive.
        if (
            self._function_name
            and _is_token_name(self._function_name)
            and _contains_random_call(node.value)
        ):
            self._emit(
                "OCSA-CRYPTO-002",
                node,
                detail=f"{self._function_name}() returns a value from the random module",
            )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        value = node.value
        literal = _string_literal(value)
        if literal is not None and not is_allowlisted(literal):
            for name in _names_from_target(node.target):
                if self._is_credential_literal(name, literal):
                    self._emit(
                        "OCSA-CRED-001",
                        node,
                        detail=f"assigned to {name!r}",
                        secret=literal,
                    )
        self.generic_visit(node)

    @staticmethod
    def _is_credential_literal(name: str, value: str) -> bool:
        """Decide whether a string literal assigned to *name* is a credential.

        Four conditions must all hold. Each exists because its absence produced a
        false positive in this repository's own source:

        * the name is credential-shaped and not a *reference* name
        * the value is long enough to be a real credential
        * the value is not an identifier-shaped name (``"HUGGINGFACE_TOKEN"``)
        * the value is not already a known placeholder
        """
        if not _secret_confident(name):
            return False
        if len(value) < 8 or is_allowlisted(value):
            return False
        return not _is_reference_value(value)

    def _check_url_credential(self, node: ast.AST, name: str, value: str) -> None:
        if not _secret_confident(name) and name.lower() not in _URL_NAME_HINTS:
            return
        scheme, _, rest = value.partition("://")
        if not rest:
            return
        authority = rest.split("/", 1)[0]
        if ":" not in authority:
            return
        userinfo = authority.rsplit("@", 1)[0] if "@" in authority else authority
        if ":" not in userinfo:
            return
        _, _, password = userinfo.partition(":")
        if password and not is_allowlisted(password):
            self._emit(
                "OCSA-CRED-005",
                node,
                detail=f"{scheme} URL assigned to {name!r}",
                secret=password,
            )

    # -- calls ------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        tail = name.rsplit(".", 1)[-1]
        args = node.args
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        if tail == "eval":
            self._emit_dynamic_exec(node, "OCSA-EXEC-001", name)
        elif tail == "exec":
            self._emit_dynamic_exec(node, "OCSA-EXEC-002", name)

        if self._is_pickle(name):
            self._emit("OCSA-CRYPTO-004", node, detail=f"call to {name}()")
        elif _dotted(node.func).rsplit(".", 1)[0] in {"yaml", "ruamel.yaml"}:
            self._emit_yaml_load(node)

        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                self._emit("OCSA-EXEC-004", node, detail=f"call to {name}(shell=True)")

        if name in {"os.system", "os.popen"}:
            self._emit("OCSA-EXEC-004", node, confidence=Confidence.HIGH, detail=f"{name}()")

        if name == "tempfile.mktemp":
            self._emit("OCSA-FILE-001", node, detail="tempfile.mktemp()")

        if name in {"hashlib.md5", "hashlib.sha1"}:
            self._emit("OCSA-CRYPTO-001", node, detail=f"{name}()")

        if name == "hashlib.pbkdf2_hmac":
            iterations = (
                self._int_literal(args[3])
                if len(args) > 3
                else self._int_literal(keywords.get("iterations"))
            )
            if iterations is not None and iterations < 100_000:
                self._emit("OCSA-CRYPTO-003", node, detail=f"{iterations} iterations")

        if tail in {"get", "post", "put", "delete", "patch", "head", "request"} and self._is_http(
            name
        ):
            self._check_verify_flag(node, name, keywords)

        if tail == "urlopen" or (tail == "Request" and self._is_http(name)):
            self._check_urlopen_context(node)

        if tail in {"extractall", "extract"} and self._is_archive(name):
            self._check_archive_member_validation(node, name, keywords)

        if tail in {"parse", "fromstring", "XMLParser", "XMLPullParser"} and self._is_xml(name):
            self._check_xml_parser(node, name, keywords)

        if name in _PATH_NORMALISERS:
            self._check_path_join(node, args, name)

        self.generic_visit(node)

    # -- statement level --------------------------------------------------
    def visit_Assert(self, node: ast.Assert) -> None:
        if not _is_type_narrowing_assert(node.test):
            self._emit(
                "OCSA-VALID-001",
                node,
                detail="assert is removed under python -O",
            )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        bare = node.type is None
        broad = isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
        swallows = (
            not bare
            and not any(isinstance(stmt, ast.Raise) for stmt in node.body)
            and not _reassigns_and_returns(node)
        )
        if bare or (broad and swallows):
            self._emit(
                "OCSA-VALID-002",
                node,
                detail="bare except" if bare else f"broad except {getattr(node.type, 'id', '')}",
            )
        self.generic_visit(node)

    # -- classification helpers ------------------------------------------
    @staticmethod
    def _is_pickle(name: str) -> bool:
        return name.startswith(("pickle.", "cPickle.", "dill.", "shelve.")) or name in {
            "pickle.load",
            "pickle.loads",
            "shelve.open",
        }

    @staticmethod
    def _is_http(name: str) -> bool:
        return name.split(".")[0] in {"requests", "httpx", "aiohttp"} or name.startswith("urllib")

    @staticmethod
    def _is_archive(name: str) -> bool:
        return name.split(".")[0] in {"tarfile", "zipfile"}

    @staticmethod
    def _is_xml(name: str) -> bool:
        return name.split(".")[0] in {"lxml", "defusedxml", "xml", "xmltodict"}

    def _emit_dynamic_exec(self, node: ast.Call, rule_id: str, name: str) -> None:
        # A pure literal argument is not attacker controlled; reporting it is
        # noise. Anything else -- a name, a call result, a join -- is reported.
        if args_literal(node.args):
            return
        self._emit(
            rule_id,
            node,
            confidence=Confidence.HIGH,
            detail=f"call to {name}() with a runtime argument",
        )

    def _emit_yaml_load(self, node: ast.Call) -> None:
        callee = _dotted(node.func)
        if callee.endswith(("safe_load", "full_load_", "load_all")):
            return
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        loader = keywords.get("Loader")
        if loader is not None:
            if _dotted(loader) not in {"yaml.SafeLoader", "yaml.CSafeLoader"}:
                self._emit("OCSA-CRYPTO-006", node, detail=f"unsafe loader {_dotted(loader)}")
            return
        self._emit("OCSA-CRYPTO-006", node, detail=f"{callee}() without SafeLoader")

    def _check_verify_flag(self, node: ast.Call, name: str, keywords: dict[str, ast.expr]) -> None:
        verify = keywords.get("verify")
        if verify is not None and isinstance(verify, ast.Constant) and verify.value is False:
            self._emit(
                "OCSA-TLS-001", node, confidence=Confidence.HIGH, detail=f"{name}(verify=False)"
            )
        cert = keywords.get("cert_reqs")
        if cert is not None and _dotted(cert).rsplit(".", 1)[-1] == "CERT_NONE":
            self._emit("OCSA-TLS-001", node, detail=f"{name}(cert_reqs=CERT_NONE)")

    def _check_urlopen_context(self, node: ast.Call) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and _dotted(child.func).endswith(
                "_create_unverified_context"
            ):
                self._emit("OCSA-TLS-001", node, detail="unverified SSL context passed to urllib")

    def _check_archive_member_validation(
        self, node: ast.Call, name: str, keywords: dict[str, ast.expr]
    ) -> None:
        if _dotted(node.func).endswith("extractall"):
            if "filter" in keywords:
                return
            if "members" in keywords:
                return
            self._emit("OCSA-PATH-001", node, detail=f"{name}() without member filtering")
            return
        for keyword in node.keywords:
            if keyword.arg == "path":
                self._emit(
                    "OCSA-PATH-001", node, detail=f"{name}(path=...) without member filtering"
                )

    def _check_xml_parser(self, node: ast.Call, name: str, keywords: dict[str, ast.expr]) -> None:
        resolve = keywords.get("resolve_entities")
        if resolve is None:
            return
        if isinstance(resolve, ast.Constant) and resolve.value is True:
            self._emit("OCSA-INJ-007", node, detail=f"{name}(resolve_entities=True)")

    def _check_path_join(self, node: ast.Call, args: list[ast.expr], name: str) -> None:
        """Flag a path built from a non-literal with no containment check.

        A join is only reported when at least one argument is a runtime value
        *and* the enclosing function performs no containment validation. That
        second condition is what keeps the rule usable: the overwhelmingly
        common correct pattern resolves the path and then compares it against
        the allowed root, and reporting that as vulnerable would bury the real
        findings.
        """
        if len(args) < 2 or args_literal(args):
            return
        if not self._scope_has_containment_check():
            self._emit(
                "OCSA-PATH-002",
                node,
                detail=f"{name}() builds a path from a runtime value with no containment check in scope",
            )

    def _scope_has_containment_check(self) -> bool:
        """Return ``True`` when the current scope validates path containment."""
        if not self._scope:
            return False
        for statement in self._scope:
            for child in ast.walk(statement):
                if not isinstance(child, ast.Call):
                    continue
                callee = _dotted(child.func)
                tail = callee.rsplit(".", 1)[-1]
                if tail in {"commonpath", "commonprefix", "relative_to", "is_relative_to"}:
                    return True
                if tail in {"resolve", "realpath", "abspath"}:
                    return True
                if tail == "startswith" and child.args:
                    # root containment expressed as `path.startswith(root)`
                    return True
                if tail in {"startswith", "startswith_path"} and callee.startswith("pathlib"):
                    return True
                if isinstance(child.func, ast.Attribute) and child.func.attr in {"is_relative_to"}:
                    return True
                if _dotted(child.func) in {"os.path.isabs"} and child.args:
                    return True
        return False

    def _enter_scope(self, node: ast.stmt) -> None:
        previous = self._function_name
        self._function_name = (
            node.name if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) else ""
        )
        self._scope.append(node)
        self.generic_visit(node)
        self._scope.pop()
        self._function_name = previous

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_scope(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            if isinstance(op, ast.Eq) and self._compare_is_secret(node.left, comparator):
                self._emit(
                    "OCSA-AUTH-002",
                    node,
                    detail="== comparison of a secret-shaped value is not constant time",
                )
                break
        self.generic_visit(node)

    @staticmethod
    def _compare_is_secret(left: ast.expr, right: ast.expr) -> bool:
        for side in (left, right):
            if isinstance(side, ast.Attribute) and _secret_confident(side.attr):
                return True
            if isinstance(side, ast.Call) and _dotted(side).rsplit(".", 1)[-1] in {
                "digest",
                "hexdigest",
                "encode",
            }:
                return True
        return False

    @staticmethod
    def _int_literal(node: ast.expr | None) -> int | None:
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
        ):
            return node.value
        return None


def _is_type_narrowing_assert(test: ast.expr) -> bool:
    """Return ``True`` for ``assert x is not None`` / ``assert isinstance(...)``.

    These exist to narrow a type for a type checker and carry no runtime intent,
    so reporting them as a validation weakness is noise. A conjunction of them --
    the usual ``assert a is not None and b is not None`` after a validation pass
    -- is narrowing too, and is treated as such only when *every* operand is.

    Every other assert -- a comparison, a truthiness check -- is reported,
    because those are the ones people use as runtime guards and then forget
    disappear under ``python -O``.
    """
    if isinstance(test, ast.BoolOp):
        return all(_is_type_narrowing_assert(value) for value in test.values)
    if isinstance(test, ast.Compare):
        # Any comparison other than `x is None` / `x is not None` is a runtime
        # guard rather than type narrowing, and is reported.
        return (
            len(test.ops) == 1
            and isinstance(test.ops[0], ast.Is | ast.IsNot)
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value is None
        )
    if isinstance(test, ast.Call):
        target = _dotted(test.func)
        return target in {"isinstance", "issubclass", "callable", "hasattr"}
    return False


def _is_token_name(name: str) -> bool:
    """Return ``True`` when *name* denotes a secret, token or unique id."""
    lowered = name.lower().lstrip("_")
    return any(hint in lowered for hint in _TOKEN_NAME_HINTS)


def _contains_random_call(node: ast.expr | None) -> bool:
    """Return ``True`` when *node* calls ``random.<anything>``."""
    if node is None:
        return False
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            callee = _dotted(child.func)
            if callee.startswith("random.") and callee.rsplit(".", 1)[-1] in _RANDOM_CALLS:
                return True
    return False


def _string_literal(node: ast.expr | None) -> str | None:
    """Return the text of *node* when it is a non-empty string constant.

    Returning the value rather than a boolean keeps the ``isinstance`` checks in
    one place, so callers never re-test the type before using the string.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
        return node.value
    return None


def args_literal(args: list[ast.expr]) -> bool:
    """Return ``True`` when every argument is a literal constant.

    Args:
        args: list[ast.expr]: Positional, keyword and ``*args`` arguments to test.
    """
    if not args:
        return True
    return all(isinstance(arg, ast.Constant) for arg in args)


def _reassigns_and_returns(node: ast.ExceptHandler) -> bool:
    for statement in node.body:
        if isinstance(statement, ast.Return | ast.Raise):
            return True
        if isinstance(statement, ast.Assign):
            continue
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            continue
        return False
    return False


def iter_python_findings(file_label: str, source: str) -> Iterator[Finding]:
    """Yield structural findings for one Python source file.

    A file that cannot be parsed yields nothing; the caller records the parse
    error at scan level so a single broken file does not abort the audit.

    Args:
        file_label: str: Path shown on every finding this source produces.
        source: str: Full Python source text to parse and walk.
    """
    lines = source.splitlines()
    auditor = _PythonAstAuditor(file_label, lines)
    try:
        tree = ast.parse(source, filename=file_label)
    except SyntaxError:
        return
    except ValueError:
        # Source containing null bytes; the engine records it as skipped.
        return
    auditor.visit(tree)
    yield from auditor.findings


def python_parse_error(source: str) -> str | None:
    """Return a short parse-error description, or ``None`` when the file parses.

    Args:
        source: str: Full Python source text to check.
    """
    try:
        ast.parse(source)
    except SyntaxError as exc:
        return f"line {exc.lineno}: {exc.msg}"
    except ValueError as exc:
        return str(exc)
    return None
