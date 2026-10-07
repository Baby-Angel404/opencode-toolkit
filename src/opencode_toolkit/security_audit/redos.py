"""Catastrophic-backtracking (ReDoS) detection for regular expressions.

``OCSA-VALID-004`` needs real analysis, not a keyword match: a nested unbounded
quantifier is only dangerous when the inner group can match the same characters
the outer quantifier is scanning. This module extracts regex literals from
source, strips escaping and character-class boundaries, then applies a
conservative structural test:

    a quantified group whose body contains an unbounded quantifier, and whose
    body is not anchored to a character disjoint from the outer repetition

Patterns that fail the test are *not* reported. The rule is confidence ``MEDIUM``
for exactly that reason, and ``opencode docs check`` documents the limitation.

The check is per-language and deliberately small: Python raw strings, JS/TS
regex literals, and Go backtick strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from opencode_toolkit.core.redact import redact_text
from opencode_toolkit.security_audit.models import Confidence, Finding, Severity
from opencode_toolkit.security_audit.rules import rule_by_id

RULE_ID: Final = "OCSA-VALID-004"

#: Literals that hold a regex. Order matters only for readability.
_LITERAL_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    # Group 1 is ``pre``, group 2 is the quote delimiter; the lookahead in
    # ``pattern`` must therefore reference group 2, not group 1. The optional
    # string-prefix group accepts r/b/u/f and their common combinations.
    "python": re.compile(
        r"(?P<pre>re\.compile\(\s*|re\.(?:match|search|fullmatch|sub|split|findall|finditer)\(\s*)"
        r"(?:[rRbBuUfF]{0,2})(?P<q>'''|\"\"\"|'|\")(?P<pattern>(?:\\.|(?!\2).)*?)(?P=q)",
        re.DOTALL,
    ),
    "javascript": re.compile(
        r"(?P<q>/)(?P<pattern>(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\n])+)/(?P<flags>[gimsuyd]*)",
    ),
    "go": re.compile(r"(?P<q>`)(?P<pattern>[^`]*)`"),
}

#: A quantifier: *, +, {n,}, {n,m}. `{n}` alone is not unbounded.
_QUANTIFIER: Final = re.compile(r"[*+]|\{\d+,\d*\}")

#: Structural group. Every group-introducer form is consumed explicitly --
#: capturing, non-capturing, Python/PCRE named ``(?P<n>...)``, named
#: ``(?<n>...)``, lookaround, inline-flag and comment groups -- because an
#: introducer that is not consumed leaks ``?P<name>`` into the body, where its
#: letters look like literal separators and flip the verdict.
#:
#: The body pattern also understands bracket expressions. Without that,
#: ``(?P<p>[^)]*)`` is mis-parsed: the ``[^()]*`` body stops at the parenthesis
#: *inside the character class*, so the class body is read as an unbounded
#: quantifier followed by one -- a false positive on a class that is not nested.
#:
#: Assembled from parts so the nesting stays auditable:
#:   ``\(``                        literal open parenthesis
#:   ``(?:\? ... )?``              optional ``?`` plus group introducer
#:   ``(?: A | B | C | D )``        the introducer forms
#:   ``(_BODY)``                    the group body, class-aware
#:   ``\)``                        literal close parenthesis
_BODY = r"(?:\[(?:\\.|[^\]\\])*\]|[^()\\])*"
_GROUP: Final = re.compile(
    r"\("
    r"(?:\?"
    r"(?:"
    r"P?<[^()]*?>"  # (?P<name>...)
    r"|[<>!][^()]*?>"  # (?<=...) (?<!...) (?<name>...)
    r"|[=:<!][a-zA-Z]*"  # (?:...) (?=...) (?!...) (?i) ...
    r"|#[^()]*?\)"  # (?#comment...)
    r")"
    r")?"
    rf"({_BODY})"
    r"\)"
)

_ANCHOR_OR_CLASS: Final = re.compile(r"[\^$]|\\b|\\B|\\Z|\\z|\\A")

#: Characters that are regex syntax rather than literal text. Everything else
#: appearing in a group body counts as a separator.
#: Characters that are regex syntax rather than literal text. Everything else
#: appearing in a group body counts as a separator. Whitespace is deliberately
#: excluded: outside verbose mode a space in a pattern is a literal that anchors
#: partitions.
_METACHARS: Final = frozenset("\x01^$|?*+()[]{}.")

#: Escape sequences naming a character class or a position rather than a literal
#: character. Any other escaped character is itself a literal and is kept by
#: :func:`_strip_escapes`, which is what makes a pattern like ``(\..+)``
#: recognisable as the safe separator idiom rather than a bare repeated class.
_CLASS_ESCAPES: Final = frozenset("dDwWsSbBAzZGnNpP")

#: Stand-in for an escaped metacharacter such as a backslash-dot or a
#: backslash-paren. It is a
#: literal for the separator analysis but is not a delimiter, so the group
#: parser cannot be confused by an escaped parenthesis.
_ESCAPED_LITERAL: Final = "\x02"


@dataclass(frozen=True, slots=True)
class RedexMatch:
    """One suspicious regex literal."""

    line: int
    column: int
    pattern: str
    reason: str


def _strip_escapes(text: str) -> str:
    r"""Normalise a pattern for structural analysis.

    Character classes collapse to a single neutral marker and class/position
    escapes are dropped. An escaped literal keeps its literal nature -- that is
    exactly what makes ``(\.\d+)`` the safe separator idiom -- but an escaped
    *metacharacter* is emitted as :data:`_ESCAPED_LITERAL` rather than as the raw
    character, so that ``\(`` does not read as a group delimiter.
    """
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            following = text[index + 1] if index + 1 < len(text) else ""
            if following in _CLASS_ESCAPES:
                # Emit the same neutral marker a bracket class produces rather
                # than dropping the escape. Deleting it left the quantifier that
                # follows with no atom, so `[A-Z]\w*` read as a repeated class
                # and any `\s*` after the group read as the group being repeated.
                out.append("\x01")
                index += 2
                continue
            if following in _METACHARS:
                if following:
                    out.append(_ESCAPED_LITERAL)
                index += 2
                continue
            if following:
                out.append(following)
            index += 2
            continue
        if char == "[":
            # Collapse the class to a single neutral marker: class membership
            # intersections are the hardest case and are handled by the
            # disjointness guard below.
            out.append("\x01")
            while index < len(text) and text[index] != "]":
                index += 2 if text[index] == "\\" else 1
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _body_is_disjoint(body: str) -> bool:
    """Return ``True`` when the group body cannot overlap its own repetition.

    The structural test, and the empirical evidence behind it (each pattern below
    was timed against a 30-character non-matching input with ``re.match``):

    ===================================  =============  ==========
    pattern                              verdict        measured
    ===================================  =============  ==========
    ``(a+)+``                            catastrophic  > 3 s
    ``(\\w*)*``                           catastrophic  > 3 s
    ``(\\w+\\s?)*``                        catastrophic  > 3 s
    ``(\\d+)+``                           catastrophic  > 3 s
    ``(x+x+)+``                           catastrophic  0.48 s
    ``([a-z0-9]+(?:-[a-z0-9]+)*)``       safe          0.004 ms
    ``(?:[A-Z][A-Za-z]*)*``              safe          0.002 ms
    ``(\\*{0,2}\\w+)``                      safe          0.002 ms
    ===================================  =============  ==========

    A body containing a **mandatory literal character** -- one that is not itself
    quantified -- is treated as safe. That is the separator idiom: a required
    non-class character forces every partition of the input to line up on the
    same separator, so the number of ways to match stays linear. A body made only
    of character classes and shorthands lets the inner and outer repetitions
    split the same run of characters arbitrarily, which is exponential.

    The "mandatory" qualifier is what separates ``(-\\w+)`` (safe: the ``-``
    anchors every partition) from ``(a+)`` (catastrophic: the ``a`` is the token
    being repeated, so it anchors nothing).

    Known limitation: ``(\\w{0,2}\\w+)`` is a bounded pattern that this test
    still reports, because its effective range is only discovered by collapsing
    adjacent quantifiers. It is reported at ``MEDIUM`` confidence for that
    reason; see ``docs/components/live-docs.md``.
    """
    if not body:
        return True
    if _ANCHOR_OR_CLASS.search(body):
        return True
    if not _QUANTIFIER.search(body):
        return True
    return bool(_mandatory_literals(body))


def _mandatory_literals(body: str) -> set[str]:
    """Return the literal characters in *body* that are not themselves quantified.

    ``(-\\w+)`` contributes ``-``; ``(a+)`` and ``(\\w+)`` contribute nothing,
    because in those the literal is the atom the quantifier applies to.
    """
    literals: set[str] = set()
    for index, char in enumerate(body):
        if char == "\x01" or char in _METACHARS:
            continue
        following = body[index + 1 :]
        if following[:1] in {"*", "+"} or (
            following.startswith("{") and _QUANTIFIER.match(following)
        ):
            continue
        literals.add(char)
    return literals


def _has_unbounded_quantifier(body: str) -> bool:
    """Return ``True`` when *body* contains ``*``, ``+`` or ``{n,}``."""
    return bool(_QUANTIFIER.search(_strip_escapes(body)))


def is_vulnerable(pattern: str) -> tuple[bool, str]:
    """Return ``(vulnerable, reason)`` for a single regex pattern.

    This reports a pattern *shape* -- a nested unbounded quantifier over a
    non-disjoint body -- not a measured slowdown; no input is ever timed here.

    Args:
        pattern: str: The regex source to judge, escaping already intact.
    """
    stripped = _strip_escapes(pattern)
    for group in _GROUP.finditer(stripped):
        body = group.group(1)
        if not _has_unbounded_quantifier(body):
            continue
        if _body_is_disjoint(body):
            continue
        # Confirm an enclosing unbounded repetition: `(a+)+`, `(\w*)*`, `(x+){2,}`.
        # The quantifier must be the group's *own* repetition, so nothing may sit
        # between the closing parenthesis and it. In `[A-Z]\w*)\s*`, the `*` after
        # `)` belongs to the following `\\s*`; without this check it would read as
        # the group being repeated and every `(?P<x>[A-Z]\\w*)\\s*` would be a
        # false positive.
        after = stripped[group.end() :]
        quantifier = _QUANTIFIER.match(after)
        if quantifier is None or quantifier.start() != 0:
            continue
        return (
            True,
            f"nested unbounded quantifier: group body {body!r} inside ({quantifier.group(0)})",
        )
    # Direct form: `a**`, or an alternation repeated, e.g. `(a|a)*` is safe but
    # `(\w+\s?)*` is caught above; `a+*` is a redundant quantifier.
    if re.search(r"(?:[*+]|\{\d+,\d*\})[*+]", stripped):
        return True, "stacked unbounded quantifiers"
    return False, ""


def extract_literals(source: str, language: str) -> list[RedexMatch]:
    """Extract regex literals from *source* for *language*.

    Args:
        source: str: Full source text to scan for regex literals.
        language: str: Language whose literal syntax applies; unknown values yield nothing.
    """
    extractor = _LITERAL_PATTERNS.get(language)
    if extractor is None:
        return []
    matches: list[RedexMatch] = []
    for match in extractor.finditer(source):
        pattern = match.group("pattern")
        line = source.count("\n", 0, match.start("pattern")) + 1
        column = match.start("pattern") - (source.rfind("\n", 0, match.start("pattern")) + 1) + 1
        matches.append(RedexMatch(line=line, column=column, pattern=pattern, reason=""))
    return matches


def scan_for_redos(file_label: str, source: str, language: str) -> list[Finding]:
    """Return ``OCSA-VALID-004`` findings for every vulnerable regex literal.

    Each finding reports a vulnerable pattern shape, not a measured slowdown.

    Args:
        file_label: str: Path shown on every finding this source produces.
        source: str: Full source text to scan for regex literals.
        language: str: Language whose literal syntax applies; unknown values yield nothing.
    """
    rule = rule_by_id(RULE_ID)
    if rule is None:  # pragma: no cover - table drift guard
        raise LookupError(RULE_ID)

    findings: list[Finding] = []
    lines = source.splitlines()
    for literal in extract_literals(source, language):
        vulnerable, reason = is_vulnerable(literal.pattern)
        if not vulnerable:
            continue
        index = max(0, literal.line - 1)
        excerpt = redact_text(lines[index].strip()) if index < len(lines) else literal.pattern
        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=file_label,
                line=literal.line,
                column=literal.column,
                code_location=excerpt[:240] or literal.pattern[:240],
                description=f"{rule.title}: {reason}",
                root_cause=rule.root_cause,
                impact=rule.impact,
                remediation=rule.remediation,
                language=language,
                references=rule.references,
            )
        )
    return findings
