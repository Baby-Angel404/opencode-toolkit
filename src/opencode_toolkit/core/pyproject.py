"""Read the dependency declarations out of ``pyproject.toml``.

``tomllib`` only exists on Python 3.11+, but this package supports 3.10. Rather
than let an SBOM silently come out empty on 3.10, this module parses exactly the
two constructs the toolkit needs -- ``project.dependencies`` and
``project.optional-dependencies.<extra>`` -- using :mod:`tomllib` when it is
available and a narrow line-oriented reader otherwise.

The fallback is intentionally not a general TOML parser. It understands the
array-of-strings and inline-table shapes that real ``pyproject.toml`` files use
for dependencies, and it raises rather than guessing when it meets a shape it
does not recognise, so an incorrect dependency list can never be reported
silently.
"""

from __future__ import annotations

import re
from typing import Any

try:  # pragma: no cover - the branch taken depends on the interpreter
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    tomllib = None

__all__ = ["RequirementGroups", "read_pyproject_requirements"]

_SECTION = re.compile(r"^\[(?P<name>[^\]]+)\]$")
# Optional whitespace is expressed as a character class rather than a quantified
# group, so the pattern stays free of the nested-quantifier shape that a ReDoS
# heuristic flags. ``.*`` is bounded because the caller feeds it one line.
_KEY = re.compile(r"^(?P<key>[A-Za-z0-9_.-]+)[ \t]*=[ \t]*(?P<value>.*)$")
_ARRAY_ENTRY = re.compile(r"""^\s*(?P<quote>["'])(?P<text>.*?)(?P=quote)\s*(?:,.*)?$""")


class RequirementGroups:
    """The requirement specifiers declared by a ``pyproject.toml``.

    Attributes:
        runtime: Entries of ``project.dependencies``.
        extras: Entries of ``project.optional-dependencies``, keyed by extra name.
    """

    __slots__ = ("extras", "runtime")

    def __init__(self, runtime: list[str], extras: dict[str, list[str]]) -> None:
        self.runtime = runtime
        self.extras = extras

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"RequirementGroups(runtime={self.runtime!r}, extras={self.extras!r})"


def _strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment that is not inside a quoted string."""
    out: list[str] = []
    quote: str | None = None
    for index, char in enumerate(line):
        if quote is not None:
            out.append(char)
            if char == quote and (index == 0 or line[index - 1] != "\\"):
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            out.append(char)
            continue
        if char == "#":
            break
        out.append(char)
    return "".join(out)


def _parse_string_array(text: str, *, context: str) -> list[str]:
    """Parse a multi-line or single-line array of quoted strings."""
    body = text.strip()
    if not body.startswith("["):
        raise ValueError(f"{context}: expected an array of strings, got {body!r}")
    if not body.endswith("]"):
        raise ValueError(f"{context}: unterminated array, expected a closing ']'")
    inner = body[1:-1]
    entries: list[str] = []
    for raw in inner.split(","):
        candidate = _strip_comment(raw).strip()
        if not candidate:
            continue
        match = _ARRAY_ENTRY.match(candidate)
        if match is None:
            raise ValueError(
                f"{context}: only arrays of quoted strings are supported, got {candidate!r}"
            )
        entries.append(match.group("text"))
    return entries


def _parse_inline_table_of_arrays(value: str, *, context: str) -> dict[str, list[str]]:
    """Parse ``{ dev = ["a", "b"], docs = ["c"] }`` into a mapping."""
    body = value.strip()
    if not (body.startswith("{") and body.endswith("}")):
        raise ValueError(f"{context}: expected an inline table, got {body!r}")
    result: dict[str, list[str]] = {}
    for raw in body[1:-1].split(","):
        candidate = _strip_comment(raw).strip()
        if not candidate:
            continue
        key, separator, items = candidate.partition("=")
        if not separator:
            raise ValueError(f"{context}: expected 'name = [...]', got {candidate!r}")
        name = key.strip().strip("\"'")
        result[name] = _parse_string_array(items, context=f"{context}.{name}")
    return result


#: Keys inside ``[project]`` this reader cares about.
_PROJECT_KEYS = {"dependencies", "optional-dependencies"}


def _read_without_tomllib(text: str) -> dict[str, Any]:
    """Extract the dependency structures with a narrow line-oriented reader."""
    runtime: list[str] = []
    extras: dict[str, list[str]] = {}
    section = ""
    # ``wanted`` records which bucket a value being accumulated belongs to, and
    # ``extra`` its key. Uninteresting multi-line values (classifiers, for
    # example) are skipped rather than parsed.
    wanted: str | None = None
    extra = ""
    pending: list[str] = []
    context = ""

    def flush() -> None:
        nonlocal wanted, pending, extra
        if wanted is None:
            return
        parsed = _parse_string_array("".join(pending).strip(), context=context)
        if wanted == "runtime":
            runtime.extend(parsed)
        elif wanted == "extra":
            extras[extra] = parsed
        wanted = None
        pending = []
        extra = ""

    for number, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        section_match = _SECTION.match(line)
        if section_match:
            flush()
            section = section_match.group("name").strip()
            continue
        in_project = section == "project"
        in_extras = section == "project.optional-dependencies"
        if not (in_project or in_extras):
            continue
        if line.startswith("]"):
            if wanted is not None:
                # The closing bracket terminates the accumulated value.
                pending.append("]")
                flush()
            continue
        key_match = _KEY.match(line)
        if key_match is None:
            if wanted is not None:
                pending.append(line)
            continue
        key = key_match.group("key").strip("\"'")
        value = key_match.group("value").strip()
        # A value that opens a bracket or quote without closing it continues on
        # the following lines.
        multiline = value.startswith(("[", "{", '"', "'")) and not value.endswith(
            ("]", "}", '"', "'")
        )
        if multiline:
            if (in_project and key in _PROJECT_KEYS) or in_extras:
                wanted = (
                    "extra" if in_extras else ("runtime" if key == "dependencies" else "inline")
                )
                extra = key
                context = f"line {number} [{section}].{key}"
                pending = [value]
            continue
        if in_project and key == "dependencies":
            runtime.extend(_parse_string_array(value, context=f"line {number}"))
        elif in_project and key == "optional-dependencies":
            extras.update(_parse_inline_table_of_arrays(value, context=f"line {number}"))
        elif in_extras:
            extras[key] = _parse_string_array(value, context=f"line {number}")
    flush()
    return {"runtime": runtime, "extras": extras}


def read_pyproject_requirements(text: str) -> RequirementGroups:
    """Return the runtime and extra requirement specifiers declared in *text*.

    Args:
        text: str: The full contents of a ``pyproject.toml`` file.

    Returns:

    Raises:
        ValueError: The file declares dependencies in a shape neither reader
            supports. This is deliberate: reporting an incomplete dependency
            list, for example in an SBOM, would be worse than failing.
    """
    if tomllib is not None:
        document = tomllib.loads(text)
        project = document.get("project", {})
        runtime = [str(item) for item in project.get("dependencies", [])]
        raw_extras = project.get("optional-dependencies", {})
        extras = {
            str(name): [str(item) for item in (values or [])] for name, values in raw_extras.items()
        }
        return RequirementGroups(runtime, extras)

    parsed = _read_without_tomllib(text)
    return RequirementGroups(parsed["runtime"], parsed["extras"])
