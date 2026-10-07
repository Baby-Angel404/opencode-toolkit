#!/usr/bin/env python3
"""Check that reusable-workflow calls grant the permissions they request.

GitHub builds the job graph before running anything. A workflow that calls a
reusable workflow may only pass down the permissions its own ``permissions``
grant, so if a nested job asks for more than the caller allows, the whole run
dies at startup: no jobs, no steps, and a conclusion of ``startup_failure``
that names neither the cause nor the file.

That is not hypothetical. ``release.yml`` pinned ``contents: read`` at the top
level while calling ``security.yml``, whose ``audit`` and ``codeql`` jobs both
request ``security-events: write``. Every tag push produced a release with zero
jobs and nothing to act on.

This is a focused reader rather than a YAML parser: PyYAML is not a dependency,
by design, because the runtime ships without third-party packages. It reads the
subset the workflows actually use -- ``permissions`` mappings and local
``uses:`` references -- and refuses to guess about anything else.

Usage::

    python scripts/security/workflow-permissions.py [--workflows DIR]

Exits non-zero and prints one ``file: message`` line per violation.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Final

# Scope keys whose value may be a level. `contents: read` is a level;
# `actions: write` is too. Anything not listed is left to GitHub to judge.
LEVELS: Final = frozenset({"read", "write", "none"})

_REUSABLE_PREFIX: Final = "./.github/workflows/"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _parse_mapping(lines: list[str], start: int, parent_indent: int) -> tuple[dict[str, str], int]:
    """Read a block mapping at *parent_indent*+2, starting at *start*.

    Returns the mapping and the index of the first line that is not part of it.
    """
    mapping: dict[str, str] = {}
    index = start
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        indent = _indent(raw)
        if indent <= parent_indent:
            break
        if ":" not in stripped:
            index += 1
            continue
        key, _, rest = stripped.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest:
            mapping[key] = _scalar(rest)
            index += 1
            continue
        # A nested block, or the first key of a mapping whose values follow on
        # subsequent lines.
        if index + 1 < len(lines) and _indent(lines[index + 1]) > indent:
            child, index = _parse_mapping(lines, index + 1, indent)
            mapping[key] = child  # type: ignore[assignment]
        else:
            index += 1
    return mapping, index


def _permissions_of(lines: list[str], start: int, owner_indent: int) -> dict[str, str]:
    """Return the permissions mapping declared for a job or workflow.

    *owner_indent* is the indentation of the ``permissions:`` key itself.
    """
    if _indent(lines[start]) != owner_indent:
        return {}
    rest = lines[start].partition(":")[2].strip()
    if rest.startswith("{"):
        inner = rest.strip("{}").strip()
        if not inner:
            return {}
        out: dict[str, str] = {}
        for item in inner.split(","):
            key, _, value = item.partition(":")
            out[key.strip()] = _scalar(value)
        return out
    if rest:  # `permissions: read-all` / `write-all` style
        return {"*": _scalar(rest)}
    nested, _ = _parse_mapping(lines, start + 1, owner_indent)
    return {k: v for k, v in nested.items() if isinstance(v, str)}


def _jobs(lines: list[str]) -> dict[str, dict[str, object]]:
    """Return ``{job_id: {"permissions", "uses", "if", "needs"}}`` per job."""
    try:
        jobs_at = next(i for i, line in enumerate(lines) if line.rstrip() == "jobs:")
    except StopIteration:
        return {}
    jobs: dict[str, dict[str, object]] = {}
    current: str | None = None
    for index in range(jobs_at + 1, len(lines)):
        raw = lines[index]
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = _indent(raw)
        if indent == 0:
            break
        stripped = raw.strip()
        if indent == 2 and stripped.endswith(":"):
            current = stripped[:-1].strip()
            jobs[current] = {"permissions": {}, "uses": None, "if": None, "needs": []}
            continue
        if current is None:
            continue
        if indent == 4 and stripped.startswith("permissions:"):
            jobs[current]["permissions"] = _permissions_of(lines, index, 4)
        elif indent == 4 and stripped.startswith("uses:"):
            jobs[current]["uses"] = _scalar(stripped.partition(":")[2])
        elif indent == 4 and stripped.startswith("if:"):
            jobs[current]["if"] = stripped.partition(":")[2].strip()
        elif indent == 4 and stripped.startswith("needs:"):
            raw = stripped.partition(":")[2].strip()
            if raw.startswith("["):
                jobs[current]["needs"] = [
                    item.strip().strip("'\"") for item in raw.strip("[]").split(",") if item.strip()
                ]
    return jobs


def _top_level_permissions(lines: list[str]) -> dict[str, str]:
    for index, raw in enumerate(lines):
        if raw.rstrip() == "permissions:" or raw.startswith("permissions: "):
            return _permissions_of(lines, index, 0)
    return {}


def _granted(permissions: dict[str, str]) -> dict[str, str]:
    """Expand ``read-all``/``write-all`` into every scope we understand."""
    if "*" in permissions:
        level = permissions["*"]
        if level in {"read-all", "write-all"}:
            return {"*": "write" if level == "write-all" else "read"}
        return {}
    return permissions


def _rank(level: str) -> int:
    return {"none": 0, "read": 1, "write": 2}.get(level, 0)


def _covers(granted: dict[str, str], wanted: dict[str, str]) -> list[str]:
    """Return the scopes *wanted* that *granted* does not cover."""
    missing: list[str] = []
    if "*" in granted:
        floor = _rank(granted["*"])
        for scope, level in wanted.items():
            if scope != "*" and _rank(level) > floor:
                missing.append(f"{scope} (wants {level}, caller grants {granted['*']})")
        return missing
    for scope, level in wanted.items():
        given = granted.get(scope, "none")
        if _rank(given) < _rank(level):
            missing.append(f"{scope} (wants {level}, caller grants {given})")
    return missing


#: Status functions that opt a job out of the "a need was skipped, so I am
#: skipped too" rule. Without one of these, GitHub skips a dependent job the
#: moment any job it needs is skipped -- even when the condition would be true.
_OPTOUTS = ("always()", "cancelled()", "failure()")


def skipped_neighbour_gaps(path: pathlib.Path, lines: list[str]) -> list[str]:
    """Report jobs whose condition can never be true.

    A job that needs X is skipped whenever X is skipped, unless its condition
    opts in with ``always()``. So a condition that *asserts* X was skipped -- the
    shape you write when X is a job that only runs on the unhappy path -- can
    never hold. The job is unreachable, silently.

    That is how an approved gate produced a green run and no release:
    ``explain-blocked`` only runs when the gate refused, so on success it is
    skipped, and ``release`` required exactly that. The condition was not wrong
    by accident; it was dead code that looked deliberate.

    Only that contradiction is reported. A job that merely *should not* run
    because a need was skipped is correct as written and is left alone.
    """
    jobs = _jobs(lines)
    problems: list[str] = []
    for job_id, job in jobs.items():
        condition = job["if"] or ""
        if any(token in condition for token in _OPTOUTS):
            continue
        for needed in job["needs"]:  # type: ignore[union-attr]
            if not re.search(rf"needs\.{re.escape(needed)}\.result\s*==\s*'skipped'", condition):
                continue
            problems.append(
                f"{path.name}: job '{job_id}' needs '{needed}' and asserts "
                f"needs.{needed}.result == 'skipped', but without always() the job "
                f"is skipped the moment '{needed}' is -- the condition can never "
                f"hold and the job would never run"
            )
    return problems


def analyse(directory: pathlib.Path) -> list[str]:
    workflows = sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml"))
    parsed = {path: path.read_text(encoding="utf-8").splitlines() for path in workflows}
    by_name = {path.name: path for path in workflows}

    problems: list[str] = []
    for path, lines in parsed.items():
        top = _granted(_top_level_permissions(lines))
        for job_id, job in _jobs(lines).items():
            uses = job["uses"]
            if not isinstance(uses, str) or not uses.startswith(_REUSABLE_PREFIX):
                continue
            callee_name = uses[len(_REUSABLE_PREFIX) :]
            callee_path = by_name.get(callee_name)
            if callee_path is None:
                problems.append(f"{path.name}: job '{job_id}' calls missing workflow {callee_name}")
                continue

            callee_lines = parsed[callee_path]
            callee_top = _granted(_top_level_permissions(callee_lines))
            wanted: dict[str, str] = {}
            for _, callee_job in _jobs(callee_lines).items():
                own = callee_job["permissions"]
                effective = _granted(own if isinstance(own, dict) else {}) or callee_top
                for scope, level in effective.items():
                    if level not in LEVELS:
                        continue
                    if _rank(level) > _rank(wanted.get(scope, "none")):
                        wanted[scope] = level

            granted = (
                _granted(job["permissions"] if isinstance(job["permissions"], dict) else {}) or top
            )
            for gap in _covers(granted, wanted):
                problems.append(
                    f"{path.name}: job '{job_id}' calls {callee_name} without "
                    f"{gap}; the run would die at startup"
                )

    for path, lines in parsed.items():
        problems.extend(skipped_neighbour_gaps(path, lines))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflows",
        default=".github/workflows",
        type=pathlib.Path,
        help="directory holding the workflow files",
    )
    arguments = parser.parse_args(argv)
    directory: pathlib.Path = arguments.workflows
    if not directory.is_dir():
        print(f"::error::{directory} is not a directory")
        return 2

    problems = analyse(directory)
    for problem in problems:
        print(f"::error::{problem}")
    if not problems:
        print("every workflow job is reachable: permissions granted, no silent skips")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
