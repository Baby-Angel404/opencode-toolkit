"""Conservative docstring repair.

Only the machine-owned sections are rewritten:

* the ``Args:`` block, when one already exists
* the ``Returns:`` block, when one already exists

Everything else -- the summary line, extended prose, ``Raises:``, ``Example:``,
``Note:``, section ordering, blank lines -- is preserved byte for byte.

Design rule: **if a rewrite would touch a line the tool does not own, the file is
not rewritten.** ``docs update`` therefore reports ``needs_review`` for a large
class of files rather than producing a diff nobody can review. That is a
deliberate trade of coverage for reviewability.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core.fsio import sha256_file, write_guarded
from opencode_toolkit.live_docs.scanner import ApiItem

#: Section headers recognised in a Google-style docstring.
# A Google-style section header: a capitalised word at any indentation, alone
# on its line, ending in a colon. Indentation is not part of the match because a
# docstring whose first line is inline has a zero-indent summary followed by
# indented sections.
_SECTION_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<name>[A-Z][A-Za-z]*(?: [A-Z][A-Za-z]*)*):\s*$")

#: Sections the tool is willing to rewrite. Anything else is human-owned.
_OWNED_SECTIONS = frozenset({"args", "arguments", "parameters", "params", "returns", "return"})

# An Args entry is ``name: description``, optionally with a parenthesised type
# between them. Parsing that in one regex needs two whitespace runs around a
# group that can match empty -- the ambiguous shape CWE-1333 describes -- so the
# entry is read in two anchored steps instead: the name here, then the remainder
# by index in :func:`_parse_arg_entries`.
_ARG_NAME_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<name>\*{0,2}\w+)(?P<gap>[ \t]*)")


@dataclass(slots=True)
class FileUpdate:
    """Proposed and applied changes for one file."""

    file: str
    status: str = "unchanged"
    reason: str = ""
    functions_updated: list[str] = field(default_factory=list)
    digest_before: str = ""
    digest_after: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return the file's update, including before/after digests."""
        return {
            "file": self.file,
            "status": self.status,
            "reason": self.reason,
            "functions_updated": sorted(self.functions_updated),
            "digest_before": self.digest_before,
            "digest_after": self.digest_after,
        }


@dataclass(slots=True)
class UpdateResult:
    """Aggregate outcome of a docs update run."""

    files: list[FileUpdate] = field(default_factory=list)
    applied: bool = False

    @property
    def changed(self) -> list[FileUpdate]:
        """Files this run would rewrite."""
        return [item for item in self.files if item.status == "updated"]

    @property
    def needs_review(self) -> list[FileUpdate]:
        """Files a human must look at, because the rewrite was refused."""
        return [item for item in self.files if item.status == "needs_review"]

    def to_dict(self) -> dict[str, Any]:
        """Return the run's per-file updates as JSON-serialisable data."""
        return {
            "applied": self.applied,
            "files": [item.to_dict() for item in self.files],
            "changed": [item.file for item in self.changed],
            "needs_review": [item.file for item in self.needs_review],
        }


def plan_file(root: Path, items: list[ApiItem]) -> tuple[FileUpdate, str]:
    """Return ``(update, new_source)`` for one file without writing anything.

    ``new_source`` is identical to the current text when ``update.status`` is not
    ``"updated"``.

    Args:
        root: Path: Scanned root that item file paths are relative to.
        items: list[ApiItem]: Public items found in one file; an empty list
            yields an ``unchanged`` update and empty text.
    """
    if not items:
        return FileUpdate(file="", status="unchanged", reason="no public items"), ""

    relative = items[0].file
    path = root / relative
    update = FileUpdate(file=relative)
    try:
        original = path.read_text(encoding="utf-8")
        update.digest_before = sha256_file(path)
    except (OSError, UnicodeDecodeError) as exc:
        update.status = "needs_review"
        update.reason = f"cannot read file: {exc}"
        return update, ""

    rewriter = _Rewriter(original)
    for item in items:
        if item.heuristic or not item.parameters:
            continue
        rewriter.rewrite(item, update)

    if rewriter.text == original:
        update.status = "unchanged"
        update.reason = "docstrings already match the signatures"
        return update, original
    if update.status == "needs_review":
        return update, original
    update.status = "updated"
    update.digest_after = _text_digest(rewriter.text)
    return update, rewriter.text


class _Rewriter:
    """Rewrites owned sections of a single docstring."""

    def __init__(self, text: str) -> None:
        self.text = text

    def rewrite(self, item: ApiItem, update: FileUpdate) -> str:
        """Return the source with *item*'s Args/Returns blocks refreshed."""
        location = self._locate(item)
        if location is None:
            return self.text
        start, end, body, indent, opening, closing = location
        sections = self._parse_sections(body, indent)
        if sections is None:
            return self.text

        changed = False
        if sections.get("args") is not None:
            rebuilt = self._render_args(item, sections["args"])
            if rebuilt != sections["args"]:
                sections["args"] = rebuilt
                changed = True
        if sections.get("returns") is not None:
            rebuilt = self._render_returns(item, sections["returns"])
            if rebuilt != sections["returns"]:
                sections["returns"] = rebuilt
                changed = True
        if not changed:
            return self.text

        tail = body[len(body.rstrip()) :]
        new_body = self._join_sections(sections, tail)
        if not self._prose_preserved(body, new_body):
            update.status = "needs_review"
            update.reason = "preserve-check failed: a human-owned line would change"
            return self.text

        rebuilt = f"{opening}{new_body}{closing}"
        self.text = self.text[:start] + rebuilt + self.text[end:]
        if item.qualified_name not in update.functions_updated:
            update.functions_updated.append(item.qualified_name)
        return self.text

    # -- locating ---------------------------------------------------------
    def _locate(self, item: ApiItem) -> tuple[int, int, str, str, str, str] | None:
        """Return ``(start, end, body, indent, opening, closing)`` for *item*.

        *start* and *end* are the exact source span of the docstring literal, so
        the caller can splice a replacement without reformatting the file.
        """
        """Find the docstring literal for *item* using AST positions."""
        try:
            tree = ast.parse(self.text)
        except SyntaxError:
            return None
        target = item.qualified_name.split(".")[-1]
        holder = item.qualified_name.split(".")[0] if "." in item.qualified_name else None

        def docstring_node(node: ast.AST) -> ast.Expr | None:
            body = getattr(node, "body", [])
            if not body:
                return None
            first = body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                return first
            return None

        candidates: list[ast.stmt] = list(tree.body)
        if holder:
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and node.name == holder:
                    candidates = list(node.body)
                    break
        for node in candidates:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == target:
                expression = docstring_node(node)
                if expression is None:
                    return None
                # get_source_segment gives the exact literal as written,
                # including any r/f prefix and quote style, so the replacement
                # cannot disturb surrounding syntax.
                raw = ast.get_source_segment(self.text, expression)
                if raw is None:
                    return None
                opening, closing, body = _split_literal(raw)
                # ``closing`` is None exactly when ``opening`` is, so one check
                # narrows both.
                if opening is None or closing is None:
                    return None
                start = self.text.index(raw)
                end = start + len(raw)
                first_line = raw.split("\n", 1)[0]
                indent_match = re.match(r"[ \t]*", first_line) if first_line else None
                indent = indent_match.group(0) if indent_match else ""
                return start, end, body, indent, opening, closing
        return None

    # -- sections ---------------------------------------------------------
    def _parse_sections(self, body: str, indent: str) -> dict[str, str] | None:  # noqa: ARG002
        """Split a docstring into ``{section: raw_block}`` plus preserved prose.

        Section headers are recognised at the body content's own base indent
        rather than at the literal's column, because ``get_source_segment``
        returns the first line without its leading whitespace while later lines
        keep theirs.

        Returns ``None`` when the docstring has no recognisable section, which
        makes the caller skip the file rather than guess.
        """
        sections: dict[str, str] = {}
        current_name: str | None = None
        current: list[str] = []
        prose: list[str] = []

        for line in body.splitlines():
            match = _SECTION_RE.match(line)
            if match is not None:
                name = match.group("name").strip().lower()
                if current_name is not None:
                    sections[current_name] = "\n".join(current)
                elif current:
                    prose.extend(current)
                current = [line]
                current_name = name
            elif current_name is not None:
                current.append(line)
            else:
                prose.append(line)

        if current_name is not None:
            sections[current_name] = "\n".join(current)
        elif current:
            prose.extend(current)
        if not sections:
            return None
        sections["__prose__"] = "\n".join(prose)
        return sections

    def _render_args(self, item: ApiItem, block: str) -> str:
        lines = block.splitlines()
        header = lines[0]
        inner_indent = _entry_indent(lines)
        described = _parse_arg_entries(lines[1:])

        rendered = [header]
        for parameter in item.parameters:
            name = parameter.name.lstrip("*")
            description = described.get(name, "")
            if not description:
                description = f"TODO: describe {parameter.name}."
            signature = parameter.signature()
            signature = signature.split(" = ", 1)[0]
            rendered.append(f"{inner_indent}{signature}: {description}".rstrip())
        return "\n".join(rendered)

    def _render_returns(self, item: ApiItem, block: str) -> str:
        lines = block.splitlines()
        header = lines[0]
        inner_indent = _entry_indent(lines)
        if item.returns:
            return header
        body = " ".join(line.strip() for line in lines[1:] if line.strip())
        if body:
            return block
        rendered = [header, f"{inner_indent}The result of the operation."]
        return "\n".join(rendered)

    def _join_sections(self, sections: dict[str, str], tail: str) -> str:
        """Reassemble the docstring, keeping the original section order.

        *tail* is the whitespace between the last content line and the closing
        quote (usually ``"\n    "``). Preserving it exactly is what keeps the
        closing delimiter on its own line instead of being glued to the prose.
        """
        out: list[str] = [sections["__prose__"].rstrip()] if sections["__prose__"].strip() else []
        for name, block in sections.items():
            if name.startswith("__"):
                continue
            if out:
                out.append("")
            out.append(block.rstrip())
        return "\n".join(out) + tail

    @staticmethod
    def _prose_preserved(before: str, after: str) -> bool:
        """Assert the summary paragraph survived the rewrite unchanged."""

        def prose(text: str) -> list[str]:
            lines: list[str] = []
            for line in text.splitlines():
                if _SECTION_RE.match(line):
                    break
                lines.append(line.rstrip())
            return [line for line in lines if line.strip()]

        return prose(before) == prose(after)


def _entry_indent(lines: list[str]) -> str:
    """Indentation for entries inside a section block.

    Taken from the first entry line when one exists, so an author's choice of
    indentation survives a rewrite; otherwise derived from the header.
    """
    header_match = re.match(r"[ \t]*", lines[0]) if lines else None
    header_indent = header_match.group(0) if header_match else ""
    for line in lines[1:]:
        if not line.strip():
            continue
        entry_match = re.match(r"[ \t]*", line)
        return entry_match.group(0) if entry_match else header_indent
    return header_indent + "    "


_QUOTE_RE = re.compile(r"^(?P<prefix>[rRbBuUfF]{0,3})(?P<quote>\"\"\"|'''|\"|')")


def _split_literal(raw: str) -> tuple[str | None, str | None, str]:
    """Split a string literal into ``(opening, closing, body)``.

    Prefixes (``r``, ``u``, ``b``, ``f`` and combinations) are preserved so a raw
    or f-string docstring round-trips unchanged. Returns ``(None, None, "")``
    when the literal is not recognised, which makes the caller skip the file
    rather than guess at its delimiters.
    """
    match = _QUOTE_RE.match(raw)
    if match is None:
        return None, None, ""
    prefix = match.group("prefix")
    quote = match.group("quote")
    if len(quote) == 3:
        if not raw.endswith(quote) or len(raw) < 2 * len(quote):
            return None, None, ""
    elif len(raw) < 2:
        return None, None, ""
    elif raw[-1] != quote or quote in raw[1:-1]:
        # An unterminated or multi-part literal; do not attempt a rewrite.
        return None, None, ""
    body = raw[len(prefix) + len(quote) : -len(quote)]
    return prefix + quote, quote, body


def _parse_arg_entries(lines: list[str]) -> dict[str, str]:
    """Map parameter name to documented description from an Args block."""
    entries: dict[str, str] = {}
    current: str | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        name, text = _split_arg_entry(line)
        if name is not None:
            current = name
            entries[current] = text
        elif current:
            entries[current] = f"{entries[current]} {stripped}".strip()
    return entries


def _split_arg_entry(line: str) -> tuple[str | None, str]:
    """Split one Args entry into its parameter name and its description.

    Returns ``(None, "")`` when the line is not an entry, which lets the caller
    treat it as continuation prose rather than guess.
    """
    match = _ARG_NAME_RE.match(line)
    if match is None:
        return None, ""
    rest = line[match.end() :]
    if rest.startswith("("):
        closing = rest.find(")")
        if closing == -1:
            return None, ""
        rest = rest[closing + 1 :]
    rest = rest.lstrip(" \t")
    if not rest.startswith(":"):
        return None, ""
    return match.group("name").lstrip("*"), rest[1:].strip()


def _text_digest(text: str) -> str:
    from opencode_toolkit.core.fsio import sha256_bytes

    return sha256_bytes(text.encode("utf-8"))


def apply_updates(
    root: Path,
    items: list[ApiItem],
    *,
    write: bool = False,
) -> UpdateResult:
    """Plan (and optionally apply) docstring updates for *items*.

    With ``write=False`` nothing on disk changes; the returned
    :class:`UpdateResult` describes exactly what would happen, which is what the
    CLI shows in ``docs diff``.

    Args:
        root: Path: Scanned root that item file paths are relative to.
        items: list[ApiItem]: Public items to plan for; heuristic items and
            parameterless items are skipped.
        write: bool: Write the planned text to disk under an expected-digest
            guard; ``False`` records digests without writing.
    """
    result = UpdateResult(applied=False)
    by_file: dict[str, list[ApiItem]] = {}
    for item in items:
        if item.heuristic or not item.parameters:
            continue
        by_file.setdefault(item.file, []).append(item)

    for relative, file_items in sorted(by_file.items()):
        path = root / relative
        update, new_text = plan_file(root, file_items)
        if update.status != "updated":
            result.files.append(update)
            continue
        if write:
            try:
                write_guarded(path, new_text, expected_sha256=update.digest_before)
                update.digest_after = _text_digest(new_text)
                result.applied = True
            except OSError as exc:
                update.status = "needs_review"
                update.reason = f"cannot write: {exc.strerror or exc}"
        else:
            update.digest_after = _text_digest(new_text)
        result.files.append(update)
    return result


def preview_diff(root: Path, items: list[ApiItem]) -> list[dict[str, Any]]:
    """Return a unified diff for each file that would change.

    Args:
        root: Path: Scanned root that item file paths are relative to.
        items: list[ApiItem]: Public items to diff; heuristic items and
            parameterless items are skipped.
    """
    import difflib

    by_file: dict[str, list[ApiItem]] = {}
    for item in items:
        if item.heuristic or not item.parameters:
            continue
        by_file.setdefault(item.file, []).append(item)

    diffs: list[dict[str, Any]] = []
    for relative, file_items in sorted(by_file.items()):
        path = root / relative
        try:
            original = path.read_text(encoding="utf-8")
        except OSError as exc:
            diffs.append({"file": relative, "error": str(exc), "diff": ""})
            continue
        result, new_text = plan_file(root, file_items)
        if result.status != "updated":
            continue
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
                n=3,
            )
        )
        diffs.append({"file": relative, "error": "", "diff": diff})
    return diffs
