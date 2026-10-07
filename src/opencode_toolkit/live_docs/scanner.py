"""API surface extraction.

Python is parsed with ``ast``, so the extracted signatures are exact: parameter
names, defaults, annotations and return annotations, plus whether the docstring
documents each parameter. JavaScript, TypeScript and Go are scanned with bounded
line patterns and their results are marked ``heuristic=True`` so consumers never
treat them as authoritative.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opencode_toolkit.core.fsio import iter_files

#: A name starting with an underscore is not part of the public API.
PRIVATE_PREFIX = "_"

DOC_PREFIXES = ("docs/", "examples/")


@dataclass(frozen=True, slots=True)
class Parameter:
    """One parameter of a callable."""

    name: str
    annotation: str = ""
    default: str | None = None
    kind: str = "positional_or_keyword"
    documented: bool = False

    def signature(self) -> str:
        """Render the parameter as it would appear in a signature."""
        parts = [self.name]
        if self.annotation:
            parts.append(f": {self.annotation}")
        if self.default is not None:
            parts.append(f" = {self.default}")
        return "".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Return the parameter as JSON-serialisable data."""
        return {
            "name": self.name,
            "annotation": self.annotation,
            "default": self.default,
            "kind": self.kind,
            "documented": self.documented,
        }


@dataclass(frozen=True, slots=True)
class ApiItem:
    """A public function, class or method."""

    name: str
    qualified_name: str
    kind: str
    file: str
    line: int
    parameters: tuple[Parameter, ...] = ()
    returns: str = ""
    docstring: str = ""
    summary: str = ""
    is_async: bool = False
    decorators: tuple[str, ...] = ()
    documented: bool = False
    heuristic: bool = False

    def signature(self) -> str:
        """Render the full signature, as written in the source."""
        params = ", ".join(parameter.signature() for parameter in self.parameters)
        prefix = "async def" if self.is_async else "def"
        suffix = f" -> {self.returns}" if self.returns else ""
        return f"{prefix} {self.name}({params}){suffix}"

    def undocumented_parameters(self) -> list[str]:
        """Return the names of parameters the docstring never mentions."""
        return [parameter.name for parameter in self.parameters if not parameter.documented]

    def to_dict(self) -> dict[str, Any]:
        """Return the item as JSON-serialisable data."""
        return {
            "name": self.name,
            "qualified_name": self.qualified_name,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "signature": self.signature(),
            "parameters": [parameter.to_dict() for parameter in self.parameters],
            "returns": self.returns,
            "summary": self.summary,
            "documented": self.documented,
            "undocumented_parameters": self.undocumented_parameters(),
            "is_async": self.is_async,
            "decorators": list(self.decorators),
            "heuristic": self.heuristic,
        }


@dataclass(slots=True)
class ApiSurface:
    """Everything extracted from a tree."""

    root: str
    items: list[ApiItem] = field(default_factory=list)
    files_scanned: int = 0
    parse_errors: list[dict[str, str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.items)

    @property
    def undocumented(self) -> list[ApiItem]:
        """Public items with no docstring at all."""
        return [item for item in self.items if not item.documented]

    @property
    def partial(self) -> list[ApiItem]:
        """Documented, but with parameters the docstring never mentions."""
        return [item for item in self.items if item.documented and item.undocumented_parameters()]

    def by_kind(self, kind: str) -> list[ApiItem]:
        """Return the items of one kind, such as ``class`` or ``function``.

        Args:
            kind: str: Item kind to match exactly, such as ``class`` or
                ``function``.
        """
        return [item for item in self.items if item.kind == kind]

    def counts(self) -> dict[str, int]:
        """Return per-kind counts plus ``total``, ``undocumented`` and ``partial``."""
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.kind] = counts.get(item.kind, 0) + 1
        counts["total"] = len(self.items)
        counts["undocumented"] = len(self.undocumented)
        counts["partial"] = len(self.partial)
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Return the surface, its counts and its parse errors as data."""
        return {
            "root": self.root,
            "counts": self.counts(),
            "files_scanned": self.files_scanned,
            "parse_errors": self.parse_errors,
            "items": [
                item.to_dict() for item in sorted(self.items, key=lambda i: (i.file, i.line))
            ],
        }

    def digest_items(self) -> list[dict[str, Any]]:
        """The subset used for drift comparison -- prose is excluded on purpose.

        Docstring text changes constantly as humans edit it; comparing it would
        report drift on every prose edit and train people to ignore the tool.
        """
        return [
            {
                "qualified_name": item.qualified_name,
                "kind": item.kind,
                "file": item.file,
                "signature": item.signature(),
                "returns": item.returns,
                "parameters": [parameter.name for parameter in item.parameters],
            }
            for item in sorted(self.items, key=lambda i: i.qualified_name)
        ]


def scan_tree(
    root: Path,
    *,
    include_extensions: Iterable[str] = (".py", ".js", ".ts", ".go"),
    exclude_dirs: Iterable[str] = (
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
    ),
    max_file_bytes: int = 1_000_000,
) -> ApiSurface:
    """Scan *root* and return the extracted API surface.

    Args:
        root: Path: Directory to walk; resolved before the walk begins.
        include_extensions: Iterable[str]: File suffixes to extract from,
            compared case-insensitively; anything else is skipped.
        exclude_dirs: Iterable[str]: Directory names pruned from the walk at
            every depth.
        max_file_bytes: int: Largest file read, in bytes; bigger files are
            skipped. Defaults to 1_000_000.
    """
    root = root.resolve()
    surface = ApiSurface(root=str(root))
    suffixes = {suffix.lower() for suffix in include_extensions}

    for path in iter_files(root, exclude_dirs=set(exclude_dirs), max_file_bytes=max_file_bytes):
        if path.suffix.lower() not in suffixes:
            continue
        relative = path.relative_to(root).as_posix()
        if relative.startswith(DOC_PREFIXES):
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            surface.parse_errors.append({"file": relative, "error": "unreadable"})
            continue

        surface.files_scanned += 1
        if path.suffix == ".py":
            try:
                tree = ast.parse(source, filename=relative)
            except SyntaxError as exc:
                surface.parse_errors.append(
                    {"file": relative, "error": f"syntax: line {exc.lineno}: {exc.msg}"}
                )
                continue
            surface.items.extend(_scan_python(relative, tree))
        else:
            surface.items.extend(_scan_heuristic(relative, path.suffix.lower().lstrip("."), source))

    surface.items.sort(key=lambda item: (item.file, item.line))
    return surface


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------


def _scan_python(relative: str, tree: ast.Module) -> list[ApiItem]:
    items: list[ApiItem] = []

    exported = _dunder_all(tree)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if node.name.startswith(PRIVATE_PREFIX) and node.name not in exported:
                continue
            items.append(_function_item(relative, node, module_prefix=""))
        elif isinstance(node, ast.ClassDef):
            if node.name.startswith(PRIVATE_PREFIX) and node.name not in exported:
                continue
            items.append(_class_item(relative, node))
            for child in node.body:
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    if child.name.startswith(PRIVATE_PREFIX) and child.name not in exported:
                        continue
                    items.append(_function_item(relative, child, module_prefix=f"{node.name}."))
    return items


def _dunder_all(tree: ast.Module) -> frozenset[str]:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "__all__"
                    and isinstance(node.value, ast.List | ast.Tuple)
                ):
                    return frozenset(
                        element.value
                        for element in node.value.elts
                        if isinstance(element, ast.Constant) and isinstance(element.value, str)
                    )
    return frozenset()


def _is_documented(name: str, documented: set[str]) -> bool:
    """Return whether a parameter name appears in the docstring's ``Args:`` block.

    A variadic parameter is recorded with its sigil (``*args``, ``**kwargs``)
    because that is how it reads in a signature, but an author may write either
    spelling in the docstring. Both are accepted.
    """
    return name in documented or f"{'*' * 2}{name}" in documented or f"*{name}" in documented


def _function_item(
    relative: str, node: ast.FunctionDef | ast.AsyncFunctionDef, *, module_prefix: str
) -> ApiItem:
    docstring = ast.get_docstring(node)
    documented_params = _documented_parameters(docstring)
    arguments = node.args
    positional = list(arguments.posonlyargs) + list(arguments.args)
    defaults = list(arguments.defaults)
    offset = len(positional) - len(defaults)
    # The receiver is implicit in a method's signature and, in Google style,
    # deliberately absent from its Args block. Treating it as an undocumented
    # parameter would report every well-written method as drift.
    if module_prefix and positional and positional[0].arg in {"self", "cls"}:
        positional = positional[1:]
        offset = max(offset - 1, 0)

    parameters: list[Parameter] = []
    for index, argument in enumerate(positional):
        default = None
        if index >= offset:
            default = _render(defaults[index - offset])
        parameters.append(
            Parameter(
                name=argument.arg,
                annotation=_render(argument.annotation),
                default=default,
                kind="positional_only"
                if index < len(arguments.posonlyargs)
                else "positional_or_keyword",
                documented=argument.arg in documented_params,
            )
        )
    for argument, default_node in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=False):
        parameters.append(
            Parameter(
                name=argument.arg,
                annotation=_render(argument.annotation),
                default=_render(default_node) if default_node is not None else None,
                kind="keyword_only",
                documented=argument.arg in documented_params,
            )
        )
    if arguments.vararg is not None:
        parameters.append(
            Parameter(
                name=f"*{arguments.vararg.arg}",
                annotation=_render(arguments.vararg.annotation),
                kind="var_positional",
                documented=_is_documented(arguments.vararg.arg, documented_params),
            )
        )
    if arguments.kwarg is not None:
        parameters.append(
            Parameter(
                name=f"**{arguments.kwarg.arg}",
                annotation=_render(arguments.kwarg.annotation),
                kind="var_keyword",
                documented=_is_documented(arguments.kwarg.arg, documented_params),
            )
        )

    return ApiItem(
        name=node.name,
        qualified_name=f"{module_prefix}{node.name}",
        kind="function",
        file=relative,
        line=node.lineno,
        parameters=tuple(parameters),
        returns=_render(node.returns),
        docstring=docstring or "",
        summary=(docstring or "").strip().splitlines()[0] if docstring else "",
        is_async=isinstance(node, ast.AsyncFunctionDef),
        decorators=tuple(_render(item) for item in node.decorator_list),
        documented=bool(docstring),
    )


def _class_item(relative: str, node: ast.ClassDef) -> ApiItem:
    docstring = ast.get_docstring(node)
    init = next(
        (
            child
            for child in node.body
            if isinstance(child, ast.FunctionDef) and child.name == "__init__"
        ),
        None,
    )
    parameters: tuple[Parameter, ...] = ()
    if init is not None and init.args.args:
        first = init.args.args[0]
        if first.arg in {"self", "cls"}:
            # The receiver is implicit. Marking it documented keeps a class from
            # being reported as partially documented for a parameter no author
            # would ever list.
            parameters = (
                Parameter(
                    name=first.arg,
                    annotation=_render(first.annotation),
                    documented=True,
                ),
            )
    return ApiItem(
        name=node.name,
        qualified_name=node.name,
        kind="class",
        file=relative,
        line=node.lineno,
        parameters=parameters,
        docstring=docstring or "",
        summary=(docstring or "").strip().splitlines()[0] if docstring else "",
        documented=bool(docstring),
    )


def _render(node: ast.expr | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):  # pragma: no cover - exotic nodes
        return "<unrenderable>"


def _documented_parameters(docstring: str | None) -> set[str]:
    """Names mentioned in a Google-style ``Args:`` block."""
    if not docstring:
        return set()
    names: set[str] = set()
    in_args = False
    for raw in docstring.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.endswith(":") and not line.startswith(" "):
            in_args = line.rstrip(":").strip().lower() in {
                "args",
                "arguments",
                "parameters",
                "params",
            }
            continue
        if in_args and ":" in line:
            names.add(line.split(":", 1)[0].strip())
    return names


# --------------------------------------------------------------------------
# Heuristic scanners
# --------------------------------------------------------------------------

_JS_FUNCTION = (
    "export function",
    "export async function",
    "function",
    "const",
    "async function",
    "=>",
)


def _scan_heuristic(relative: str, language: str, source: str) -> list[ApiItem]:
    if language in {"js", "ts"}:
        return _scan_js_like(relative, source)
    if language == "go":
        return _scan_go(relative, source)
    return []


#: ``export``/``export default`` followed by a declaration keyword.
_JS_DECLARATION = re.compile(
    r"^export\s+(?:default\s+)?"
    r"(?P<kind>async\s+function|function|class|const|let|var)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)"
    r"(?:\s*[:=][^=]*)?"  # const/let type annotation or initialiser
    r"(?:\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)?"  # arrow form
    r"(?P<params>\([^)]*\))?"  # traditional parameter list
)


def _scan_js_like(relative: str, source: str) -> list[ApiItem]:
    """Extract exported declarations from JavaScript or TypeScript.

    Heuristic by necessity: without a parser for every dialect, only the
    canonical ``export function|class|const name(...)`` forms are recognised.
    Results are flagged ``heuristic=True`` so no consumer mistakes them for
    authoritative.
    """
    items: list[ApiItem] = []
    for number, raw in enumerate(source.splitlines(), start=1):
        line = raw.strip()
        if line.startswith(("//", "*", "/*")):
            continue
        match = _JS_DECLARATION.match(line)
        if match is None:
            continue
        kind = "class" if "class" in match.group("kind") else "function"
        raw_params = match.group("params")
        parameter_source = raw_params if raw_params else _arrow_parameters(line)
        parameters = tuple(
            Parameter(
                name=chunk.strip().split(":")[0].split("=")[0].strip(),
                documented=False,
            )
            for chunk in _split_parameters(parameter_source)
            if chunk.strip()
        )
        items.append(
            ApiItem(
                name=match.group("name"),
                qualified_name=match.group("name"),
                kind=kind,
                file=relative,
                line=number,
                parameters=parameters,
                heuristic=True,
                documented=False,
            )
        )
    return items


def _arrow_parameters(line: str) -> str:
    """Extract ``(a, b) => ...`` parameters, returning ``""`` when absent."""
    match = re.search(r"=\s*(?:async\s*)?\(([^)]*)\)\s*=>", line)
    return f"({match.group(1)})" if match else ""


def _split_parameters(text: str) -> list[str]:
    start = text.find("(")
    if start == -1:
        return []
    depth = 0
    end = -1
    for index in range(start, len(text)):
        character = text[index]
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
            if depth == 0:
                end = index
                break
    return text[start + 1 : end].split(",") if end != -1 else []


def _scan_go(relative: str, source: str) -> list[ApiItem]:
    # The receiver group must be non-empty when present and its trailing space
    # sits outside the optional group, so no two quantifiers can split the same
    # whitespace (CWE-1333).
    pattern = re.compile(
        r"^func\s+(?:\([^)]+\))?\s*(?P<name>[A-Z]\w*)\s*\((?P<params>[^)]*)\)\s*(?P<ret>[^{]*)\{"
    )
    items: list[ApiItem] = []
    for number, raw in enumerate(source.splitlines(), start=1):
        match = pattern.match(raw.strip())
        if match is None:
            continue
        parameters = tuple(
            Parameter(
                name=chunk.strip().split(" ")[0] if chunk.strip() else "",
                annotation=chunk.strip().split(" ", 1)[1] if " " in chunk.strip() else "",
                documented=False,
            )
            for chunk in match.group("params").split(",")
            if chunk.strip()
        )
        items.append(
            ApiItem(
                name=match.group("name"),
                qualified_name=match.group("name"),
                kind="function",
                file=relative,
                line=number,
                parameters=parameters,
                returns=match.group("ret").strip(),
                heuristic=True,
                documented=False,
            )
        )
    return items
