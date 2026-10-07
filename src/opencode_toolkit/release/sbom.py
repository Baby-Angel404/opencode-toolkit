"""Software Bill of Materials (CycloneDX 1.5).

The interesting fact about this project is its runtime closure: **zero
third-party packages**. That is the SBOM's headline, and it is a real property
of ``pyproject.toml`` rather than an assumption -- the runtime dependency list is
parsed and emitted, so if someone adds a runtime dependency the SBOM changes and
``release gate`` will show it.

Development dependencies are emitted separately under a ``dev`` scope so a
consumer reading the SBOM can tell what is not required to run the tool.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from opencode_toolkit.core import jsonio
from opencode_toolkit.core.pyproject import read_pyproject_requirements
from opencode_toolkit.core.version import Version, detect_version

CYCLONEDX_VERSION = "1.5"
SPEC_VERSION = "1.5"
BOM_FORMAT = "CycloneDX"

TOOL_VENDOR = "opencode-toolkit"
TOOL_NAME = "opencode-toolkit"


def _parse_requirement(spec: str) -> tuple[str, str]:
    """Split ``name>=1.2`` into ``("name", ">=1.2")``."""
    match = re.match(r"^(?P<name>[A-Za-z0-9._-]+)(?P<spec>.*)$", spec.strip())
    if match is None:
        return spec.strip(), ""
    return match.group("name"), match.group("spec").strip()


def _component(name: str, version_spec: str, *, scope: str, dev: bool) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "name": name,
        "scope": scope,
        "purl": f"pkg:pypi/{name.lower()}",
    }
    if version_spec:
        component["version"] = version_spec.lstrip("=<>!~ ")
    if dev:
        component["properties"] = [{"name": "opencode:scope", "value": "development-only"}]
    return component


def project_dependencies(root: Path) -> tuple[list[str], list[str]]:
    """Return ``(runtime, development)`` requirement specifiers.

    Args:
        root: Path: Project root containing ``pyproject.toml``.
    """
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return [], []
    groups = read_pyproject_requirements(pyproject.read_text(encoding="utf-8"))
    return groups.runtime, groups.extras.get("dev", [])


def runtime_components(root: Path) -> list[dict[str, Any]]:
    """Runtime dependency closure.

    Empty for this project, and that empty list is the point: the offline pack
    bundles only first-party code, so there is nothing to attribute.

    Args:
        root: Path: Project root containing ``pyproject.toml``.
    """
    runtime, _ = project_dependencies(root)
    return [_component(*_parse_requirement(item), scope="required", dev=False) for item in runtime]


def development_components(root: Path) -> list[dict[str, Any]]:
    """Return development-only components, tagged ``optional`` and ``dev``.

    They are deliberately kept out of ``sbom_document``'s ``components`` list:
    the runtime closure is what a consumer must install, and mixing build-time
    packages into it would misstate the dependency surface.

    Args:
        root: Path: Project root containing ``pyproject.toml``.

    Returns:
    """
    _, development = project_dependencies(root)
    return [
        _component(*_parse_requirement(item), scope="optional", dev=True) for item in development
    ]


def build_sbom(root: Path, *, version: Version | None = None) -> str:
    """Return the SBOM as a deterministic JSON document.

    Args:
        root: Path: Project root containing ``pyproject.toml``.
        version: Version | None: Version to record; detected from ``pyproject.toml`` if omitted.
    """
    resolved = version or detect_version(root)
    document = sbom_document(root, version=resolved)
    return jsonio.dumps(document, indent=2) + "\n"


def sbom_document(root: Path, *, version: Version | None = None) -> dict[str, Any]:
    """Return the SBOM as a dictionary.

    Args:
        root: Path: Project root containing ``pyproject.toml``.
        version: Version | None: Version to record; detected from ``pyproject.toml`` if omitted.
    """
    resolved = version or detect_version(root)
    components = runtime_components(root)
    development = development_components(root)
    serial = _deterministic_serial(resolved, components, development)

    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": None,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": TOOL_NAME,
                        "version": str(resolved),
                        "publisher": TOOL_VENDOR,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"pkg:pypi/{TOOL_NAME}@{resolved}",
                "name": TOOL_NAME,
                "version": str(resolved),
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "description": (
                    "Unified OpenCode engineering toolkit. The runtime component "
                    "closure is empty by design."
                ),
            },
            "properties": [
                {"name": "opencode:runtime-dependencies", "value": str(len(components))},
                {"name": "opencode:development-dependencies", "value": str(len(development))},
            ],
        },
        "components": components,
        # Development-only packages are not part of the runtime graph, so they are
        # recorded here rather than in `components`.
        "annotations": [
            {
                "subjects": [{"ref": f"pkg:pypi/{TOOL_NAME}@{resolved}"}],
                "annotator": {"organization": {"name": TOOL_VENDOR}},
                "annotation": "development-dependencies",
                "text": "Not required at runtime: "
                + ", ".join(sorted(item["name"] for item in development))
                if development
                else "none",
            }
        ],
    }


def _deterministic_serial(version: Version, *groups: list[dict[str, Any]]) -> str:
    """Derive a stable UUID-shaped serial from the document's own content.

    A random serial would make every SBOM differ byte-for-byte, which defeats
    reproducible builds and lets a checksum comparison prove nothing.
    """
    from opencode_toolkit.core.fsio import sha256_bytes

    material = jsonio.dump_compact({"version": str(version), "groups": groups})
    digest = sha256_bytes(material.encode("utf-8"))
    return f"{digest[0:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"


def sbom_summary(root: Path) -> dict[str, Any]:
    """Counts used by ``opencode doctor`` and the release report.

    Args:
        root: Path: Project root containing ``pyproject.toml``.
    """
    runtime = runtime_components(root)
    development = development_components(root)
    return {
        "format": f"{BOM_FORMAT} {SPEC_VERSION}",
        "runtime_dependencies": len(runtime),
        "development_dependencies": len(development),
        "runtime_components": [item["name"] for item in runtime],
        "development_components": sorted(item["name"] for item in development),
    }
