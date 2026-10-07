"""Platform classification.

The question "Space, Dataset, Model, or code repository?" has to be answered
before anything is published, because publishing a code repository *as* a model
or dataset produces a misleading artefact on a public platform.

This project is a **Python CLI library with no model weights and no dataset**.
The honest answer is therefore:

* Hugging Face -- ``not_applicable`` by default. A Space is a legitimate target
  for a demo UI, and one is opt-in, but shipping this as a Dataset or a Model
  would misrepresent it. The classifier says so and states what would have to be
  true for the other classifications to apply.
* Kaggle -- ``dataset`` is applicable, because a Kaggle Dataset is a file bundle
  with a metadata file, which is what a distributable release is.

Each classification lists the evidence it is based on, so the answer is auditable
rather than asserted.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

#: Environment variable holding the Hugging Face write token.
HUGGINGFACE_TOKEN_ENV: Final = "HUGGINGFACE_TOKEN"  # noqa: S105 - a variable name
#: Environment variables holding Kaggle credentials.
KAGGLE_USERNAME_ENV: Final = "KAGGLE_USERNAME"
KAGGLE_KEY_ENV: Final = "KAGGLE_KEY"

#: Files that would prove a project carries model weights or dataset rows.
WEIGHT_SUFFIXES: Final = (".safetensors", ".bin", ".pt", ".pth", ".onnx", ".gguf", ".ckpt")
DATASET_SUFFIXES: Final = (".parquet", ".arrow", ".csv", ".jsonl", ".tsv")

#: Files that prove a *runnable application* for a Hugging Face Space.
#:
#: A Dockerfile is deliberately absent. A container image is not a Space: a Space
#: serves a web application, and shipping a CLI's Dockerfile as the proof would
#: claim an interface this project does not have. ``package.json`` and
#: ``index.html`` are included because a static front end is an application.
APP_MARKERS: Final = (
    "app.py",
    "streamlit_app.py",
    "server.py",
    "gradio_app.py",
    "package.json",
    "index.html",
)


@dataclass(frozen=True, slots=True)
class Classification:
    """What this project is, per platform, and on what evidence."""

    project_kind: str
    huggingface_kind: str
    huggingface_applicable: bool
    kaggle_kind: str
    kaggle_applicable: bool
    rationale: list[str] = field(default_factory=list)
    alternatives: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return the per-platform classification and its rationale."""
        return {
            "project_kind": self.project_kind,
            "huggingface": {
                "kind": self.huggingface_kind,
                "applicable": self.huggingface_applicable,
                "opt_in": self.huggingface_kind == "space",
            },
            "kaggle": {"kind": self.kaggle_kind, "applicable": self.kaggle_applicable},
            "rationale": list(self.rationale),
            "other_classifications_require": dict(self.alternatives),
        }


def classify_project(root: Path) -> Classification:
    """Classify the project at *root* from evidence on disk.

    Args:
        root: Path: Repository root to inspect; resolved before the walk, which
            skips ``.git``, ``.venv`` and ``node_modules``.
    """
    root = root.resolve()
    rationale: list[str] = []

    weights = _find_suffixes(root, WEIGHT_SUFFIXES)
    datasets = _find_suffixes(root, DATASET_SUFFIXES)
    app_markers = [name for name in APP_MARKERS if (root / name).is_file()]

    if weights:
        rationale.append(f"model weight files present: {', '.join(sorted(weights)[:5])}")
        project_kind = "model"
    elif datasets:
        rationale.append(f"dataset-shaped files present: {', '.join(sorted(datasets)[:5])}")
        project_kind = "dataset"
    else:
        rationale.append("no model weight files and no dataset-shaped files in the repository")
        project_kind = "code-repository"

    if app_markers:
        rationale.append(f"runnable application markers present: {', '.join(sorted(app_markers))}")

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        from opencode_toolkit.release.sbom import project_dependencies

        runtime, _ = project_dependencies(root)
        if not runtime:
            rationale.append(
                "pyproject.toml declares no runtime dependencies, consistent with a "
                "standard-library-only CLI rather than a model or dataset release"
            )

    if app_markers:
        hf_kind, hf_applicable = "space", True
        rationale.append(
            "runnable application entry point present: " + ", ".join(sorted(app_markers))
        )
    else:
        hf_kind, hf_applicable = "not_applicable", False
        rationale.append(
            "no Hugging Face Space entry point ("
            + "/".join(APP_MARKERS)
            + ") exists, and this project has no model or dataset to publish; "
            "publishing it as a Space or a Dataset without an application to serve "
            "would misrepresent it"
        )

    return Classification(
        project_kind=project_kind,
        huggingface_kind=hf_kind,
        huggingface_applicable=hf_applicable,
        kaggle_kind="dataset",
        kaggle_applicable=True,
        rationale=rationale,
        alternatives={
            "model": "would require trained weight files and a model card describing the architecture",
            "dataset": (
                "would require tabular row data and a dataset card with a documented schema; "
                "Kaggle 'dataset' is a file bundle, which is what the release artefacts are"
            ),
            "space": "would require a runnable application entry point and a Docker Space configuration",
        },
    )


def _find_suffixes(root: Path, suffixes: tuple[str, ...], *, limit: int = 40) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in _walk(root):
        dirnames[:] = [name for name in dirnames if name not in {".git", ".venv", "node_modules"}]
        for name in filenames:
            if name.endswith(suffixes):
                found.append(str(Path(dirpath, name).relative_to(root)))
                if len(found) >= limit:
                    return found
    return found


def _walk(root: Path) -> Iterator[tuple[str, list[str], list[str]]]:
    return os.walk(root)


def missing_credentials(*names: str, environ: Mapping[str, str] | None = None) -> list[str]:
    """Return the subset of *names* that are absent or empty in the environment.

    Values are never returned, only names -- a caller cannot accidentally log a
    token by using this helper.

    Args:
        *names: str: Environment variable names to test, in the order given.
        environ: Mapping[str, str] | None: Environment mapping to read from;
            defaults to :data:`os.environ`. Only the presence and non-emptiness
            of a name is inspected -- no value is returned or logged.
    """
    env: Mapping[str, str] = os.environ if environ is None else environ
    return [name for name in names if not env.get(name, "").strip()]


def credential_status(
    *,
    huggingface: bool = True,
    kaggle: bool = True,
    environ: Mapping[str, str] | None = None,
) -> dict[str, bool]:
    """Report credential availability by platform, without exposing values.

    Args:
        huggingface: bool: When ``True``, report whether
            ``HUGGINGFACE_TOKEN`` is set and non-empty.
        kaggle: bool: When ``True``, report whether ``KAGGLE_USERNAME`` and
            ``KAGGLE_KEY`` are set and non-empty.
        environ: Mapping[str, str] | None: Environment mapping to read from;
            defaults to :data:`os.environ`. The mapping is consulted only for
            presence -- no credential value is returned or logged.
    """
    env: Mapping[str, str] = os.environ if environ is None else environ
    status: dict[str, bool] = {}
    if huggingface:
        status["huggingface"] = not missing_credentials(HUGGINGFACE_TOKEN_ENV, environ=env)
    if kaggle:
        status["kaggle"] = not missing_credentials(KAGGLE_USERNAME_ENV, KAGGLE_KEY_ENV, environ=env)
    return status
