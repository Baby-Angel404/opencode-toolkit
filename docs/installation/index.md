# Installation

## Requirements

- **Python 3.10 or newer.** Verified on CPython 3.11–3.14 on Linux, macOS and
  Windows.
- No compiler, no system libraries, no runtime dependencies. The toolkit is pure
  standard library.
- Git is optional. It is used to record the commit in the release gate; without it
  the gate still works and records an empty commit.

Python 3.10 is supported but not exercised in CI. It predates `tomllib`, so the
SBOM dependency reader falls back to a narrower parser there and `doctor` reports
a non-blocking warning. If you can, use 3.11 or newer.

## From PyPI

```console
$ pip install opencode-toolkit
$ opencode doctor
```

The runtime install pulls nothing else. If you want the development tool chain:

```console
$ pip install -e ".[dev]"
```

That adds `pytest`, `pytest-cov`, `ruff`, `mypy`, `pip-audit` and `build` — the
tooling the quality pipeline and the release gate use.

## From a source checkout

```console
$ git clone https://github.com/opencode-toolkit/opencode-toolkit
$ cd opencode-toolkit
$ python -m venv .venv
$ source .venv/bin/activate        # Windows: .venv\Scripts\activate
$ pip install -e ".[dev]"
$ opencode doctor
```

Running from the source tree without installing also works, because the CLI is a
module:

```console
$ PYTHONPATH=src python -m opencode_toolkit version
```

`scripts/quality-check` prefers `.venv/bin/python`, then an installed `opencode`,
then `PYTHONPATH=src`. A clean checkout needs no install step to run the pipeline.

## Running without installing

Nothing is needed. The runtime is standard library only, so a checkout is
runnable:

```console
$ git clone https://github.com/opencode-toolkit/opencode-toolkit
$ cd opencode-toolkit
$ ./opencode doctor
```

`./opencode` resolves an interpreter itself: the project `.venv` when the
package is installed there, an `opencode` already on `PATH`, otherwise `python3`
with the source tree on `PYTHONPATH`. On a host without any of those it prints
what is missing rather than failing silently.

This is the intended way to try the toolkit, and the way CI uses it for the
security audit: there is no build step that can be stale, and no install step
that can be skipped.

## Verifying an install

```console
$ opencode doctor --strict
$ opencode version
$ opencode security-audit . --strict
```

`doctor --strict` exits non-zero if any check fails. It reports the Python
version, the resolved configuration, workspace layout, available credentials
(presence only, never values), optional integrations, and the state directory.

## Optional accelerators

None of these are required. When present they are used automatically; when absent
the toolkit falls back and says so.

| Library | Effect if present |
|---------|-------------------|
| `cryptography` | AES-GCM instead of the default HMAC-SHA256-CTR construction for sync sealing. Same guarantees; see [the security model](../security/model.md). |
| `huggingface_hub` | A native upload path for Hugging Face instead of the HTTP API client. |
| `PyYAML` | Parses Hugging Face `README.md` front matter with a real YAML parser instead of the minimal reader. |

## Uninstalling

```console
$ pip uninstall opencode-toolkit
```

State under `.opencode/toolkit` is left in place; it is yours and may hold
snapshots. Remove it explicitly if you want it gone:

```console
$ rm -rf .opencode/toolkit
```

## Next steps

- [Configuration](../configuration/reference.md) — every key and its default
- [Architecture](../architecture/overview.md) — how the components fit together
- [Contributing](../development/contributing.md) — running the pipeline locally
