# OpenCode Toolkit

A modular engineering toolkit for OpenCode projects: security auditing, encrypted
workflow sync, verified snippets, task-graph orchestration, verifiable offline
packs, and documentation drift detection — behind one CLI.

The runtime has **zero third-party dependencies**. It uses only the Python
standard library, which is what makes the offline pack honest and a clean-checkout
install deterministic. Development tooling (`pytest`, `ruff`, `mypy`, `pip-audit`,
`build`) lives in the `dev` extra.

### Run it straight from a checkout

No install, no virtualenv, no build step — the runtime is standard library only:

```console
$ git clone https://github.com/opencode-toolkit/opencode-toolkit
$ cd opencode-toolkit
$ ./opencode doctor
$ ./opencode security-audit . --strict
```

`./opencode` picks a working interpreter itself: the project `.venv` if the
package is installed there, an `opencode` already on `PATH`, otherwise `python3`
with the source tree on `PYTHONPATH`.

### Install it

```console
$ pip install opencode-toolkit
$ opencode doctor
$ opencode security-audit . --strict
```

## Requirements

Python 3.10 or newer. Verified on CPython 3.11–3.14 across Linux, macOS and
Windows. 3.10 is supported but not exercised in CI, because it predates
`tomllib` and the SBOM reader falls back to a narrower parser there.

## What each component does

| Component | Command | What it gives you |
|-----------|---------|-------------------|
| **Security audit** | `opencode security-audit` | Static analysis of Python, JavaScript, TypeScript and Go. 45 rules across CWE-mapped categories, ReDoS shape detection, and secret fingerprinting that reports a hash instead of the value. Text, JSON and SARIF output. |
| **Workflow sync** | `opencode sync` | Content-addressed snapshots with authenticated encryption, three-way conflict detection, and an offline queue for when the remote is unreachable. A push carries the sealed document *and* the blobs it references, so a pull on the other side can actually restore. Refuses to overwrite a conflict unless forced, and reports a forced restore as such. |
| **Verified snippets** | `opencode snippet` | 16 reviewed snippets, each validated against a contract before installation, with provenance and verification that a file still contains what was installed. |
| **Orchestrator** | `opencode orchestrator` | DAG task graphs with roles and capabilities, declared write ownership, per-task timeouts and retries, journalled checkpoints, and resume. Ships a null executor that plans without executing anything. |
| **Offline pack** | `opencode pack` | Deterministic ZIP builds with a manifest, per-file checksums, a content digest, and licence decisions for every third-party dependency. Byte-identical rebuilds; verification re-checks every digest. |
| **Live docs** | `opencode docs` | Detects drift between the code and its docstrings, and repairs only the parameter blocks it owns. A rewrite that would touch a human-owned line is reported for review instead. |

## Quick tour

```console
# What is wrong with this tree?
$ opencode security-audit . --strict

# Snapshot the working state, encrypted
$ opencode sync save --tag before-refactor --passphrase-env SYNC_PASSPHRASE

# What would a restore change, and where does it conflict?
$ opencode sync restore before-refactor --passphrase-env SYNC_PASSPHRASE --dry-run

# Install a reviewed snippet, then check it is still intact
$ opencode snippet add python-constant-time-compare ./src/auth.py
$ opencode snippet verify python-constant-time-compare ./src/auth.py

# Plan a multi-agent run without executing it
$ opencode orchestrator run --plan examples/plan-review-and-release.json \
      --executor null --dry-run

# Build a verifiable offline bundle
$ opencode pack build --output dist/opencode-toolkit-offline.zip
$ opencode pack verify dist/opencode-toolkit-offline.zip

# Is the documentation still true?
$ opencode docs check --path src
```

Every command accepts `--format json` for machine-readable output, and
`--dry-run` where a write would otherwise happen.

## No container, no daemon

This is a CLI, not a service, so the project carries no Dockerfile and no compose
file. There is nothing to build before you can run it, and nothing to keep
running.

That has a deliberate consequence for the release gate: **every one of its
thirteen checks runs on any host with a Python interpreter.** There is no check
that "cannot run here", so an unanswered question can never be confused with a
passed one. A stage that fails to run is recorded as `NOT_RUN` and blocks.

## Development

```console
$ python -m venv .venv && source .venv/bin/activate
$ pip install -e ".[dev]"
$ ./scripts/quality-check
```

`scripts/quality-check` runs every stage the release gate requires and writes
`.opencode/toolkit/release-gate.json` as it goes, so

```console
$ ./scripts/quality-check && opencode release preflight
```

is a real precondition rather than a ritual. A stage that cannot run is recorded
as `NOT_RUN`, which blocks the gate exactly as a failure does.

Individual stages:

```console
$ ruff check src tests scripts
$ ruff format --check src tests scripts
$ mypy
$ pytest
$ pip-audit --requirement requirements-dev.txt
```

## Release gate

A release requires an explicit `PASS` for all thirteen checks: `BUILD`, `FORMAT`,
`LINT`, `TYPECHECK`, `UNIT_TEST`, `INTEGRATION_TEST`, `CLI_TEST`, `SECURITY`,
`DEPENDENCY_AUDIT`, `SECRET_SCAN`, `DOCUMENTATION`, `PACKAGE`,
`REPRODUCIBILITY`.

```console
$ opencode release gate
$ opencode release preflight
$ opencode release artifacts
$ opencode release sbom --output dist/sbom.cdx.json
```

`release.yml` calls `ci.yml` and `security.yml` as reusable workflows, assembles
the gate from their results, and only then creates the release and calls the
publishing workflows. The publish jobs restore the approved gate document
themselves and re-check it before reaching the network. A job cannot depend on a
job in a different workflow file, so the ordering is expressed by calling those
files, not by a comment.

## Publishing

Publishing is gated, and gated by construction rather than by convention.

```console
$ opencode publish classify
$ opencode publish huggingface --namespace my-org --repo-id my-tool
$ opencode publish kaggle --slug my-org/my-dataset
```

Credentials come from the environment — `HUGGINGFACE_TOKEN`, `KAGGLE_USERNAME`,
`KAGGLE_KEY` — and their values are never logged or echoed. Hugging Face defaults
to `NOT_APPLICABLE` for a code-only repository: uploading a CLI as a Dataset
would misrepresent it, and the classifier says so instead of proceeding.

## Documentation

- [Architecture](docs/architecture/overview.md) — component boundaries and the data that flows between them
- [Configuration](docs/configuration/reference.md) — every key, its default, and why it exists
- [Installation](docs/installation/index.md) — pip, and running from a source checkout
- [Security](docs/security/model.md) — the threat model behind the guarantees above
- [Development](docs/development/contributing.md) — how to add a rule, a snippet, or a component
- [Contributing](CONTRIBUTING.md) — the short version GitHub shows on the repository root
- [Exit codes](docs/development/exit-codes.md) — the process exit contract
- [Filesystem notes](docs/development/filesystem-notes.md) — cross-platform behaviour and where the guarantees are weaker
- [Snippets](docs/components/snippets.md) and [Live docs](docs/components/live-docs.md) — the registry contract and the drift rules
- [Deployment](docs/deployment/offline.md) — building and verifying offline packs

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
