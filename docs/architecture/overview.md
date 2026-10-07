# Architecture

## Overview

OpenCode Toolkit is six components behind one CLI, sharing a core. Each component
owns its own storage layout, its own failure vocabulary, and its own tests. They
communicate through files and JSON documents, never through each other's internals.

```
                       ┌──────────────────────────────┐
                       │            CLI               │
                       │  opencode <command> [flags]  │
                       └───────────────┬──────────────┘
                                       │  CliContext
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
   ┌──────────▼─────────┐  ┌───────────▼──────────┐  ┌──────────▼─────────┐
   │   security_audit    │  │     workflow_sync    │  │  snippet_verified  │
   │  rules, AST, ReDoS  │  │  crypto, store, diff │  │  registry, install │
   └──────────┬─────────┘  └───────────┬──────────┘  └──────────┬─────────┘
              │                        │                        │
   ┌──────────▼─────────┐  ┌───────────▼──────────┐  ┌──────────▼─────────┐
   │    orchestrator     │  │     offline_pack     │  │      live_docs     │
   │  graph, executor    │  │  builder, manifest   │  │  scanner, drift    │
   └──────────┬─────────┘  └───────────┬──────────┘  └──────────┬─────────┘
              │                        │                        │
              └────────────────────────┼────────────────────────┘
                                       │
   ┌───────────────────────────────────▼───────────────────────────────────┐
   │                              core                                     │
   │  config · errors · fsio · jsonio · logging · redact · paths ·        │
   │  timeutil · version · exit_codes · pyproject                         │
   └─────────────────────────────────────���─────────────────────────────────┘
                                       │
                        ┌──────────────▼──────────────┐
                        │  release · publishing       │
                        │  gate, artifacts, sbom,     │
                        │  classify, HF, Kaggle       │
                        └─────────────────────────────┘
```

## Design rules

These are the constraints every component is written against. They explain most of
the code's shape.

**The runtime has no third-party dependencies.** Every capability is built on the
standard library. This makes clean-checkout installs deterministic, makes the
offline pack honest about what it contains, and removes third-party
redistribution questions from published artefacts. Optional accelerators
(`cryptography`, `huggingface_hub`, `PyYAML`) are imported lazily behind
availability checks and are never required.

**Failures are typed and carry a machine-readable code.** Every error crossing a
component boundary is a `ToolkitError` subclass with a stable `code`, a fixed
`exit_code`, a `details` mapping, and an optional `hint`. Scripts branch on the
code; humans read the hint.

**Nothing is silently degraded.** A stage that cannot run is `NOT_RUN`, which
blocks the release gate exactly as a failure does. A missing baseline, an absent
credential, an unreachable transport: each reports itself rather than proceeding
as if it had succeeded.

**Writes are atomic and guarded.** Every file the toolkit writes goes through
`fsio`, which writes to a temporary file in the same directory, `fsync`s, sets
explicit permissions, and renames. A crash mid-write leaves the previous content
intact. Guarded writes additionally verify the file is unchanged since it was
read.

**Secrets never reach output.** `core.redact` is the single path for turning a
possibly-sensitive value into something safe to print. Findings carry a SHA-256
fingerprint of a secret, never the secret. This is enforced by tests, not by
convention.

## Component boundaries

Each component exposes its types from `__init__.py` and keeps its implementation
modules private. Other components import from the package, never from a sibling's
internals — a check in `tests/integration` enforces this.

### core

Configuration loading and validation, the error hierarchy, atomic filesystem
operations, canonical JSON I/O, redacting logging, path and state-directory
resolution, timestamps, version parsing, exit codes, and the `pyproject.toml`
reader. Everything else depends on `core`; `core` depends on nothing.

### security_audit

Rule definitions with CWE references and remediation text, an AST-based Python
analyser, pattern analysis for JavaScript, TypeScript and Go, ReDoS shape
detection, secret detection with fingerprinting, and three report renderers.
Findings are plain data with a fingerprint instead of a secret value.

### workflow_sync

PBKDF2-HMAC-SHA256 key derivation, encrypt-then-MAC sealing with HMAC-SHA256-CTR,
content-addressed encrypted blobs, three-way snapshot diffing, conflict planning,
an offline queue, and a local-directory transport.

### snippet_verified

A registry contract, validation of every entry against it, search, installation
into a target file, and verification that the installed text is still present.

### orchestrator

Task and plan models, a role-and-capability map, DAG construction with cycle
detection and duplicate-write detection, null/command/recording executors,
checkpoints with a journal, and a coordinator that resumes.

### offline_pack

Deterministic pack construction, a manifest with per-file checksums and a content
digest, licence decisions for third-party dependencies, incremental manifest
refresh, and full verification on read.

### live_docs

An API surface scanner (Python AST, `__all__`-aware), baseline documents, drift
detection, and a conservative docstring updater that rewrites only the parameter
blocks it owns.

### release and publishing

The fourteen-check gate and its decision logic, artefact assembly with checksums
and a CycloneDX SBOM, changelog generation, and platform publishing. Publishing
classifies the project first and refuses when a platform has no honest
representation for it.

## State layout

State lives under the state directory, which is `.opencode/toolkit` inside the
workspace by default, overridable with `--state-dir` or
`OPENCODE_TOOLKIT_STATE_DIR`.

It is per project by design, with no `$XDG_STATE_HOME` fallback. An XDG location
is machine-wide; putting the snapshot index and encrypted project content there
would let one repository read another's snapshots.

```
.opencode/toolkit/
├── release-gate.json        the fourteen-check gate
├── docs/baseline.json       the documentation baseline
├── snapshots/               sync snapshots and encrypted blobs
├── queue/                   offline operations awaiting a remote
├── orchestrator/            checkpoints and journals
├── packs/                   built pack manifests
└── logs/                    rotating redacting logs
```

## Request flow

A single invocation, using `security-audit` as the example:

1. `cli.main` parses arguments, builds a `CliContext` (workspace, state
   directory, config, output format, logger), and dispatches to the command
   handler.
2. The handler resolves its inputs, translating invalid input into a `UsageError`
   with the offending value in `details`.
3. The component runs. Any `ToolkitError` propagates unchanged.
4. The handler renders the result: JSON through `emit_json`, text through the
   component's renderer.
5. `cli.main` catches `ToolkitError`, prints `message`, `details` and `hint` to
   stderr, and returns the error's `exit_code`.

Exit codes are constants in `core.exit_codes`, shared by the CLI, the scripts and
the workflows so that a CI job and a human see the same meaning.
