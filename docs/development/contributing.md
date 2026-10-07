# Contributing

## Setup

```console
$ python -m venv .venv
$ source .venv/bin/activate
$ pip install -e ".[dev]"
$ pytest
```

## The quality pipeline

`scripts/quality-check` runs every stage the release gate requires and writes
`.opencode/toolkit/release-gate.json` as it goes.

```console
$ ./scripts/quality-check              # everything
$ ./scripts/quality-check --fast       # skip the slow stages
$ ./scripts/quality-check --list       # show the stages without running them
```

All thirteen checks run on any host with a Python interpreter — there is no
container, no daemon and no service. A stage that still cannot run is recorded as
`NOT_RUN`, which blocks the gate exactly as a failure does, rather than the
pipeline reporting a pass it did not earn.

For a fast inner loop, run the individual stages:

```console
$ ruff check src tests scripts
$ ruff format --check src tests scripts
$ mypy
$ pytest -m unit
$ pytest -m integration
$ pytest -m cli
$ pytest -m security
```

## Project layout

```
src/opencode_toolkit/
├── core/            config, errors, fsio, jsonio, logging, redact, paths, …
├── security_audit/  rules, Python AST analysis, patterns, ReDoS, reports
├── workflow_sync/   crypto, snapshots, blobs, conflicts, queue, transport
├── snippet_verified/ registry, validation, installation
├── orchestrator/    graph, executors, coordinator, checkpoints, journal
├── offline_pack/    builder, manifest, licences, verification
├── live_docs/       scanner, drift, conservative updater
├── release/         gate, artifacts, checksums, sbom, changelog, version
├── publishing/      classification, staging, secret scan, HF, Kaggle
└── cli/             argument parsing, context, command handlers
```

`core` depends on nothing. Every other component depends on `core` and on the
standard library. Components never import each other's internals — import from the
package's `__init__.py`, which is what the public API is.

## Adding a security rule

1. Add a `Rule` to `src/opencode_toolkit/security_audit/rules.py` with a stable
   `id` (`OCSA-<CATEGORY>-<NNN>`), a severity, the languages it applies to, a
   one-line summary, the failure mechanism, the impact, a remediation, and CWE
   references. A rule that cannot explain *why* it matters does not belong here.
2. If it needs more than a pattern, add the analysis to the matching module:
   `py_ast.py` for Python, the pattern matcher for JavaScript/TypeScript/Go,
   `redos.py` for regex shapes.
3. Add a positive fixture in `tests/fixtures/vulnerable.py` that must fire.
4. Add a negative fixture in `tests/fixtures/safe.py` that must not fire. A rule
   without a negative test is a rule that will eventually cry wolf.
5. Run `pytest -m security`.

Two constraints are enforced and will fail your build otherwise:

- A new rule will fire on the toolkit's own source. Either fix the code, or add
  the rule to the self-audit allow-list in `.opencode/toolkit/config.json` with a
  reason. `tests/integration/test_cross_component.py` asserts each allow-list
  entry is a real finding, so a stale entry fails rather than lingering.
- If your rule adds a regex with nested unbounded quantifiers, the self-audit will
  report it as a ReDoS shape. Express optional whitespace as a character class
  rather than a quantified group, and keep `.*` bounded to a single line.

## Adding a snippet

Snippets live in `src/opencode_toolkit/snippet_verified/data/registry.json` and
must satisfy the registry contract: a stable id, a category, a status, the content
itself, provenance explaining where it came from and why it is trusted, and a
review date. Validation runs at load time, so a malformed entry fails on startup
rather than at install time.

## Adding a CLI command

1. Create `src/opencode_toolkit/cli/commands/<name>.py` with a `register`
   function that adds the parser, and a `run_<name>` dispatcher.
2. Set `parser.set_defaults(handler=run_<name>)`.
3. Handle the subcommand inside the dispatcher and raise `UsageError` for bad
   input — with the offending value in `details` and a `hint` explaining the fix.
4. Support `--format json` on anything that produces output.
5. Add a test in `tests/cli/test_cli.py`. The CLI tests invoke the real entry
   point, so they also cover argument parsing and exit codes.

## Code conventions

- Google-style docstrings on every public item; `mypy` is configured strictly and
  `ruff` selects `E W F I B C4 UP S SIM RET ARG PTH TID RUF`.
- `E501` is disabled with a documented reason in `pyproject.toml`: the formatter
  owns line length for code it can reflow, and the remaining hits are prose in the
  rule catalogue and source embedded in test fixtures.
- Prefer `pathlib` over `os.path`; `PTH` is enabled.
- Prefer a typed error over a bare `raise Exception`. Every error crossing a
  component boundary is a `ToolkitError` subclass with a stable `code`.
- Never log a value that could be a credential. Route it through `core.redact`.

## Tests

Markers: `unit`, `integration`, `cli`, `security`, `regression`. `pytest -m unit`
runs the fast ones.

```console
$ pytest                              # everything
$ pytest -m security                  # the security guarantees
$ pytest --cov=opencode_toolkit --cov-report=term-missing
$ pytest --cov=opencode_toolkit --cov-fail-under=80
```

The security tests are the ones that back the claims in
[the security model](../security/model.md). If you change behaviour that a claim
depends on, change the test that proves it — or the claim.

## Before opening a pull request

```console
$ ruff format src tests scripts
$ ruff check src tests scripts
$ mypy
$ pytest
$ opencode security-audit src --strict
```

If your change affects the documented API surface, regenerate the documentation
baseline and review the diff:

```console
$ opencode docs scan --path src --write-baseline --force
$ git diff .opencode/toolkit/docs/baseline.json
$ opencode docs check --path src --baseline .opencode/toolkit/docs/baseline.json
```

## Commit and PR conventions

Commits are conventional-prefixed: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`chore:`, `build:`, `ci:`. Imperative mood, one logical change per commit.

A pull request should explain what changed and why, note anything a reviewer
cannot infer from the diff — a deliberate behaviour change, a security trade-off,
a new dependency — and confirm that `./scripts/quality-check` passes, or state
exactly which stage does not run on your machine and why.

## Licence

Apache-2.0. See [LICENSE](../../LICENSE).
