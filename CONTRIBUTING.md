# Contributing

The full guide lives in [`docs/development/contributing.md`](docs/development/contributing.md).
This file is the short version and the one GitHub shows on the repository root.

## Setup

```console
$ python -m venv .venv
$ source .venv/bin/activate
$ pip install -e ".[dev]"
$ pytest
```

## Before opening a pull request

```console
$ ruff format src tests scripts
$ ruff check src tests scripts
$ mypy
$ pytest
$ opencode security-audit src --strict
```

Or run the whole thing, which is what the release gate uses:

```console
$ ./scripts/quality-check
```

`scripts/quality-check` writes `.opencode/toolkit/release-gate.json` as it goes.
All thirteen checks run on any host with a Python interpreter — there is no
container or daemon in this project. A stage that still cannot run is recorded as
`NOT_RUN`, which blocks the gate rather than reporting a pass it did not earn.

## Changing the documented API

```console
$ opencode docs scan --path src --write-baseline \
      --baseline .opencode/toolkit/docs/baseline.json --force
$ git diff .opencode/toolkit/docs/baseline.json
$ opencode docs check --path src --baseline .opencode/toolkit/docs/baseline.json
```

Review that diff rather than accepting it: the baseline is what makes
documentation drift detectable, and regenerating it without reading it disables
the check.

## Adding things

- **A security rule** — see
  [contributing.md § Adding a security rule](docs/development/contributing.md).
  A rule needs both a positive and a negative fixture, and it will fire on the
  toolkit's own source until you either fix the code or record a reason.
- **A snippet** — see
  [docs/components/snippets.md](docs/components/snippets.md). Every field of the
  registry contract is required, including `source` and `security_notes`.
- **A CLI command** — one module in `src/opencode_toolkit/cli/commands/`, a
  `register` function, a `run_<name>` dispatcher, and tests in
  `tests/cli/test_cli.py`.

## Conventions

- Google-style docstrings on every public item. The docs gate enforces it.
- Prefer `pathlib` over `os.path`; `PTH` is enabled in Ruff.
- Raise a typed error from `core.errors` with a stable `code` and a `hint`,
  never a bare `Exception`.
- Never log a value that could be a credential. Route it through `core.redact`.
- Exit codes are a public contract; see
  [docs/development/exit-codes.md](docs/development/exit-codes.md).

## Commit messages

Conventional-prefixed, imperative mood, one logical change per commit:
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:`, `ci:`, `chore:`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
