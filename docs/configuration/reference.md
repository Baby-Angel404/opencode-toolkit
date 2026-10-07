# Configuration reference

The toolkit reads one optional file, `.opencode/toolkit/config.json`, from the
state directory. Every key is optional: an absent file, an absent section, or an
absent key means the documented default applies.

```console
$ opencode doctor --format json     # shows the resolved configuration
```

Validation is strict. An unknown section, a wrong type, or a value outside its
enforced range is a `ConfigurationError` that lists every problem at once, not
just the first. The toolkit refuses to start on a partial configuration, because
running with half the intended policy is worse than not running.

## Discovery order

1. `--state-dir PATH`
2. `OPENCODE_TOOLKIT_STATE_DIR`
3. `<workspace>/.opencode/toolkit`

The workspace is `--workspace PATH`, else the nearest ancestor directory
containing `pyproject.toml` or `.git`.

State is **per project**, and there is no fallback to `$XDG_STATE_HOME`. An XDG
location is shared by every project on the machine, and this state holds the
snapshot index alongside encrypted project content — two unrelated repositories
sharing it would see each other's snapshot tags. Put the state on a shared
volume deliberately, with `--state-dir` or the environment variable, when
synchronising between machines is the intent.

## `config_version`

Integer, currently `1`. A configuration declaring a different version is
rejected rather than interpreted on a guess.

## `security_audit`

Controls `opencode security-audit`.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `include_extensions` | list of str | `.py .js .jsx .mjs .cjs .ts .tsx .go` | Which file extensions are analysed. |
| `exclude_dirs` | list of str | `.git .venv venv node_modules __pycache__ dist build .mypy_cache .pytest_cache .ruff_cache` | Directories never descended into. |
| `max_file_bytes` | int > 0 | `4000000` | Files larger than this are skipped, with the skip reported. |
| `follow_symlinks` | bool | `false` | When false, symlinks are reported but not followed, so a scan cannot be redirected outside the tree. |
| `fail_on` | list of str | `["critical", "high"]` | Severities that make the audit fail. |
| `ignore_rule_ids` | list of str | `[]` | Rule IDs to suppress. Each is reported in the self-audit output rather than silently applied. |
| `exclude_paths` | list of str | `[]` | Glob patterns matched against each file's path relative to the scanned root. A pattern also matches when the label *ends with* it, so `"/security_audit/rules.py"` works without naming the package. |

Raising `fail_on` to include `medium` is reasonable for a package about to be
published. Lowering it below `high` means the exit code no longer reflects the
finding; use `--format json` and enforce a threshold in your own tooling instead.

### Using `exclude_paths` honestly

An exclusion is a claim: "these files are not where a vulnerability would be, and
here is why." Every exclusion in this project's own configuration carries that
reason, and the reasons are of two kinds.

**A file must contain what it detects.** A rule catalogue needs an example of the
pattern it flags, and the ReDoS analyser needs the catastrophic shapes it is
built to recognise. Auditing those files reports the detector's own fixtures.

**A tree proves the detectors.** `tests/fixtures/vulnerable.py` contains
`shell=True`, `pickle.loads` and a literal credential deliberately, and each test
asserts that the corresponding rule fires. Auditing `tests/` therefore produces
around a thousand findings that are the suite working correctly.

```json
{
  "security_audit": {
    "exclude_paths": [
      "/security_audit/rules.py",
      "/security_audit/py_ast.py",
      "/security_audit/redos.py",
      "tests/*",
      "examples/*"
    ]
  }
}
```

What is **not** excluded, and why that matters: `src/`. The self-audit runs over
it with `--strict`, so any finding at or above the threshold fails the release
gate. An exclusion list that covered `src/` would make the check theatre.

## `sync`

Controls `opencode sync`.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `kdf_algorithm` | str | `pbkdf2-hmac-sha256` | The only implemented algorithm. Anything else is rejected rather than silently downgraded. |
| `kdf_iterations` | int ≥ 100000 | `600000` | PBKDF2 work factor. **The floor is enforced at 100000 and a lower value is a configuration error.** Raising it is the direct response to a weak passphrase. |
| `salt_bytes` | int | `16` | Per-payload KDF salt length. |
| `nonce_bytes` | int | `16` | Per-payload nonce length. |
| `encrypt_by_default` | bool | `true` | When true, saving requires a passphrase. `--no-encrypt` overrides per invocation and is recorded in the snapshot notes. |
| `redact_env_files` | bool | `true` | Redact credential-shaped assignments when `.env` files are captured. |

A configuration that lowers `kdf_iterations` is rejected, not clamped. Silently
using a stronger setting than the operator asked for hides a mistake; failing
makes it visible.

## `orchestrator`

Controls `opencode orchestrator`.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `max_parallel_agents` | int > 0 | `4` | Tasks executed concurrently within a level. |
| `task_timeout_seconds` | int > 0 | `1800` | Per-task timeout. |
| `max_task_retries` | int ≥ 0 | `2` | Retries after a failed task. |
| `require_ownership` | bool | `true` | Refuse a plan where two tasks declare the same write path. Two writers for one file is a race, not a feature. |
| `checkpoint_on_transition` | bool | `true` | Write a checkpoint at every status change, so a resumed run starts from the last observed state. |

## `pack`

Controls `opencode pack`.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `include_docs` | bool | `true` | Include `docs/` and `README.md` in the pack. |
| `include_dependencies` | bool | `false` | Bundle third-party dependencies. Off by default: bundling means redistributing, which needs a licence decision per package. |
| `exclude_patterns` | list of str | `*.pyc __pycache__/* .git/*` | Glob patterns excluded from the pack. |
| `verify_on_build` | bool | `true` | Re-verify every digest immediately after building. |

## `docs`

Controls `opencode docs`.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `docstring_style` | str | `google` | Section style the updater recognises. |
| `require_docstrings_for_public` | bool | `true` | Treat a missing docstring on a public item as blocking drift. |
| `check_cli_commands` | bool | `true` | Include CLI command handlers in the scanned surface. |

## `release`

Controls the release gate.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `require_reproducibility` | bool | `true` | `REPRODUCIBILITY` must be `PASS`. |
| `allow_prerelease` | bool | `false` | Permit a prerelease version to satisfy the gate. |

## Environment variables

| Variable | Effect |
|----------|--------|
| `OPENCODE_TOOLKIT_STATE_DIR` | Overrides the state directory. |
| `HUGGINGFACE_TOKEN` | Hugging Face publishing credential. Never logged. |
| `KAGGLE_USERNAME`, `KAGGLE_KEY` | Kaggle publishing credentials. Never logged. |
| `OPENCODE_<COMPONENT>_PASSPHRASE` | Passphrase source when a command takes `--passphrase-env`. |

## Validation example

```json
{
  "config_version": 1,
  "sync": { "kdf_iterations": 200000 },
  "security_audit": { "fail_on": ["critical", "high", "medium"] }
}
```

Every other key takes its default. With this file the gate still requires an
explicit `PASS` for `REPRODUCIBILITY`, because that setting only controls whether
the gate *asks*, never whether a missing answer passes.

There is no `require_docker` key. Every check in the gate runs on any host with a
Python interpreter, so there is nothing that "cannot run here" — which is what
makes a missing answer unambiguously a failure.
