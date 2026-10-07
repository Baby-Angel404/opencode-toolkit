# Examples

| File | What it is |
|------|------------|
| [`config.json`](config.json) | A fully populated configuration, with every key at its documented default. Copy it to `.opencode/toolkit/config.json` and edit. |
| [`plan-review-and-release.json`](plan-review-and-release.json) | An orchestration plan, exactly as `opencode orchestrator plan-example` emits it. |

## Using the configuration

```console
$ mkdir -p .opencode/toolkit
$ cp examples/config.json .opencode/toolkit/config.json
$ opencode doctor --format json
```

Every key is optional. Delete the ones you do not need; the documented default
applies. The file is strict JSON — no comments, no trailing commas — because the
same parser reads configuration, the release gate and the artefacts index, and
each of those must be machine-generated without ambiguity.

To try a value without editing the file:

```console
$ opencode security-audit . --format json
```

An invalid value is refused rather than corrected. `sync.kdf_iterations` below
the enforced floor of 100000 is a configuration error, not a value that gets
clamped, because silently using a stronger setting than you asked for hides a
mistake.

## Running the plan

```console
$ opencode orchestrator tasks examples/plan-review-and-release.json
$ opencode orchestrator run --plan examples/plan-review-and-release.json \
      --executor null --dry-run
```

which prints the dependency levels without touching anything:

```
dry run: plan 'example-release-check' is valid
  tasks   5
  depth   3
  level 0: plan
  level 1: implement
  level 2: document, security-review, test
```

`--executor null` plans and journals without executing anything, which is the
safe way to check that the dependency order and the declared write ownership are
what you intended before letting a real command run. See
[the contributing guide](../docs/development/contributing.md) for the executor
options.
