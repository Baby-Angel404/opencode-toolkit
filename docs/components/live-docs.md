# Live docs

Detects when the code and its docstrings disagree, and repairs only the part of a
docstring the tool owns.

```console
$ opencode docs scan --path src
$ opencode docs check --path src
$ opencode docs diff --path src
$ opencode docs update --path src
$ opencode docs scan --path src --write-baseline
```

## The design problem

Auto-generating docstrings is easy and mostly produces noise: `:param x:` lines
restating the signature, prose nobody wrote, and a diff too large to review. The
result is worse than no documentation, because it looks documented.

So this tool inverts the usual approach. It **never writes prose**. It rewrites
exactly two machine-owned blocks — `Args:` and `Returns:` — and only when they
already exist. Everything else is preserved byte for byte: the summary line,
extended prose, `Raises:`, `Example:`, `Note:`, section ordering, blank lines.

The governing rule is: **if a rewrite would touch a line the tool does not own,
the file is not rewritten at all.** The file is reported as `needs_review` with
the reason. That is a deliberate trade of coverage for reviewability — some
docstrings will not be updated, and each one that isn't is named in the output
rather than silently skipped.

## What counts as the public API

For Python, a module-level name that does not start with `_`, plus public methods
of public classes. A leading-underscore name listed in `__all__` is public, since
`from module import _helper` is legal and `from module import *` will include it.

The receiver (`self` or `cls`) is not a documented parameter. Google-style
docstrings omit it, so treating its absence as drift would report every
well-written method in the codebase.

For JavaScript, TypeScript and Go, extraction uses bounded line patterns rather
than a real parser. Results from those languages are marked `heuristic=True` and
are never treated as authoritative — a signature reconstructed from a regex can be
wrong, and the drift report says which entries came from a heuristic so you know
which to double-check.

## The baseline

`docs check` compares the scanned surface against a baseline document:

```console
$ opencode docs scan --path src --write-baseline
```

An existing baseline is never replaced without `--force`. Overwriting one is how a
real drift report gets silently accepted, so it has to be a deliberate act with
`docs diff` reviewed first.

Without `--baseline`, the path is derived from the scanned root: `--path src`
resolves to `src/.opencode/toolkit/docs/baseline.json`. This project's baseline is
at the repository root, so pass it explicitly:

```console
$ opencode docs scan --path src --write-baseline \
      --baseline .opencode/toolkit/docs/baseline.json
```

With **no** baseline, every public item is reported as `added`. The report says so
explicitly rather than reporting zero drift, which would read as "everything is
documented" when nothing has actually been compared.

The baseline is committed to the repository. Without it in CI, `docs check`
reports the whole surface as new and the release gate fails for a reason that has
nothing to do with the code.

## Drift kinds

| Kind | Meaning | Blocks? |
|------|---------|---------|
| `added` | A public item the baseline does not know about. | yes |
| `changed` | A signature that no longer matches the baseline. | yes |
| `undocumented` | No docstring, or one that omits parameters. | yes |
| `removed` | A public item that is gone. | no |

`removed` is informational because deleting code is usually deliberate. The other
three block: each means the documented surface no longer matches the code, or that
a public function has no description — the exact failure this tool exists to
prevent.

## Parameter matching

A parameter counts as documented when its name appears in an `Args:` block.
Matching tolerates both spellings of a variadic: `args` or `*args`, `kwargs` or
`**kwargs`. An author may write either, and both are correct.

For functions that were never documented at all, the report lists them under
`undocumented` with the message "public item has no docstring". That is not
something `docs update` can fix — writing a summary line is prose, and this tool
does not write prose.

## Configuration

```json
{
  "docs": {
    "docstring_style": "google",
    "require_docstrings_for_public": true,
    "check_cli_commands": true
  }
}
```

`require_docstrings_for_public` set to `false` stops a missing docstring from
blocking, leaving only signature drift. Turning it off is a decision to ship
public functions without descriptions; it is not a default.

## Reviewing a change

```console
$ opencode docs diff --path src
$ opencode docs update --path src --dry-run
$ opencode docs update --path src
$ opencode docs check --path src
```

`update` reports per file: `updated`, `unchanged`, or `needs_review` with the
reason. A file that lands in `needs_review` needs a human, and the reason names
the check that refused it.

## Known limitation in ReDoS reporting

The security auditor's ReDoS rule reports a pattern **shape** — a nested unbounded
quantifier over a non-disjoint body — not a measured slowdown. No input is ever
timed.

Its structural test treats a group body containing a mandatory literal character
as safe, because a required non-class character anchors every partition. That
makes `(-\w+)` safe and `(a+)` vulnerable, which is the right distinction. It
cannot see quantifier *ranges*, so `(\w{0,2}\w+)` — a bounded pattern — is still
reported, at `MEDIUM` confidence, for that reason.

The practical consequence: a ReDoS finding is a prompt to look at the pattern,
not a claim that a slow input exists.
