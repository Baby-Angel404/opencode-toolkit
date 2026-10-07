# Snippets

Sixteen reviewed snippets ship with the toolkit. Each is validated against the
registry contract before installation, carries provenance explaining why it is
trusted, and records what it was tested against and what can go wrong.

```console
$ opencode snippet list
$ opencode snippet search auth
$ opencode snippet inspect python-password-hashing-argon2
$ opencode snippet add python-constant-time-compare --path ./src/auth.py
$ opencode snippet verify python-constant-time-compare --path ./src/auth.py
```

## The registry contract

`src/opencode_toolkit/snippet_verified/data/registry.json` holds every snippet.
Validation runs at **load time**, so a malformed registry fails on startup rather
than at the moment someone installs from it. Each entry carries:

| Field | What it must say |
|-------|------------------|
| `id` | Stable kebab-case identifier; the filename is derived from it. |
| `language` | Which language the implementation is written in. |
| `version` | The snippet's own version, independent of the toolkit's. |
| `status` | `stable`, `experimental`, or `deprecated`. |
| `category` | Coarse grouping, listed below. |
| `summary` | One sentence: what it does. |
| `implementation` | The code that gets installed. |
| `source` | Where it came from, and why it is trusted. |
| `security_notes` | What the code does to stay safe, and what it does not protect against. |
| `edge_cases` | The inputs that make it behave surprisingly. |
| `maintenance_notes` | What a reviewer should re-check when it is edited. |
| `dependencies` | What must be installed alongside it, if anything. |
| `tested_against` | The versions this was exercised with. |

Every field is required. A missing one is a validation error, not a default —
"we did not record where this came from" is exactly the information a snippet
registry exists to prevent you from having to guess.

## What ships

| Snippet | Category | Status |
|---------|----------|--------|
| `python-password-hashing-argon2` | authentication | stable |
| `python-constant-time-compare` | authentication | stable |
| `typescript-jwt-verification` | authentication | stable |
| `python-argument-parser-guard` | authorization | stable |
| `yaml-least-privilege-service-account` | authorization | stable |
| `python-validating-deserializer` | validation | stable |
| `typescript-safe-html-render` | validation | stable |
| `python-error-boundary` | error-handling | stable |
| `go-graceful-shutdown` | error-handling | stable |
| `python-atomic-file-write` | file-io | stable |
| `python-atomic-single-writer-queue` | file-io | **experimental** |
| `python-httpx-timeout-client` | api-integration | stable |
| `python-config-from-environment` | configuration | stable |
| `shell-reproducible-install` | configuration | stable |
| `python-structured-logging` | logging | stable |
| `python-contract-test-fixture` | testing | stable |

### Why one is experimental

`python-atomic-single-writer-queue` is marked **experimental**. Its locking is
correct on a local filesystem and has no protection against a network filesystem
where the advisory lock is not honoured. `experimental` means: read
`maintenance_notes` before using it, and do not install it on a mount you do not
control. It is shipped rather than hidden because the notes explain the boundary
better than silence would.

## Installing

`snippet add` writes the implementation into a target file:

```console
$ opencode snippet add python-constant-time-compare --path ./src/auth.py
```

Before writing, the toolkit checks the target: an existing snippet with the same
id is replaced only when `--force` is given, and a conflicting definition is
reported rather than merged. Every write goes through the atomic writer, so a
crash mid-install leaves the previous file intact.

## Verifying later

```console
$ opencode snippet verify python-constant-time-compare --path ./src/auth.py
```

This answers a different question from "did the install succeed": *is the code
still there?* Three outcomes:

| Result | Meaning |
|--------|---------|
| `present and unmodified` | The body appears verbatim. |
| `present but modified` | The body was edited after installation. Not automatically wrong — many teams adapt a snippet — but worth knowing before you rely on the property it provides. |
| `not installed here` | The snippet is not in this file at all. |

"present" refers to the *snippet*, not the file: verifying against an unrelated
file reports `not installed here` rather than claiming your code drifted.

Text appended **after** the snippet does not count as a modification — the body
is still verbatim, which is the property that matters. Editing *inside* the body
is what `present but modified` reports, and that also notes when the provenance
header has been removed.

## Adding a snippet

1. Add an entry to `src/opencode_toolkit/snippet_verified/data/registry.json`
   satisfying every field of the contract above.
2. Write the `source` field as provenance a reviewer could act on: an upstream
   specification, a reference implementation, or a first-party decision with its
   reasoning. "Written by the author" is not provenance.
3. Write `security_notes` to include what the snippet does **not** protect
   against. Every security-relevant snippet here says so; a snippet with no
   limitations section is almost certainly missing one.
4. Add a test in `tests/unit/test_components.py` that loads the registry and
   exercises the install and verify cycle for your entry.

The registry loads at import time, so a mistake in your entry fails
`pytest` immediately rather than at someone's install.

## What a snippet is not

A snippet is **not** a dependency, a package, or a security control. It is a
reviewed starting point that has been read by a human. It does not receive
security updates, and the toolkit does not audit installed snippets against
anything. If you need a maintained implementation with an advisory channel, use
the dependency.
