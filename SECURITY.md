# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

Use GitHub's private reporting form: **Security → Report a vulnerability** on this
repository. If that is unavailable to you, open an issue that says only that you
have found a security problem and request a private channel — do not include
details in the issue body.

Include what you can: the affected component, the version or commit, the inputs
that reproduce it, and the impact you observed. A reproduction is worth more than
a hypothesis.

## What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement | 3 business days |
| Triage and severity assessment | 7 business days |
| Fix or mitigation plan | 14 business days from triage |
| Release | Coordinated with you, before public disclosure |

We will tell you when a report is a duplicate or out of scope, and why.

## Supported versions

The most recent released version. There is no long-term-support branch; fixes
land on `main` and ship in the next release.

## Scope

In scope:

- Anything in `src/opencode_toolkit/` that weakens a documented guarantee: the
  scanner missing a detection it claims to make, encrypted snapshots readable
  without the passphrase, secret values reaching a report, log line, or artefact,
  the release gate reporting APPROVED when a required check did not pass, or
  publishing reaching the network without an approved gate.
- The GitHub Actions workflows in `.github/workflows/`, and anything a user wraps the CLI in.

Out of scope:

- Findings that require an attacker who already controls the host, the Python
  interpreter, or the repository's CI configuration.
- Denial of service from intentionally scanning a hostile tree with no resource
  limits; that is a documented property, and hardening it is a feature request.
- Missing hardening headers on a CLI that serves no HTTP.
- Reports with no reproduction, from an automated scanner with no triage.

## What the project already guarantees

These are enforced by tests in `tests/security/`, not just asserted here:

- Encrypted snapshot blobs are sealed and authenticated; a blob is rejected if
  its authentication tag fails **or** its content does not match its digest.
  Neither check can be skipped.
- Findings carry a SHA-256 fingerprint of a secret, never the secret itself, and
  the same holds for logs, reports, and the publication staging directory.
- DSN and URL credentials are redacted from error messages and log lines.
- The release gate requires an explicit `PASS` for every mandatory check.
  `NOT_RUN` blocks the release exactly as a failure does, so a stage that could
  not run can never be mistaken for one that passed.
- The publish workflows reach the network only from a job that a prior approved
  gate unblocked. There is no flag or override that bypasses it.
- Publishing credentials are read from the environment. No credential value is
  written into a workflow, a build argument, or a commit.

## Credential exposure

If you discover a credential in this repository or in its history: revoke and
rotate it first, then report it. Deleting the commit does not undo the exposure;
rotation does.
