# Security model

This document describes what the toolkit defends against, how, and — as
importantly — what it does not defend against. Claims here are backed by tests in
`tests/security/`; the section on verification names the tests.

## Threat model

The toolkit assumes:

- **The repository is yours to scan**, and the tree may contain hostile content:
  a vendored dependency, a generated file, a contributor's patch.
- **Filesystem state can be lost**, partially written, or restored from an older
  backup.
- **The remote may be absent, stale, or hostile.** A synced snapshot directory
  could be a shared folder you do not fully control.
- **You may choose a weak passphrase.** Crypto that only works when the operator
  behaves is not a guarantee.
- **An attacker may read your logs, your CI output, and your artefacts.** These
  are routinely copied into tickets and chat.

The toolkit does **not** assume:

- That an attacker who already controls your Python interpreter, your CI
  configuration, or your shell is a threat it can address.
- That the machine is free of other local users. File permissions are set
  narrowly (0600 for secrets, 0644 for public data) but this is not a defence
  against root.
- That a scanner can prove the absence of a vulnerability. A clean audit means
  "no rule in this catalogue fired", not "this code is safe".

## Guarantees

### 1. Encrypted snapshots are authenticated

**Guarantee.** A sealed snapshot or blob cannot be read or modified without the
passphrase. Tampering is detected, not silently decrypted into wrong plaintext.

**How.** Encrypt-then-MAC: HMAC-SHA256-CTR with independent sealing and MAC keys,
both derived from the passphrase. The MAC covers a versioned header, the salt and
the nonce as associated data, so an attacker cannot move ciphertext between
payloads or replay an old one. PBKDF2-HMAC-SHA256 at 600 000 iterations derives
the keys from a per-payload random salt.

Two independent checks guard a blob: the authentication tag must verify, **and**
the decrypted content must match the SHA-256 digest in its filename. Neither can
be skipped. The tag catches an attacker who modified the ciphertext; the digest
catches a store that produced the wrong bytes in the first place.

**Tests.** `tests/unit/test_crypto_sync.py` covers wrong-passphrase rejection,
bit-flip rejection, cross-payload nonce substitution, digest mismatch, and the
snapshot-blob confidentiality test that asserts plaintext never appears in a
sealed blob on disk.

**Known limits.** The default construction is HMAC-SHA256-CTR rather than a
standard AEAD, because the runtime has no third-party dependencies and
`cryptography` may be absent. AES-GCM is used automatically when the library is
importable; it is a performance and standard-compliance improvement, not a
security upgrade — the default path is the encrypt-then-MAC construction above.
There is no recovery path for a lost passphrase, by design. A memory-resident
passphrase can be read by an attacker with process access; the toolkit mitigates
by never persisting it.

### 2. Secret values never reach output

**Guarantee.** No report, log line, error message or published artefact contains a
secret value. A finding identifies a secret by SHA-256 fingerprint, which supports
correlation without disclosure.

**How.** Secret-bearing files are written `0600` and the directories holding them
`0700`, so another local user cannot read them or even list what is there.

**Platform note.** That guarantee is POSIX. On Windows `os.chmod` only toggles the
read-only flag, so `stat.S_IMODE` reports `0o666` for any writable file and an
owner-only mode cannot be expressed at all. The toolkit still requests `0600`
wherever it can, and `opencode doctor` reports the platform's fsync and
permission semantics rather than assuming them. Confidentiality on Windows rests
on ACLs, so a deployment there should set them on the state directory; the tests
that assert the owner-only mode skip themselves on `nt` instead of pretending the
bit is present.

`core.redact` is the only sanctioned path from a possibly-sensitive value
to something printable. The scanner stores the fingerprint at detection time and
discards the value before constructing a finding. DSN and URL credentials are
redacted in error paths. The publication staging directory is scanned with the
same detector before upload.

**Tests.** `tests/security/test_security.py` plants realistic credentials in
fixtures and asserts they are absent from the JSON, text and SARIF renderings, from
log output, and from `clean_publish_directory` results.

**Known limits.** A fingerprint is not reversible, but it is stable: two reports of
the same secret share a fingerprint, so a report is correlatable. That is the
intended trade. A secret *value* that is also a substring of a legitimate value
may be over-redacted; the goal is a report that is safe to share, and that is the
side to err on.

### 3. Destructive operations are conflict-guarded

**Guarantee.** A restore never silently overwrites a locally modified file. A
forced restore reports itself as forced and is distinguishable in the output.

**How.** A three-way diff between the base snapshot (the last-applied pointer), the
current working tree and the incoming snapshot classifies each path as added,
unchanged, modified, deleted or conflicted. Conflicted paths block the restore
unless `--force` is given, and the report records `forced` separately from
success so a caller can distinguish the two.

**Tests.** `tests/unit/test_crypto_sync.py` and
`tests/integration/test_cross_component.py` cover the conflict matrix, including
the case where a file changed identically on both sides (which is not a conflict)
and the case where the last-applied pointer is missing (which degrades to
reporting everything rather than assuming a clean tree).

A push transfers the sealed manifest *and* the content blobs it references. Only
sending the document would leave a remote that exists but cannot be restored
from, so the transport reads the manifest to learn what else must travel — which
is why `sync push` needs the passphrase for an encrypted snapshot, the same as
`sync save`.

**Known limits.** Content comparison is by hash, so a file whose content changed
and returned to the original is treated as unchanged. That is correct for the
purpose. A one-sided edit — only the working tree changed, or only the incoming
side changed — is not a conflict and is resolved in favour of whichever side
moved; only a path that moved on *both* sides blocks a restore.

### 4. The release gate cannot be satisfied by absence

**Guarantee.** Publishing requires an explicit `PASS` for all fourteen mandatory
checks. A stage that could not run is `NOT_RUN`, which blocks exactly as a failure
does.

**How.** `release.gate` records a status per check. Only `PASS` satisfies a
required check; `NOT_RUN`, `FAIL`, `SKIP` and a missing entry are all blocking
unless explicitly listed in `allow_skip`. `scripts/quality-check` writes the gate
as each stage completes, so a crashed pipeline leaves an incomplete gate rather
than a permissive one.

**Tests.** `tests/unit/test_release.py` asserts that `NOT_RUN` blocks, that a
skipped check blocks unless allow-listed, and that a missing check blocks. The
`release.yml` workflow calls `ci.yml` and `security.yml` as reusable workflows
rather than trusting that they ran.

**Known limits.** The gate records what the pipeline reported. It cannot detect a
pipeline that was modified to report success. That is what review is for.

### 5. Publishing is gated by construction

**Guarantee.** The publish workflows reach the network only from a job that an
approved gate unblocked.

**How.** `release.yml` assembles the gate, then calls `huggingface.yml` and
`kaggle.yml` as reusable workflows with `needs: [validate, release]`. A job cannot
depend on a job in a different workflow file, so the ordering is expressed by
calling those files — not by a comment. The publish jobs download the approved
gate document, and `scripts/publishing/*.sh` re-check it with
`release preflight` before any network call. There is no flag to bypass it.

**Tests.** `tests/security/test_security.py` asserts that no workflow contains a
cross-file `needs:` that GitHub would reject, and that no credential-shaped value
appears in a workflow file.

**Known limits.** A repository administrator can edit the workflow. The control is
against accident and against an automated path, not against an adversary with
write access to `.github/`.

### 6. The scanner audits its own source

**Guarantee.** `opencode security-audit src --strict` is part of the release
gate, and intentional suppressions are recorded rather than hidden.

**How.** The self-audit runs over `src/` in the quality pipeline. Findings at or
above the threshold fail the stage unless the specific rule and file are listed in
the self-audit allow-list, which is data in `.opencode/toolkit/config.json` and is
covered by a test asserting each entry is a real finding rather than a stale one.

**Tests.** `tests/integration/test_cross_component.py::test_shipped_toolkit_audits_itself_clean`.

**Known limits.** A rule that does not exist cannot fire. The catalogue is 45 rules
covering the common classes (injection, secrets, crypto misuse, path traversal,
unsafe deserialisation, TLS verification, CORS, prototype pollution, ReDoS); it is
not a proof of absence.

## Scanner coverage

45 rules across 30 distinct CWE references:

| Language | Rules |
|----------|-------|
| Python | 25 |
| JavaScript | 23 |
| TypeScript | 23 |
| Go | 17 |

By severity: 7 critical, 19 high, 17 medium, 1 low, 1 informational.

Python analysis is AST-based, so it resolves imports and call targets rather than
matching text — `subprocess.run(cmd, shell=True)` is found regardless of how
`cmd` was built. JavaScript, TypeScript and Go use pattern analysis, which is
inherently less precise: a pattern match reports a location for human review and
is not proof of exploitability. ReDoS detection looks for nested unbounded
quantifiers and reports the shape, not a measured slowdown.

## Reporting a vulnerability

See [SECURITY.md](../../SECURITY.md).
