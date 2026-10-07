# Exit codes

Exit codes are part of the public contract. Scripts, CI jobs and the release
gate branch on them, so the mapping is stable and defined once, in
`src/opencode_toolkit/core/exit_codes.py`.

| Code | Name | Meaning |
|------|------|---------|
| 0 | `ok` | The command did what was asked. |
| 1 | `failure` | A required check ran and reported at least one failure. |
| 2 | `usage` | The command line itself was wrong: unknown command, bad arguments. |
| 3 | `config-error` | The tool refused to start because configuration or the environment is invalid. |
| 4 | `io-error` | Missing file, permission denied, or corrupt state. |
| 5 | `conflict` | A conflict was detected and nothing was overwritten. |
| 6 | `integrity-error` | A checksum, signature or tamper check failed. |
| 7 | `network-error` | A network operation failed and no offline path was available. |
| 130 | `interrupted` | SIGINT or `KeyboardInterrupt`. |

```console
$ opencode doctor --format json | python -c 'import json,sys; print(json.load(sys.stdin)["summary"])'
```

`opencode version` and the JSON reports carry the same names, so a human reading a
log and a script branching on `$?` see the same meaning.

## Which code a command returns

Every command maps its outcome onto these. The distinctions that matter:

**`failure` versus `usage`.** `1` means the tool ran and something was wrong
with the world — a finding above the threshold, a test that failed. `2` means the
tool never got that far: the command does not exist, or the flags do not parse.

**`config-error` is not `usage`.** A configuration file with a bad value is
`3`, not `2`. The command line was fine; the tool refused to start rather than
run with a policy the operator did not intend.

**`conflict` is not `failure`.** `5` specifically means the tool detected a
conflict and did not overwrite anything. A caller can therefore distinguish "I
refused because you would lose work" from "the work failed".

**`integrity-error` is not `io-error`.** A file that does not match its checksum
is `6`, not `4`. The bytes are readable; they are simply not what they claim to
be, and a script may want to react differently than to a missing file.

**`network-error` versus queuing.** `7` means the operation failed *and* no
offline path existed. When the toolkit can queue the operation instead — an
unreachable sync remote — it does so and reports success, because the work was
accepted rather than lost. The queued operation is visible in
`opencode sync status`.

## Interpreting `0`

`0` means the command's own criteria were met. For a gated command that is
narrower than "everything is fine":

- `opencode security-audit . --strict` returns `0` when no finding reached
  `security_audit.fail_on`, not when the tree is free of every possible issue.
  The default threshold is `critical` and `high`.
- `opencode publish ...` returns `0` only after an **approved** gate and a
  **verified** remote state. An upload that completed but could not be confirmed
  returns `6`, so it cannot be mistaken for a release.
- `opencode sync restore --force` returns `0` when the forced restore worked. The
  forced paths are reported separately from a clean restore in the `forced` field
  and in the text output, so a caller that cares can check.
- `opencode pack verify` returns `0` only when every declared digest matched,
  every archived file was declared, and the manifest's content digest agreed.

## In shell scripts

```bash
opencode sync restore "$tag" --passphrase-env SYNC_PASSPHRASE
case $? in
  0) echo "restored" ;;
  5) echo "conflicts present; nothing was overwritten" ;;
  6) echo "integrity check failed; do not use this state" ;;
  *) echo "failed with $?" >&2; exit 1 ;;
esac
```

Do not parse `--format json` output to recover an exit code. The exit code is the
supported signal; the JSON is for reading the detail, and its shape may grow
fields without that being a contract change.
