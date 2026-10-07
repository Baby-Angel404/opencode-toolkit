# Filesystem notes

Cross-platform behaviour the toolkit relies on, and the places where the guarantee
is weaker. Every item here is something that could otherwise surprise you on a
platform you did not test on.

## Atomic writes

Every file the toolkit writes goes through `core.fsio`, which:

1. creates a temporary file in the **same directory** as the target,
2. writes the content and `fsync`s the file handle,
3. sets explicit permissions,
4. `rename`s it over the target,
5. `fsync`s the **parent directory**.

Step 1 matters: a temporary file on a different filesystem cannot be renamed onto
the target, because `rename` is only atomic within one filesystem. Step 5 is what
makes the rename itself durable rather than merely atomic.

The consequence: a crash at any point leaves either the previous content or the
new content, never a half-written file. A crash *after* the rename but before the
directory `fsync` can, in the worst case, leave the old name pointing at nothing
on a filesystem that journals lazily — which is why step 5 exists.

### Windows

`os.replace` is atomic on Windows for a same-directory rename, so a reader never
sees a partial file. What is **not** available is opening a directory handle for
`fsync`, so step 5 is skipped.

| | Linux / macOS | Windows |
|---|---|---|
| Rename is atomic | yes | yes |
| Write is durable before rename | yes | yes |
| Rename is durable after rename | yes | **no** |
| Crash leaves partial file | no | no |
| Crash can lose the rename | no | **yes**, on a non-journaled filesystem |

`opencode doctor` reports this as a non-blocking warning on Windows rather than
passing silently.

## Permissions

Modes are set explicitly rather than inherited, because the process umask is not
a policy:

| Content | Mode |
|---------|------|
| Secrets (encrypted snapshots, blobs, queues, pointers) | `0600` |
| Public data (manifests, reports, documentation) | `0644` |
| Executable scripts | `0755` |
| Directories this toolkit creates | `0700` |

Directories are included deliberately. `0600` on the files inside a store protects
their contents, but a world-readable directory still reveals how many snapshots
exist and which blob digests they reference. `mkdir` applies the umask, so an
inherited `022` would leave the directory `0755` — the toolkit therefore sets the
mode explicitly on a directory it creates.

An **existing** directory is left alone. Narrowing one the operator created would
be surprising; widening one would be a security regression, so neither happens.

On Windows these modes are largely advisory; access control is the filesystem's
own ACL model. The narrow modes are a defence on POSIX, not a portable one.

## Case sensitivity and path comparison

Comparisons of relative paths are done on normalised POSIX-style strings with `/`
separators, so a report generated on Windows reads the same as one generated on
Linux. This means two files differing only in case are **distinct** to the
toolkit even on a case-insensitive filesystem. That is the safer error: a
collision is reported rather than silently merged.

## Symlinks

Three places deliberately do not follow symlinks:

- The security scanner (`security_audit.follow_symlinks` defaults to `false`).
  A scan that followed a link out of the tree could be redirected to read anything
  the invoking user can read, and would report findings about files that are not
  in the repository.
- The offline pack builder skips symlinks and records them as excluded.
- The secret scanner skips symlinked files for the same reason as the audit.

A symlink that points outside the scanned root is reported, so it is visible, but
its target is not read.

## Reserved names and long paths

Not handled specially. If you keep a repository on Windows, the usual constraints
apply to whatever you put in it: no `:` in a filename, no trailing dot or space,
and paths under 260 characters unless long-path support is enabled. The toolkit
does not rewrite or reject such paths.

## Network filesystems

Advisory file locks are not reliably honoured on NFS or SMB, so anything built on
them is best-effort. This matters for:

- `python-atomic-single-writer-queue`, which is marked **experimental** for exactly
  this reason;
- concurrent `opencode orchestrator run` invocations sharing one state directory.

The atomic write path itself remains correct on a network filesystem — `rename`
within one directory is atomic there too — but the *locking* around it is not
something this toolkit can promise.

## Temporary files

Every temporary file is created with `tempfile.mkstemp`, which opens with
`O_EXCL` — the file is created or the call fails, never truncated over an existing
one. There is no `mktemp`-style predictable-name path anywhere in the toolkit, and
the scanner reports one as `OCSA-PATH-003` (insecure temporary file) if it finds
one in a scanned tree.

On an ordinary failure the `except` handler removes the temporary file. A
`SIGKILL` or a power loss can leave one behind, since no handler runs. Those are
named `.tmp` and live beside their target, so `find <state> -name '*.tmp'` finds
them; the toolkit does not sweep them automatically, because a file matching that
pattern may be something you put there deliberately.

## What is not handled

- **Disk full during a write.** The write fails, the temporary file is removed, the
  original is untouched, and the error names the path. Partially recovered state
  is not attempted.
- **Concurrent writers to the same state directory.** Not locked. Two `sync save`
  runs against one store can interleave; the second's index write wins.
- **Clock skew.** Snapshot timestamps come from the local clock. Ordering between
  snapshots taken on different machines is therefore not reliable, which is why
  sync uses explicit tags rather than timestamps to order anything. `sync list`
  does sort by timestamp, so on a multi-machine store that order reflects clock
  skew rather than history.
- **Resolving the workspace root.** The root is the nearest ancestor containing
  `pyproject.toml` or `.git`. Running from a subdirectory of a larger repository
  finds the larger one; pass `--workspace` when that is not what you want.
