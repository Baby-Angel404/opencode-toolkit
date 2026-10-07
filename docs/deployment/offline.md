# Offline packs

An offline pack is a ZIP that carries the toolkit and everything needed to run it
on a host with no network: the package, its documentation, a manifest, per-file
checksums, and licence decisions for every third-party dependency it bundles.

The point is verifiable offline transfer. Anyone receiving the archive can confirm
it is byte-for-byte what the sender built, and can confirm which licences it
carries, without a network and without trusting the transfer channel.

## Building

```console
$ opencode pack build --output dist/opencode-toolkit-offline.zip
$ opencode pack inspect dist/opencode-toolkit-offline.zip
$ opencode pack verify dist/opencode-toolkit-offline.zip
```

Build is deterministic: the same source tree produces the same archive, byte for
byte. Entries are sorted, timestamps are fixed, permissions are normalised, and
the manifest records a content digest over the sorted per-file digests. Two builds
on different machines at different times are comparable.

## What is inside

```
manifest.json        the manifest: every entry with its size, mode and SHA-256
SHA256SUMS           the same digests in sha256sum format
INSTALL.md           install instructions and the licence notices
package/
├── pyproject.toml    package metadata
├── LICENSE
├── README.md
├── SECURITY.md
└── src/opencode_toolkit/…
```

Top-level metadata sits outside the `package/` directory so a consumer can read
the manifest without unpacking the source. Entries are attributed to a component
(`package`, `docs`, `metadata`) in the manifest, which is what makes
`--component` selection and the offline pack's per-component provenance work.

There is no installer script in the archive, deliberately: a script in a ZIP that
a recipient is told to run is an execution path the checksum manifest cannot
constrain. `INSTALL.md` gives the commands; you run them yourself.

## Verification

`pack verify` re-checks three things and reports each separately:

1. **Every declared digest matches the stored bytes.** A single modified file
   fails, and the failing path is named.
2. **Every file in the archive is declared in the manifest.** An undeclared extra
   file is an error, not a warning — an attacker who can write into the archive
   should not be able to add a file that verification ignores.
3. **The manifest's content digest matches.** This catches a manifest edited to
   match tampered contents.

Exit code `0` means all three passed. Anything else is non-zero and names what
failed.

```console
$ opencode pack verify dist/opencode-toolkit-offline.zip --json
```

`pack inspect` is the read-only summary: entry count, total size, content digest,
and the licence decisions, without verifying every digest. Use it to answer "what
is in this?"; use `verify` to answer "is this intact?".

## Determinism in detail

Two details make byte-identical rebuilds possible:

- **Fixed timestamps.** Every ZIP entry gets the same mtime, so the archive does
  not encode when it was built.
- **Sorted entries.** Files are emitted in sorted path order, so directory
  iteration order — which differs between filesystems — cannot leak in.

The content digest is computed over the sorted `(path, digest)` pairs. It is
therefore stable under rebuilds and changes if any file's content changes, without
changing if only the ordering of an unchanged tree differs.

## Dependencies and licensing

The runtime has no third-party dependencies, so a default pack bundles only
first-party code and the licensing question is simple. That is not an accident; it
is why the runtime is standard-library-only.

`pack.include_dependencies` can be set to bundle the development tool chain. When
it is, every package gets a licence decision:

```console
$ opencode pack licenses
```

Each entry states the SPDX identifier, whether redistribution is permitted, and
the notice that must ship. A package with no licence, or a copyleft licence in a
context that would require source disclosure, is marked `EXCLUDED` and is not
bundled. The decision and its reason land in `manifest.json` and in `INSTALL.md`,
so a recipient can see why a package is absent.

## Updating a manifest

If a pack's contents change without being rebuilt — for example after an
incremental transfer — regenerate the manifest rather than editing it by hand:

```console
$ opencode pack update dist/opencode-toolkit-offline.zip
$ opencode pack verify dist/opencode-toolkit-offline.zip
```

`pack update` re-emits the archive with a refreshed manifest and digest. It does
not change any file's content.

## Transferring

Verify after transfer, on the receiving host, not before sending:

```console
$ opencode pack verify opencode-toolkit-offline.zip
$ cd package && python -m pip install .
$ opencode doctor
```

If verification fails, the archive is not what the sender built. Do not install it.

## Using it as the source of an install

```console
$ unzip opencode-toolkit-offline.zip
$ cd package
$ python -m pip install .
$ opencode version
```

Or with no install at all:

```console
$ cd package
$ PYTHONPATH=src python -m opencode_toolkit version
```

The offline pack is what the `REPRODUCIBILITY` gate check installs in a clean
virtual environment:

```console
$ ./scripts/test/clean-environment-check.sh
```

That check creates a fresh virtual environment, installs the built
distributions, and runs the suite against the installed package rather than the
source tree. A packaging error that only appears after installation fails there,
not in a user's environment.
