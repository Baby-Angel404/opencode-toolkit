#!/usr/bin/env python3
"""Scan the repository and any build output for credential-shaped content.

Uses the toolkit's own scanner, so the rule set that CI enforces and the one a
developer runs locally are the same code path. Exits non-zero on any hit and
optionally records the result in the release gate.

Excluded: ``.gitignore`` (it lists credential *filenames* by design) and the
``tests/`` tree, which deliberately contains realistic fake credentials to prove
the detectors fire.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from opencode_toolkit.publishing.artifacts import (
    scan_for_secrets,
)
from opencode_toolkit.release.gate import CheckStatus, load_gate, new_gate, record, write_gate

#: Paths excluded from the scan, each with a documented reason.
EXCLUSIONS: dict[str, str] = {
    ".gitignore": "lists credential filenames by design",
    "tests/": "contains fake credentials that prove the detectors fire",
    "examples/": "templates, which contain placeholder credential names",
    "scripts/": "contains the pattern list used to describe what to look for",
}


def excluded(path: str) -> bool:
    return any(path == item or path.startswith(item) for item in EXCLUSIONS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root to scan")
    parser.add_argument("--gate", default=None, help="release gate to record the result in")
    parser.add_argument(
        "--staging", default=None, help="also scan this prepared publishing directory"
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    report = scan_for_secrets(root)

    interesting = [hit for hit in report.hits if not excluded(hit.file)]

    staging_report = None
    if args.staging:
        staging_path = Path(args.staging).resolve()
        if staging_path.is_dir():
            staging_report = scan_for_secrets(staging_path)
        else:
            print(f"note: staging directory {staging_path} does not exist; not scanned")

    print(f"Scanned {report.files_scanned} file(s) under {root}")
    if staging_report is not None:
        print(f"Scanned {staging_report.files_scanned} file(s) under {args.staging}")
    for note in EXCLUSIONS.values():
        print(f"  excluded: {note}")

    if interesting or (staging_report is not None and not staging_report.clean):
        print("\nPOTENTIAL CREDENTIALS FOUND")
        for hit in interesting:
            print(f"  {hit.file}:{hit.line}  {hit.kind}  {hit.redacted}")
        if staging_report is not None:
            for hit in staging_report.hits:
                print(f"  [staging] {hit.file}:{hit.line}  {hit.kind}  {hit.redacted}")
        print("\nValues are never printed. Remove the credential, rotate it, and re-run.")
    else:
        print("\nNo credential-shaped content found.")

    if args.gate:
        path = Path(args.gate)
        gate = load_gate(path) if path.is_file() else new_gate()
        if interesting or (staging_report is not None and not staging_report.clean):
            gate = record(
                gate,
                "SECRET_SCAN",
                CheckStatus.FAIL,
                detail=f"{len(interesting)} potential credential(s) found",
            )
        else:
            gate = record(
                gate,
                "SECRET_SCAN",
                CheckStatus.PASS,
                detail=f"{report.files_scanned} file(s) scanned, no credential-shaped content",
            )
        write_gate(path, gate)

    return 1 if interesting or (staging_report is not None and not staging_report.clean) else 0


if __name__ == "__main__":
    raise SystemExit(main())
