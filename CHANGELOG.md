# Changelog

All notable changes are recorded here as structured fragments under `.changes/unreleased/`.

## 0.1.0 - 2026-10-08

No changes recorded for this release.
## 0.1.0 - 2026-10-07

### Added

* Task-graph orchestrator with role capabilities, declared write ownership, checkpoints and resume (`orchestrator`)
* Unified CLI with text, JSON and SARIF output and stable exit codes, fronting six components that share one core (`cli`)
* Encrypted workflow sync with authenticated snapshots, content-addressed blobs, three-way conflict detection and an offline queue (`workflow-sync`)
* Five GitHub Actions workflows and a local quality pipeline; no container required (`ci`)
* Hugging Face and Kaggle publishing gated on an approved release, with platform classification (`publishing`)
* Verified snippet registry with 16 reviewed snippets, contract validation and provenance (`snippet-verified`)
* Security auditor for Python, JavaScript, TypeScript and Go with 45 CWE-mapped rules, ReDoS shape detection and secret fingerprinting (`security-audit`)
* Fourteen-check release gate that blocks on NOT_RUN as well as FAIL (`release`)
* Apache-2.0 licence, security policy and full documentation set (`docs`)
* Live documentation drift detection and a conservative docstring updater that owns only parameter blocks (`live-docs`)
* Deterministic offline pack builder with per-file checksums, a content digest and licence decisions (`offline-pack`)
