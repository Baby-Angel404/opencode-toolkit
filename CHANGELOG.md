# Changelog

All notable changes are recorded here as structured fragments under `.changes/unreleased/`.

## 0.1.1 - 2026-10-08

### Added

* scripts/security/workflow-permissions.py verifies that reusable-workflow calls grant at least the permissions their nested jobs request, catching startup failures before push. (`ci`)

### Changed

* Pinned actions moved to their current majors: checkout v7, setup-python v7, upload-artifact v7, download-artifact v8, dependency-review v5, codeql-action v4, action-gh-release v3. (`ci`)

### Fixed

* The CI doctor step wrote its report into the checkout, so doctor's own git.clean check warned and --strict turned that warning into the failure being tested. (`ci`)
* The history secret scan ignored the audit's configured exclusions and flagged the patch's own 40-hex commit headers, so a clean history reported leaks. (`security-audit`)
* An installed wheel could not be imported outside a checkout of this repository: detect_version read pyproject.toml or raised, and a wheel ships no pyproject.toml. Distribution metadata is now the fallback. (`release`)
* release.yml pinned contents: read while calling security.yml, whose audit and codeql jobs request security-events: write. Every tag push produced a release with zero jobs. (`ci`)
* The SARIF relationship target carried a description and a non-UUID guid, so GitHub rejected the whole file as invalid and code scanning never received any results. (`security-audit`)
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
