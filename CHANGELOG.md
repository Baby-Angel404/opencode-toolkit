# Changelog

All notable changes are recorded here as structured fragments under `.changes/unreleased/`.

## 0.1.1 - 2026-10-08

### Added

* A .gitattributes pins LF line endings in the working tree on every platform, so the offline pack, the SBOM and the reproducibility gate hash the same bytes whoever ran them. (`build`)
* scripts/security/workflow-permissions.py verifies that reusable-workflow calls grant at least the permissions their nested jobs request, catching startup failures before push. (`ci`)

### Changed

* Pinned actions moved to their current majors: checkout v7, setup-python v7, upload-artifact v7, download-artifact v8, dependency-review v5, codeql-action v4, action-gh-release v3. (`ci`)

### Fixed

* Artefact verification only re-hashed what a build had recorded, so a build that silently lost the wheel verified clean and printed RESULT: VERIFIED for a set with no wheel in it. Verification now also confirms every required kind was produced. It has to distinguish an explicit opt-out from a silent loss, so the required kinds are chosen by the build, persisted in artifacts.json, and a FAILED build step is fatal while a SKIPPED one is not. (`release`)
* The CI doctor step wrote its report into the checkout, so doctor's own git.clean check warned and --strict turned that warning into the failure being tested. (`ci`)
* The history secret scan ignored the audit's configured exclusions and flagged the patch's own 40-hex commit headers, so a clean history reported leaks. (`security-audit`)
* An installed wheel could not be imported outside a checkout of this repository: detect_version read pyproject.toml or raised, and a wheel ships no pyproject.toml. Distribution metadata is now the fallback. (`release`)
* The release job installed only the package, so `python -m build` was missing. That module exits non-zero rather than raising, so the wheel was silently skipped and the run died later at artefact verification with nothing pointing at the cause. It now installs the same toolchain the gate approved. build-artifacts.sh also honoured --output for the build but verified the default directory, so its 'verified' line could describe artefacts the run never wrote. (`ci`)
* The release gate is stored outside version control on purpose, since it records a verdict about one commit rather than a fact about the repository. The release job therefore started with no gate at all and preflight refused to build. It now takes the approved gate from the validate job's artefact and refuses it unless the recorded commit is the commit being released, so a stale artefact cannot authorise a release. (`ci`)
* The release job required needs.explain-blocked.result == 'skipped', but GitHub skips a dependent job whenever a job it needs is skipped unless the condition uses always(). Since explain-blocked only runs when the gate refuses, the condition could never hold and no release was ever cut, while the run stayed green. The condition now opts in, and the workflow checker reports the contradiction before it can ship. (`ci`)
* release.yml pinned contents: read while calling security.yml, whose audit and codeql jobs request security-events: write. Every tag push produced a release with zero jobs. (`ci`)
* The step that re-reads the published release over the API had no GH_TOKEN, so gh refused to authenticate and the run went red after the release was already live. contents: write grants the permission but exports no credential; gh reads the environment. (`ci`)
* The SARIF relationship target carried a description and a non-UUID guid, so GitHub rejected the whole file as invalid and code scanning never received any results. (`security-audit`)
* Four tests asserted a 0600 file mode unconditionally. Windows has no POSIX mode bits, so stat.S_IMODE reports 0o666 for every writable file and the owner-only guarantee does not exist there; they now skip on nt with that stated as the reason. The guarantee is documented as POSIX-only in the security model. (`test`)
* Tests shelled out to a bare `python3`, which is not on PATH on Windows, and one of them killed itself with signal.SIGKILL, which does not exist there. Both now use the running interpreter, and the crash path reaches the retry policy through the branch the platform can actually produce. The generated example plan does the same, so it runs on the machine that wrote it. (`test`)
## 0.1.1 - 2026-10-08

### Added

* A .gitattributes pins LF line endings in the working tree on every platform, so the offline pack, the SBOM and the reproducibility gate hash the same bytes whoever ran them. (`build`)
* scripts/security/workflow-permissions.py verifies that reusable-workflow calls grant at least the permissions their nested jobs request, catching startup failures before push. (`ci`)

### Changed

* Pinned actions moved to their current majors: checkout v7, setup-python v7, upload-artifact v7, download-artifact v8, dependency-review v5, codeql-action v4, action-gh-release v3. (`ci`)

### Fixed

* Artefact verification only re-hashed what a build had recorded, so a build that silently lost the wheel verified clean and printed RESULT: VERIFIED for a set with no wheel in it. Verification now also confirms every required kind was produced. It has to distinguish an explicit opt-out from a silent loss, so the required kinds are chosen by the build, persisted in artifacts.json, and a FAILED build step is fatal while a SKIPPED one is not. (`release`)
* The CI doctor step wrote its report into the checkout, so doctor's own git.clean check warned and --strict turned that warning into the failure being tested. (`ci`)
* The history secret scan ignored the audit's configured exclusions and flagged the patch's own 40-hex commit headers, so a clean history reported leaks. (`security-audit`)
* An installed wheel could not be imported outside a checkout of this repository: detect_version read pyproject.toml or raised, and a wheel ships no pyproject.toml. Distribution metadata is now the fallback. (`release`)
* The release job installed only the package, so `python -m build` was missing. That module exits non-zero rather than raising, so the wheel was silently skipped and the run died later at artefact verification with nothing pointing at the cause. It now installs the same toolchain the gate approved. build-artifacts.sh also honoured --output for the build but verified the default directory, so its 'verified' line could describe artefacts the run never wrote. (`ci`)
* The release gate is stored outside version control on purpose, since it records a verdict about one commit rather than a fact about the repository. The release job therefore started with no gate at all and preflight refused to build. It now takes the approved gate from the validate job's artefact and refuses it unless the recorded commit is the commit being released, so a stale artefact cannot authorise a release. (`ci`)
* The release job required needs.explain-blocked.result == 'skipped', but GitHub skips a dependent job whenever a job it needs is skipped unless the condition uses always(). Since explain-blocked only runs when the gate refuses, the condition could never hold and no release was ever cut, while the run stayed green. The condition now opts in, and the workflow checker reports the contradiction before it can ship. (`ci`)
* release.yml pinned contents: read while calling security.yml, whose audit and codeql jobs request security-events: write. Every tag push produced a release with zero jobs. (`ci`)
* The SARIF relationship target carried a description and a non-UUID guid, so GitHub rejected the whole file as invalid and code scanning never received any results. (`security-audit`)
* Four tests asserted a 0600 file mode unconditionally. Windows has no POSIX mode bits, so stat.S_IMODE reports 0o666 for every writable file and the owner-only guarantee does not exist there; they now skip on nt with that stated as the reason. The guarantee is documented as POSIX-only in the security model. (`test`)
* Tests shelled out to a bare `python3`, which is not on PATH on Windows, and one of them killed itself with signal.SIGKILL, which does not exist there. Both now use the running interpreter, and the crash path reaches the retry policy through the branch the platform can actually produce. The generated example plan does the same, so it runs on the machine that wrote it. (`test`)
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
