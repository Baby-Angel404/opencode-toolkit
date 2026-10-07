#!/usr/bin/env bash
# Cut a release: gate check, changelog, version bump, artefacts, checksums.
#
#   ./scripts/release/prepare-release.sh minor
#   ./scripts/release/prepare-release.sh patch --prerelease rc.1
#
# Refuses to proceed on a BLOCKED gate. It does not push, tag or publish:
# those are separate, explicitly invoked steps.

set -uo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

if [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  PYTHON="${PROJECT_ROOT}/.venv/bin/python"
else
  PYTHON="$(command -v python3)"
fi
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
OPENCODE=("${PYTHON}" -m opencode_toolkit)

LEVEL="${1:-}"
if [[ -z "${LEVEL}" ]]; then
  printf 'usage: %s <major|minor|patch> [--prerelease LABEL]\n' "$0" >&2
  exit 2
fi
shift

printf '==> Gate check before cutting a release\n'
if ! "${OPENCODE[@]}" release preflight; then
  printf '\nRefusing to cut a release: the gate is BLOCKED.\n' >&2
  exit 1
fi

printf '\n==> Checking the working tree is clean\n'
if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  if [[ -n "$(git status --porcelain)" ]]; then
    printf 'Refusing to cut a release with uncommitted changes.\n' >&2
    git status --short >&2
    exit 1
  fi
  printf '    working tree is clean\n'
fi

printf '\n==> Rendering CHANGELOG.md\n'
"${OPENCODE[@]}" release changelog

printf '\n==> Bumping the version (%s)\n' "${LEVEL}"
"${OPENCODE[@]}" release bump "${LEVEL}" "$@"
VERSION="$("${OPENCODE[@]}" --format json version | python3 -c 'import json,sys; print(json.load(sys.stdin)["toolkit"]["declared"])')"

printf '\n==> Rendering CHANGELOG.md for %s\n' "${VERSION}"
"${OPENCODE[@]}" release changelog --release "${VERSION}"

printf '\n==> Building artefacts\n'
"${OPENCODE[@]}" release artifacts --output "${PROJECT_ROOT}/dist"

printf '\n==> Verifying artefacts\n'
"${OPENCODE[@]}" release verify-artifacts --output "${PROJECT_ROOT}/dist"

printf '\n==> Release artefacts are ready in %s/dist\n' "${PROJECT_ROOT}"
printf 'Checksums: %s/dist/SHA256SUMS\n' "${PROJECT_ROOT}"
printf '\nNext steps (not performed by this script):\n'
printf '  git tag -s v%s -m "opencode-toolkit %s"\n' "${VERSION}" "${VERSION}"
printf '  gh release create v%s --generate-notes dist/*\n' "${VERSION}"
printf '  ./scripts/publishing/publish-huggingface.sh\n'
printf '  ./scripts/publishing/publish-kaggle.sh\n'
