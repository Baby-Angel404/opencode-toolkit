#!/usr/bin/env bash
# Build every release artefact into dist/.
#
# Assumes the quality pipeline has already run and left the gate APPROVED --
# this script checks that first, because a release must not be possible from a
# blocked state by accident.

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

REQUIRE_GATE="${REQUIRE_GATE:-1}"
if [[ "${REQUIRE_GATE}" == "1" ]]; then
  printf '==> Checking the release gate\n'
  if ! "${PYTHON}" -m opencode_toolkit release preflight; then
    printf '\nRefusing to build release artefacts: the gate is BLOCKED.\n' >&2
    printf 'Run ./scripts/quality-check and resolve every blocking check.\n' >&2
    exit 1
  fi
fi

# The build and the re-verification must look at the same directory. Passing
# --output and then verifying ${PROJECT_ROOT}/dist anyway means the "verified"
# line describes a directory this run never wrote -- the check passes while
# proving nothing about the artefacts about to be published.
OUTPUT_DIR="${PROJECT_ROOT}/dist"
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_DIR="$2"
      ARGS+=("$1" "$2")
      shift 2
      ;;
    --output=*)
      OUTPUT_DIR="${1#--output=}"
      ARGS+=("$1")
      shift
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

printf '\n==> Building artefacts into %s\n' "${OUTPUT_DIR}"
"${PYTHON}" -m opencode_toolkit release artifacts --output "${OUTPUT_DIR}" "${ARGS[@]+"${ARGS[@]}"}"
STATUS=$?

printf '\n==> Re-verifying the artefacts from disk\n'
if [[ ${STATUS} -eq 0 ]]; then
  "${PYTHON}" -m opencode_toolkit release verify-artifacts --output "${OUTPUT_DIR}"
  STATUS=$?
fi

exit ${STATUS}
