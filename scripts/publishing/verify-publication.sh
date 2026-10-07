#!/usr/bin/env bash
# Verify a published artefact without re-uploading it.
#
#   ./scripts/publishing/verify-publication.sh huggingface --namespace my-org
#   ./scripts/publishing/verify-publication.sh kaggle --slug opencode-toolkit
#
# Reports PUBLISHED_BUT_VERIFICATION_FAILED rather than PASS when the remote
# state cannot be confirmed, because a publication that cannot be verified is
# not a completed publication.

set -uo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

PLATFORM="${1:-}"
if [[ -z "${PLATFORM}" ]]; then
  printf 'usage: %s <huggingface|kaggle> [options]\n' "$0" >&2
  exit 2
fi
shift

if [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  PYTHON="${PROJECT_ROOT}/.venv/bin/python"
else
  PYTHON="$(command -v python3)"
fi
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

exec "${PYTHON}" -m opencode_toolkit publish verify --platform "${PLATFORM}" "$@"
