#!/usr/bin/env bash
# Publish to Kaggle as a Dataset -- but only through an APPROVED release gate.
#
# Same non-negotiable dependency chain as the Hugging Face workflow:
#
#   tests -> security -> build -> release gate -> upload -> remote verification
#
# Credentials come from the environment: KAGGLE_USERNAME and KAGGLE_KEY. In GitHub
# Actions set repository secrets with those exact names. Neither value is ever
# printed by this script or by the toolkit.

set -uo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

SLUG="${KAGGLE_DATASET_SLUG:-opencode-toolkit}"
OWNER="${KAGGLE_OWNER:-${KAGGLE_USERNAME:-}}"

if [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  PYTHON="${PROJECT_ROOT}/.venv/bin/python"
else
  PYTHON="$(command -v python3)"
fi
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
OPENCODE=("${PYTHON}" -m opencode_toolkit)

printf '==> Release gate\n'
if ! "${OPENCODE[@]}" release preflight; then
  printf '\nREFUSED: the release gate is BLOCKED. Nothing was uploaded.\n' >&2
  exit 1
fi
printf '    gate APPROVED\n'

printf '\n==> Platform classification\n'
"${OPENCODE[@]}" publish classify || exit 1

MISSING=""
[[ -z "${KAGGLE_USERNAME:-}" ]] && MISSING="${MISSING} KAGGLE_USERNAME"
[[ -z "${KAGGLE_KEY:-}" ]] && MISSING="${MISSING} KAGGLE_KEY"
if [[ -n "${MISSING}" ]]; then
  printf '\nSKIP PUBLISH\n'
  printf '  Missing required configuration:%s\n' "${MISSING}"
  printf '  Set each as a GitHub Actions repository secret, or export it locally.\n'
  printf '  Nothing was uploaded.\n'
  exit 0
fi
printf '\n==> Credentials: KAGGLE_USERNAME and KAGGLE_KEY are present (values not displayed)\n'

ARGS=(publish kaggle --slug "${SLUG}" --staging "${PROJECT_ROOT}/dist/publish-kaggle")
if [[ -n "${OWNER}" ]]; then
  ARGS+=(--owner "${OWNER}")
fi

printf '\n==> Publishing\n'
"${OPENCODE[@]}" "${ARGS[@]}" "$@"
STATUS=$?

case ${STATUS} in
  0)
    printf '\nPublished and verified. See the verification block above for the remote checks.\n'
    ;;
  6)
    printf '\nPUBLISHED_BUT_VERIFICATION_FAILED\n' >&2
    printf '  The upload completed but the remote dataset was not confirmed.\n' >&2
    printf '  Re-run verification rather than re-uploading:\n' >&2
    printf '    opencode publish verify --platform kaggle --slug %s\n' "${SLUG}" >&2
    exit 6
    ;;
  3)
    printf '\nREFUSED: the release gate is missing or blocked. Nothing was uploaded.\n' >&2
    exit 1
    ;;
  *)
    printf '\nPublish did not complete (exit %s). Nothing is claimed as published.\n' "${STATUS}" >&2
    exit "${STATUS}"
    ;;
esac
