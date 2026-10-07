#!/usr/bin/env bash
# Publish to the Hugging Face Hub -- but only through an APPROVED release gate.
#
# The dependency chain is explicit and is not negotiable:
#
#   tests -> security -> build -> release gate -> upload -> remote verification
#
# This script refuses to reach the network unless the gate says APPROVED. There
# is no flag to override that, because a flag to bypass the gate would be a flag
# to publish untested code to a public platform.
#
# Credentials come from the environment. In GitHub Actions set a repository
# secret named HUGGINGFACE_TOKEN and map it with
# `env: HUGGINGFACE_TOKEN: ${{ secrets.HUGGINGFACE_TOKEN }}`.
# Never write the token into this file, a workflow, or a commit.

set -uo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

NAMESPACE="${HF_NAMESPACE:-}"
REPO_ID="${HF_REPO_ID:-opencode-toolkit}"
DRY_RUN="${DRY_RUN:-0}"

if [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  PYTHON="${PROJECT_ROOT}/.venv/bin/python"
else
  PYTHON="$(command -v python3)"
fi
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
OPENCODE=("${PYTHON}" -m opencode_toolkit)

# ------------------------------------------------------------------ gate --
printf '==> Release gate\n'
if ! "${OPENCODE[@]}" release preflight; then
  printf '\nREFUSED: the release gate is BLOCKED. Nothing was uploaded.\n' >&2
  exit 1
fi
printf '    gate APPROVED\n'

# ------------------------------------------------------------- classify --
printf '\n==> Platform classification\n'
"${OPENCODE[@]}" publish classify || exit 1

# ---------------------------------------------------------- credentials --
if [[ -z "${HUGGINGFACE_TOKEN:-}" ]]; then
  printf '\nSKIP PUBLISH\n'
  printf '  HUGGINGFACE_TOKEN is not set.\n'
  printf '  Set it as a GitHub Actions repository secret, or export it locally.\n'
  printf '  Nothing was uploaded.\n'
  exit 0
fi
printf '\n==> Credentials: HUGGINGFACE_TOKEN is present (value not displayed)\n'

if [[ -z "${NAMESPACE}" ]]; then
  printf '\nREFUSED: HF_NAMESPACE is required.\n' >&2
  printf '  It is the Hugging Face user or organisation that will own the repository.\n' >&2
  printf '  Example: HF_NAMESPACE=my-org ./scripts/publishing/publish-huggingface.sh\n' >&2
  exit 2
fi

if [[ "${DRY_RUN}" == "1" ]]; then
  export DRY_RUN=1
fi

printf '\n==> Publishing\n'
"${OPENCODE[@]}" publish huggingface \
  --namespace "${NAMESPACE}" \
  --repo-id "${REPO_ID}" \
  --staging "${PROJECT_ROOT}/dist/publish-hf" \
  "$@"
STATUS=$?

case ${STATUS} in
  0)
    printf '\nPublished and verified. See the verification block above for the remote checks.\n'
    ;;
  6)
    printf '\nPUBLISHED_BUT_VERIFICATION_FAILED\n' >&2
    printf '  The upload completed but the remote state was not confirmed.\n' >&2
    printf '  Do not treat this as a successful release. Re-run verification:\n' >&2
    printf '    opencode publish verify --platform huggingface --namespace %s\n' "${NAMESPACE}" >&2
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
