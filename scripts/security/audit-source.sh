#!/usr/bin/env bash
# Convenience wrapper: audit a path with the project's own rules.
#
#   ./scripts/security/audit-source.sh src
#   ./scripts/security/audit-source.sh . --strict

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

TARGET="${1:-src}"
shift || true

exec "${PYTHON}" -m opencode_toolkit security-audit "${TARGET}" "$@"
