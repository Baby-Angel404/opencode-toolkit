#!/usr/bin/env bash
# Run one named test suite through pytest, with the project's own configuration.
#
#   ./scripts/test/run-suite.sh unit
#   ./scripts/test/run-suite.sh security -- -k crypto
#
# Named suites map to pytest markers, so what a developer runs and what CI runs
# are the same selection.

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

if [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  PYTHON="${PROJECT_ROOT}/.venv/bin/python"
else
  PYTHON="$(command -v python3)"
fi
export PYTHONPATH="${PROJECT_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

SUITE="${1:-all}"
shift || true

case "${SUITE}" in
  all)      MARKER="" ;;
  unit|integration|cli|security|regression|slow) MARKER="${SUITE}" ;;
  *) printf 'unknown suite %s; expected all, unit, integration, cli, security, regression or slow\n' "${SUITE}" >&2; exit 2 ;;
esac

ARGS=(-m pytest -q --no-cov)
if [[ -n "${MARKER}" ]]; then
  ARGS+=(-m "${MARKER}")
fi
# Anything after `--` is passed straight through to pytest.
if [[ "${1:-}" == "--" ]]; then
  shift
  ARGS+=("$@")
fi

exec "${PYTHON}" "${ARGS[@]}"
