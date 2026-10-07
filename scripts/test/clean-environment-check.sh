#!/usr/bin/env bash
# Reproducibility check: build, install and test from a clean virtual
# environment, in a directory that shares nothing with the developer's tree.
#
# This is the check that backs the claim "reproducible from a clean checkout".
# It deliberately installs from the built wheel rather than the source tree, so
# a missing package-data entry (the snippet registry, for example) fails here
# rather than on a user's machine.

set -uo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly WORK="$(mktemp -d -t opencode-cleanenv-XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

if ! command -v python3 >/dev/null 2>&1; then
  printf 'python3 is not available\n' >&2
  exit 127
fi

# Record interpreter identity so the run is attributable.
python3 -c 'import platform, sys; print(f"{platform.python_implementation()} {platform.python_version()} on {platform.system()} {platform.machine()}")' \
  > "${WORK}/interpreter.txt" 2>&1 || true

printf '==> Creating a clean virtual environment in %s\n' "${WORK}"
python3 -m venv "${WORK}/venv" || { printf 'venv creation failed\n' >&2; exit 1; }
VENV_PY="${WORK}/venv/bin/python"

printf '\n==> Installing the development tool chain from PyPI\n'
# Network access is required here; this is the one stage that cannot run on an
# air-gapped host, which is exactly why it is a separate stage.
if ! "${VENV_PY}" -m pip install --quiet --upgrade pip setuptools wheel; then
  printf 'cannot install the build tool chain (no network?)\n' >&2
  printf 'reproducibility is NOT_RUN in this environment\n' >&2
  exit 127
fi

printf '\n==> Installing the project\n'
if ! "${VENV_PY}" -m pip install --quiet "${PROJECT_ROOT}[dev]"; then
  printf 'clean install failed\n' >&2
  exit 1
fi

printf '\n==> Verifying the installed package imports and the CLI entry point works\n'
( cd "${WORK}" && "${VENV_PY}" -c 'import opencode_toolkit; print(opencode_toolkit.__version__)' ) || exit 1
( cd "${WORK}" && "${WORK}/venv/bin/opencode" version ) || exit 1

printf '\n==> Running the test suite against the installed package\n'
# Run from the temp directory so the local `src/` tree cannot be picked up via
# PYTHONPATH or cwd; anything the tests need is already installed.
( cd "${WORK}" && "${VENV_PY}" -m pytest --rootdir "${PROJECT_ROOT}" -q --no-cov "${PROJECT_ROOT}/tests" ) || exit 1

printf '\n==> Building the offline pack from the installed tree\n'
( cd "${WORK}" && "${WORK}/venv/bin/opencode" --workspace "${PROJECT_ROOT}" pack build \
    --output "${WORK}/pack.zip" ) || exit 1
( cd "${WORK}" && "${WORK}/venv/bin/opencode" --workspace "${PROJECT_ROOT}" pack verify "${WORK}/pack.zip" ) || exit 1

printf '\nCLEAN ENVIRONMENT CHECK PASSED\n'
