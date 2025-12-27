#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

failures=0

run_test() {
  local script="$1"
  set +e
  bash "${script}"
  local status=$?
  set -e
  if [[ ${status} -ne 0 ]]; then
    failures=1
  fi
}

run_test "${ROOT_DIR}/tests/suites/smoke/experiments_tri_run.sh"
run_test "${ROOT_DIR}/tests/suites/smoke/xpc_app_smoke.sh"
run_test "${ROOT_DIR}/tests/suites/smoke/xpc_session_smoke.sh"
run_test "${ROOT_DIR}/tests/suites/smoke/quarantine_smoke.sh"
run_test "${ROOT_DIR}/tests/suites/smoke/observer_smoke.sh"

if [[ ${failures} -ne 0 ]]; then
  exit 1
fi
