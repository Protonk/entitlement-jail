#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

test_begin "integration" "cli.integration"

PRECHECK_JSON="${EJ_TEST_OUT_DIR}/suites/preflight/codesign.preflight/artifacts/preflight.json"
if [[ -f "${PRECHECK_JSON}" ]]; then
  export EJ_PREFLIGHT_JSON="${PRECHECK_JSON}"
fi
export EJ_INTEGRATION=1

LOG_PATH="${EJ_TEST_ARTIFACTS}/cargo-test-integration.log"

test_step "cargo_test_integration" "cargo test --tests (cli integration)"
set +e
cargo test --manifest-path "${ROOT_DIR}/runner/Cargo.toml" --tests >"${LOG_PATH}" 2>&1
status=$?
set -e

if [[ ${status} -ne 0 ]]; then
  test_fail "cargo test --tests failed" "{\"log_path\":\"${LOG_PATH}\"}"
fi

test_pass "integration tests ok" "{\"log_path\":\"${LOG_PATH}\"}"
