#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

test_begin "unit" "rust.unit"

LOG_PATH="${PW_TEST_ARTIFACTS}/cargo-test-bins.log"

test_step "cargo_test_bins" "cargo test --bins (unit tests)"
set +e
cargo test --manifest-path "${ROOT_DIR}/runner/Cargo.toml" --bins >"${LOG_PATH}" 2>&1
status=$?
set -e

if [[ ${status} -ne 0 ]]; then
  test_fail "cargo test --bins failed" "{\"log_path\":\"${LOG_PATH}\"}"
fi

test_step "inherit_child_fixture_schema" "validate inherit_child fixture schema"
/usr/bin/python3 "${ROOT_DIR}/tests/tools/validate_inherit_child_fixtures.py"

test_pass "unit tests ok" "{\"log_path\":\"${LOG_PATH}\"}"
