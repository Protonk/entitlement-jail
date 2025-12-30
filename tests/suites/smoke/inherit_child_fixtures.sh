#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

test_begin "smoke" "inherit_child.fixtures"

EJ="${EJ_BIN:-${ROOT_DIR}/EntitlementJail.app/Contents/MacOS/entitlement-jail}"
OUT_DIR="${EJ_TEST_ARTIFACTS}"
FIXTURE_DIR="${ROOT_DIR}/tests/fixtures/inherit_child"
SCRUB_TOOL="${ROOT_DIR}/tests/tools/scrub_inherit_child_witness.py"
COMPARE_TOOL="${ROOT_DIR}/tests/tools/compare_json_fixture.py"

if [[ ! -x "${EJ}" ]]; then
  test_fail "missing or non-executable EntitlementJail launcher at: ${EJ}"
fi

mkdir -p "${OUT_DIR}"

run_fixture() {
  local scenario="$1"
  local profile="$2"
  shift 2
  local out_json="${OUT_DIR}/inherit-child-${scenario}.json"
  local scrubbed_json="${OUT_DIR}/inherit-child-${scenario}.scrub.json"
  local fixture_json="${FIXTURE_DIR}/${scenario}.json"

  "${EJ}" xpc run --profile "${profile}" inherit_child --scenario "${scenario}" "$@" >"${out_json}"
  /usr/bin/python3 "${SCRUB_TOOL}" --in "${out_json}" --out "${scrubbed_json}"

  if [[ "${EJ_UPDATE_FIXTURES:-}" == "1" ]]; then
    mkdir -p "${FIXTURE_DIR}"
    cp "${scrubbed_json}" "${fixture_json}"
  else
    /usr/bin/python3 "${COMPARE_TOOL}" "${scrubbed_json}" "${fixture_json}"
  fi
}

test_step "inherit_child_dynamic_extension" "inherit_child fixture: dynamic_extension"
run_fixture "dynamic_extension" "temporary_exception" --path-class tmp --target specimen_file --name ej_fixture_dynamic.txt --create

test_step "inherit_child_matrix_basic" "inherit_child fixture: matrix_basic"
run_fixture "matrix_basic" "minimal" --path-class tmp --target specimen_file --name ej_fixture_matrix.txt --create

test_step "inherit_child_bookmark_ferry" "inherit_child fixture: bookmark_ferry"
run_fixture "bookmark_ferry" "bookmarks_app_scope" --path-class tmp --target specimen_file --name ej_fixture_bookmark.txt --create

test_step "inherit_child_lineage_basic" "inherit_child fixture: lineage_basic"
run_fixture "lineage_basic" "minimal"

test_step "inherit_child_bad_entitlements" "inherit_child fixture: inherit_bad_entitlements"
run_fixture "inherit_bad_entitlements" "minimal"

test_pass "inherit_child fixtures ok" "{}"
