#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

CURRENT_STEP=""

test_begin "smoke" "inherit_child.fixtures"

fail() {
  test_fail "${CURRENT_STEP:-inherit_child fixtures failed}"
}

trap fail ERR

PW="${PW_BIN:-${ROOT_DIR}/PolicyWitness.app/Contents/MacOS/policy-witness}"
OUT_DIR="${PW_TEST_ARTIFACTS}"
FIXTURE_DIR="${ROOT_DIR}/tests/fixtures/inherit_child"
SCRUB_TOOL="${ROOT_DIR}/tests/tools/scrub_inherit_child_witness.py"
COMPARE_TOOL="${ROOT_DIR}/tests/tools/compare_json_fixture.py"

if [[ ! -x "${PW}" ]]; then
  test_fail "missing or non-executable PolicyWitness launcher at: ${PW}"
fi

mkdir -p "${OUT_DIR}"

run_fixture() {
  local scenario="$1"
  local profile="$2"
  shift 2
  local out_json="${OUT_DIR}/inherit-child-${scenario}.json"
  local scrubbed_json="${OUT_DIR}/inherit-child-${scenario}.scrub.json"
  local fixture_json="${FIXTURE_DIR}/${scenario}.json"

  set +e
  "${PW}" xpc run --profile "${profile}" inherit_child --scenario "${scenario}" "$@" >"${out_json}"
  local pw_status=$?
  set -e
  if [[ ${pw_status} -ne 0 ]]; then
    local summary
    summary="$(
      /usr/bin/python3 - "${out_json}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
except Exception as e:
    print(f"invalid_json: {e}")
    raise SystemExit(0)

result = data.get("result") or {}
normalized = result.get("normalized_outcome")
err = result.get("error") or result.get("stderr") or ""
if isinstance(err, str):
    err = err.replace("\n", "\\n")
print(f"kind={data.get('kind')!r} normalized_outcome={normalized!r} error={err[:240]!r}")
PY
    )"
    test_fail "inherit_child fixture scenario=${scenario} profile=${profile} failed (exit_code=${pw_status}): ${summary}"
  fi

  /usr/bin/python3 "${SCRUB_TOOL}" --in "${out_json}" --out "${scrubbed_json}"

  if [[ "${PW_UPDATE_FIXTURES:-}" == "1" ]]; then
    mkdir -p "${FIXTURE_DIR}"
    cp "${scrubbed_json}" "${fixture_json}"
  else
    /usr/bin/python3 "${COMPARE_TOOL}" "${scrubbed_json}" "${fixture_json}"
  fi
}

test_step "inherit_child_dynamic_extension" "inherit_child fixture: dynamic_extension"
CURRENT_STEP="inherit_child_dynamic_extension"
run_fixture "dynamic_extension" "temporary_exception" --path-class tmp --target specimen_file --name pw_fixture_dynamic.txt --create

test_step "inherit_child_matrix_basic" "inherit_child fixture: matrix_basic"
CURRENT_STEP="inherit_child_matrix_basic"
run_fixture "matrix_basic" "minimal" --path-class tmp --target specimen_file --name pw_fixture_matrix.txt --create

test_step "inherit_child_bookmark_ferry" "inherit_child fixture: bookmark_ferry"
CURRENT_STEP="inherit_child_bookmark_ferry"
run_fixture "bookmark_ferry" "bookmarks_app_scope" --path-class tmp --target specimen_file --name pw_fixture_bookmark.txt --create

test_step "inherit_child_lineage_basic" "inherit_child fixture: lineage_basic"
CURRENT_STEP="inherit_child_lineage_basic"
run_fixture "lineage_basic" "minimal"

test_step "inherit_child_bad_entitlements" "inherit_child fixture: inherit_bad_entitlements"
CURRENT_STEP="inherit_child_bad_entitlements"
run_fixture "inherit_bad_entitlements" "minimal"

test_pass "inherit_child fixtures ok" "{}"
