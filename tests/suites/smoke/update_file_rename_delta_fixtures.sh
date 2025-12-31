#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

test_begin "smoke" "sandbox_extension.update_file_rename_delta.fixtures"

PW="${PW_BIN:-${ROOT_DIR}/PolicyWitness.app/Contents/MacOS/policy-witness}"
OUT_DIR="${PW_TEST_ARTIFACTS}"
FIXTURE_DIR="${ROOT_DIR}/tests/fixtures/update_file_rename_delta"
SCRUB_TOOL="${ROOT_DIR}/tests/tools/scrub_update_file_rename_delta.py"
VALIDATE_TOOL="${ROOT_DIR}/tests/tools/validate_update_file_rename_delta.py"
COMPARE_TOOL="${ROOT_DIR}/tests/tools/compare_json_fixture.py"

if [[ ! -x "${PW}" ]]; then
  test_fail "missing or non-executable PolicyWitness launcher at: ${PW}"
fi

mkdir -p "${OUT_DIR}"

HARNESS_BASE="/tmp/policy-witness-harness"
mkdir -p "${HARNESS_BASE}"
RUN_DIR="$(mktemp -d "${HARNESS_BASE}/fixture-update-file-rename-delta-XXXXXX")"

cleanup() {
  rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

run_fixture() {
  local fixture="$1"
  shift 1
  local out_json="${OUT_DIR}/update-file-rename-delta-${fixture}.json"
  local scrubbed_json="${OUT_DIR}/update-file-rename-delta-${fixture}.scrub.json"
  local fixture_json="${FIXTURE_DIR}/${fixture}.json"

  "${PW}" xpc run --profile "temporary_exception" sandbox_extension \
    --op update_file_rename_delta \
    --class com.apple.app-sandbox.read \
    "$@" >"${out_json}"

  /usr/bin/python3 "${SCRUB_TOOL}" --in "${out_json}" --out "${scrubbed_json}"
  /usr/bin/python3 "${VALIDATE_TOOL}" --in "${scrubbed_json}" --expect "${fixture}"

  if [[ "${PW_UPDATE_FIXTURES:-}" == "1" ]]; then
    mkdir -p "${FIXTURE_DIR}"
    cp "${scrubbed_json}" "${fixture_json}"
  else
    /usr/bin/python3 "${COMPARE_TOOL}" "${scrubbed_json}" "${fixture_json}"
  fi
}

test_step "update_file_rename_delta_happy" "update_file_rename_delta fixture: happy"

old_path="${RUN_DIR}/pw_update_file_old.txt"
new_path="${RUN_DIR}/pw_update_file_new.txt"
printf 'pw fixture: update file rename delta\n' >"${old_path}"

out_happy="${OUT_DIR}/update-file-rename-delta-happy.json"

set +e
"${PW}" xpc run --profile "temporary_exception" sandbox_extension \
  --op update_file_rename_delta \
  --class com.apple.app-sandbox.read \
  --path "${old_path}" \
  --new-path "${new_path}" \
  --wait-for-external-rename >"${out_happy}" &
probe_pid=$!
set -e

sleep 1
mv "${old_path}" "${new_path}"
wait "${probe_pid}"

/usr/bin/python3 "${SCRUB_TOOL}" --in "${out_happy}" --out "${OUT_DIR}/update-file-rename-delta-happy.scrub.json"
/usr/bin/python3 "${VALIDATE_TOOL}" --in "${OUT_DIR}/update-file-rename-delta-happy.scrub.json" --expect "happy"

if [[ "${PW_UPDATE_FIXTURES:-}" == "1" ]]; then
  mkdir -p "${FIXTURE_DIR}"
  cp "${OUT_DIR}/update-file-rename-delta-happy.scrub.json" "${FIXTURE_DIR}/happy.json"
else
  /usr/bin/python3 "${COMPARE_TOOL}" "${OUT_DIR}/update-file-rename-delta-happy.scrub.json" "${FIXTURE_DIR}/happy.json"
fi

test_step "update_file_rename_delta_dest_preexisted" "update_file_rename_delta fixture: dest_preexisted"

old_path2="${RUN_DIR}/pw_update_file_old2.txt"
new_path2="${RUN_DIR}/pw_update_file_new2.txt"
printf 'pw fixture: old2\n' >"${old_path2}"
printf 'pw fixture: new2\n' >"${new_path2}"

run_fixture "dest_preexisted" --path "${old_path2}" --new-path "${new_path2}"

test_step "update_file_rename_delta_rename_inode_changed" "update_file_rename_delta fixture: rename_inode_changed"

old_path3="${RUN_DIR}/pw_update_file_old3.txt"
new_path3="${RUN_DIR}/pw_update_file_new3.txt"
printf 'pw fixture: old3\n' >"${old_path3}"

out_inode_changed="${OUT_DIR}/update-file-rename-delta-rename-inode-changed.json"

set +e
"${PW}" xpc run --profile "temporary_exception" sandbox_extension \
  --op update_file_rename_delta \
  --class com.apple.app-sandbox.read \
  --path "${old_path3}" \
  --new-path "${new_path3}" \
  --wait-for-external-rename >"${out_inode_changed}" &
probe_pid=$!
set -e

sleep 1
cp "${old_path3}" "${new_path3}"
rm -f "${old_path3}"
wait "${probe_pid}"

/usr/bin/python3 "${SCRUB_TOOL}" --in "${out_inode_changed}" --out "${OUT_DIR}/update-file-rename-delta-rename-inode-changed.scrub.json"
/usr/bin/python3 "${VALIDATE_TOOL}" --in "${OUT_DIR}/update-file-rename-delta-rename-inode-changed.scrub.json" --expect "rename_inode_changed"

if [[ "${PW_UPDATE_FIXTURES:-}" == "1" ]]; then
  mkdir -p "${FIXTURE_DIR}"
  cp "${OUT_DIR}/update-file-rename-delta-rename-inode-changed.scrub.json" "${FIXTURE_DIR}/rename_inode_changed.json"
else
  /usr/bin/python3 "${COMPARE_TOOL}" "${OUT_DIR}/update-file-rename-delta-rename-inode-changed.scrub.json" "${FIXTURE_DIR}/rename_inode_changed.json"
fi

test_pass "update_file_rename_delta fixtures ok" "{}"
