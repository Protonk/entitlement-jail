#!/usr/bin/env bash

testlib_root() {
  local lib_dir
  lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "${lib_dir}/../.." && pwd
}

now_ms() {
  /usr/bin/python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

gen_run_id() {
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local suffix
  suffix="$(/usr/bin/python3 - <<'PY'
import uuid
print(uuid.uuid4().hex[:8])
PY
)"
  echo "${stamp}_${suffix}"
}

testlib_init() {
  local root
  root="$(testlib_root)"

  if [[ -z "${PW_TEST_RUN_ID:-}" ]]; then
    PW_TEST_RUN_ID="$(gen_run_id)"
    export PW_TEST_RUN_ID
  fi
  if [[ -z "${PW_TEST_OUT_DIR:-}" ]]; then
    PW_TEST_OUT_DIR="${root}/tests/out"
    export PW_TEST_OUT_DIR
  fi
  if [[ -z "${PW_TEST_EVENTS:-}" ]]; then
    PW_TEST_EVENTS="${PW_TEST_OUT_DIR}/events.jsonl"
    export PW_TEST_EVENTS
  fi

  mkdir -p "${PW_TEST_OUT_DIR}/suites"
}

write_json_line() {
  local line="$1"
  local path="$2"
  mkdir -p "$(dirname "${path}")"
  printf '%s\n' "${line}" >> "${path}"
}

emit_event() {
  local status="$1"
  local step="$2"
  local message="$3"
  local data_json="${4:-}"
  local duration_ms="${5:-}"

  local ts_ms
  ts_ms="$(now_ms)"

  PW_EVENT_STATUS="${status}" \
  PW_EVENT_STEP="${step}" \
  PW_EVENT_MESSAGE="${message}" \
  PW_EVENT_DATA="${data_json}" \
  PW_EVENT_DURATION_MS="${duration_ms}" \
  PW_EVENT_TS_MS="${ts_ms}" \
  /usr/bin/python3 - <<'PY'
import json
import os

def maybe_int(value):
    try:
        return int(value)
    except Exception:
        return None

data_raw = os.environ.get("PW_EVENT_DATA", "")
if data_raw:
    try:
        data = json.loads(data_raw)
    except Exception:
        data = {"raw": data_raw}
else:
    data = None

event = {
    "schema_version": 1,
    "kind": "test_event",
    "run_id": os.environ.get("PW_TEST_RUN_ID", ""),
    "suite": os.environ.get("PW_TEST_SUITE", ""),
    "test_id": os.environ.get("PW_TEST_ID", ""),
    "step": os.environ.get("PW_EVENT_STEP", ""),
    "status": os.environ.get("PW_EVENT_STATUS", ""),
    "ts_unix_ms": maybe_int(os.environ.get("PW_EVENT_TS_MS")),
    "duration_ms": maybe_int(os.environ.get("PW_EVENT_DURATION_MS")),
    "message": os.environ.get("PW_EVENT_MESSAGE", ""),
    "data": data,
}

print(json.dumps(event, sort_keys=True))
PY
}

test_log() {
  local message="$1"
  local suite="${PW_TEST_SUITE:-unknown}"
  local test_id="${PW_TEST_ID:-unknown}"
  echo "==> [${suite}/${test_id}] ${message}"
}

test_begin() {
  local suite="$1"
  local test_id="$2"

  testlib_init

  PW_TEST_SUITE="${suite}"
  PW_TEST_ID="${test_id}"
  PW_TEST_START_MS="$(now_ms)"
  PW_TEST_DIR="${PW_TEST_OUT_DIR}/suites/${suite}/${test_id}"
  PW_TEST_EVENTS_LOCAL="${PW_TEST_DIR}/events.jsonl"
  PW_TEST_REPORT="${PW_TEST_DIR}/report.json"
  PW_TEST_ARTIFACTS="${PW_TEST_DIR}/artifacts"

  export PW_TEST_SUITE PW_TEST_ID PW_TEST_START_MS
  export PW_TEST_DIR PW_TEST_EVENTS_LOCAL PW_TEST_REPORT PW_TEST_ARTIFACTS

  mkdir -p "${PW_TEST_ARTIFACTS}"

  test_log "start"
  local event_line
  event_line="$(emit_event "start" "test_start" "start")"
  write_json_line "${event_line}" "${PW_TEST_EVENTS}"
  write_json_line "${event_line}" "${PW_TEST_EVENTS_LOCAL}"
}

test_step() {
  local step="$1"
  local message="${2:-$1}"

  PW_TEST_CURRENT_STEP="${step}"
  export PW_TEST_CURRENT_STEP

  test_log "${message}"
  local event_line
  event_line="$(emit_event "info" "${step}" "${message}")"
  write_json_line "${event_line}" "${PW_TEST_EVENTS}"
  write_json_line "${event_line}" "${PW_TEST_EVENTS_LOCAL}"
}

write_report() {
  local status="$1"
  local message="$2"
  local duration_ms="$3"

  PW_REPORT_STATUS="${status}" \
  PW_REPORT_MESSAGE="${message}" \
  PW_REPORT_DURATION_MS="${duration_ms}" \
  /usr/bin/python3 - <<'PY'
import json
import os

def maybe_int(value):
    try:
        return int(value)
    except Exception:
        return None

report = {
    "schema_version": 1,
    "suite": os.environ.get("PW_TEST_SUITE", ""),
    "test_id": os.environ.get("PW_TEST_ID", ""),
    "status": os.environ.get("PW_REPORT_STATUS", ""),
    "message": os.environ.get("PW_REPORT_MESSAGE", ""),
    "duration_ms": maybe_int(os.environ.get("PW_REPORT_DURATION_MS")),
    "artifacts_dir": os.environ.get("PW_TEST_ARTIFACTS", ""),
    "notes": [],
}

path = os.environ.get("PW_TEST_REPORT", "")
if not path:
    raise SystemExit("missing PW_TEST_REPORT path")
with open(path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
PY
}

test_pass() {
  local message="${1:-ok}"
  local data_json="${2:-}"
  local end_ms
  end_ms="$(now_ms)"
  local duration_ms=$((end_ms - ${PW_TEST_START_MS:-end_ms}))

  local event_line
  event_line="$(emit_event "pass" "test_end" "${message}" "${data_json}" "${duration_ms}")"
  write_json_line "${event_line}" "${PW_TEST_EVENTS}"
  write_json_line "${event_line}" "${PW_TEST_EVENTS_LOCAL}"
  write_report "pass" "${message}" "${duration_ms}"
  test_log "pass: ${message}"
}

test_fail() {
  local message="${1:-failed}"
  local data_json="${2:-}"
  local end_ms
  end_ms="$(now_ms)"
  local duration_ms=$((end_ms - ${PW_TEST_START_MS:-end_ms}))

  local event_line
  event_line="$(emit_event "fail" "test_end" "${message}" "${data_json}" "${duration_ms}")"
  if [[ -n "${PW_TEST_EVENTS:-}" ]]; then
    write_json_line "${event_line}" "${PW_TEST_EVENTS}"
  fi
  if [[ -n "${PW_TEST_EVENTS_LOCAL:-}" ]]; then
    write_json_line "${event_line}" "${PW_TEST_EVENTS_LOCAL}"
  fi
  write_report "fail" "${message}" "${duration_ms}"
  echo "FAIL: [${PW_TEST_SUITE:-unknown}/${PW_TEST_ID:-unknown}] ${message}" 1>&2
  exit 1
}

test_skip() {
  local message="${1:-skipped}"
  local data_json="${2:-}"
  local end_ms
  end_ms="$(now_ms)"
  local duration_ms=$((end_ms - ${PW_TEST_START_MS:-end_ms}))

  local event_line
  event_line="$(emit_event "skip" "test_end" "${message}" "${data_json}" "${duration_ms}")"
  write_json_line "${event_line}" "${PW_TEST_EVENTS}"
  write_json_line "${event_line}" "${PW_TEST_EVENTS_LOCAL}"
  write_report "skip" "${message}" "${duration_ms}"
  test_log "skip: ${message}"
}
