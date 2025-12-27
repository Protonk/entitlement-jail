#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

CURRENT_STEP=""

test_begin "smoke" "observer.basic"

fail() {
  test_fail "${CURRENT_STEP:-observer smoke failed}"
}

trap fail ERR

step() {
  CURRENT_STEP="$1"
  test_step "$1" "${2:-$1}"
}

EJ="${EJ_BIN:-${ROOT_DIR}/EntitlementJail.app/Contents/MacOS/entitlement-jail}"
OBSERVER="${EJ%/*}/sandbox-log-observer"
OUT_DIR="${EJ_TEST_ARTIFACTS}"

if [[ ! -x "${EJ}" ]]; then
  test_fail "missing or non-executable EntitlementJail launcher at: ${EJ}"
fi

if [[ ! -x "${OBSERVER}" ]]; then
  test_fail "missing or non-executable sandbox-log-observer at: ${OBSERVER}"
fi

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

uuid() {
  /usr/bin/python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
}

step "observer_json_show" "sandbox-log-observer JSON (show)"
TOKEN="$(uuid)"
/usr/bin/logger "ej-observer-test deny ${TOKEN}"
sleep 0.5

SHOW_JSON="${OUT_DIR}/observer-show.json"
"${OBSERVER}" \
  --pid $$ \
  --process-name ej-test \
  --last 10s \
  --predicate "eventMessage CONTAINS[c] \"${TOKEN}\"" \
  --output "${SHOW_JSON}" \
  >/dev/null

/usr/bin/python3 - "${SHOW_JSON}" "${TOKEN}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
token = sys.argv[2]
data = json.loads(path.read_text(encoding="utf-8"))
if data.get("kind") != "sandbox_log_observer_report":
    raise SystemExit(f"unexpected kind: {data.get('kind')!r}")
report = data.get("data") or {}
if report.get("observer_schema_version") != 1:
    raise SystemExit(f"unexpected observer_schema_version: {report.get('observer_schema_version')!r}")
if report.get("mode") != "show":
    raise SystemExit(f"expected mode='show'; got {report.get('mode')!r}")
if report.get("observed_deny") is not True:
    raise SystemExit("expected observed_deny=true")
deny_lines = report.get("deny_lines") or []
if not any(token in line for line in deny_lines):
    raise SystemExit("expected deny_lines to include the emitted token")
PY

step "observer_jsonl_stream" "sandbox-log-observer JSONL (stream)"
TOKEN_STREAM="$(uuid)"
JSONL_PATH="${OUT_DIR}/observer-stream.jsonl"
"${OBSERVER}" \
  --pid $$ \
  --process-name ej-test \
  --duration 3 \
  --format jsonl \
  --predicate "eventMessage CONTAINS[c] \"${TOKEN_STREAM}\"" \
  --output "${JSONL_PATH}" \
  >/dev/null 2>&1 &
OBS_PID=$!

sleep 0.5
/usr/bin/logger "ej-observer-test deny ${TOKEN_STREAM}"
wait "${OBS_PID}"

/usr/bin/python3 - "${JSONL_PATH}" "${TOKEN_STREAM}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
token = sys.argv[2]
lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
if not lines:
    raise SystemExit("expected jsonl output lines")

events = []
report = None
for line in lines:
    data = json.loads(line)
    kind = data.get("kind")
    if kind == "sandbox_log_observer_event":
        events.append(data)
    elif kind == "sandbox_log_observer_report":
        report = data

if report is None:
    raise SystemExit("missing sandbox_log_observer_report line")

report_data = report.get("data") or {}
if report_data.get("observer_schema_version") != 1:
    raise SystemExit(f"unexpected observer_schema_version: {report_data.get('observer_schema_version')!r}")
if report_data.get("mode") != "stream":
    raise SystemExit(f"expected mode='stream'; got {report_data.get('mode')!r}")
if report_data.get("observed_deny") is not True:
    raise SystemExit("expected observed_deny=true in stream report")

if not events:
    raise SystemExit("expected sandbox_log_observer_event lines")

matching = [
    ev for ev in events
    if token in ((ev.get("data") or {}).get("line") or "") and (ev.get("data") or {}).get("is_deny") is True
]
if not matching:
    raise SystemExit("expected at least one deny event containing the token")
PY

test_pass "smoke artifacts written" "{\"out_dir\":\"${OUT_DIR}\"}"
