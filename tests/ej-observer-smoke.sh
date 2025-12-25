#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EJ="${EJ_BIN:-${ROOT_DIR}/EntitlementJail.app/Contents/MacOS/entitlement-jail}"
OBSERVER="${EJ%/*}/sandbox-log-observer"
OUT_DIR="${EJ_OBSERVER_SMOKE_OUT_DIR:-${ROOT_DIR}/tests/out/observer-smoke}"

CURRENT_STEP=""

fail() {
  echo "FAIL: ${CURRENT_STEP}" 1>&2
}

trap fail ERR

step() {
  CURRENT_STEP="$1"
  echo "==> ${CURRENT_STEP}"
}

if [[ ! -x "${EJ}" ]]; then
  echo "ERROR: missing or non-executable EntitlementJail launcher at: ${EJ}" 1>&2
  echo "hint: run \`make build\` first, or set EJ_BIN to the launcher path" 1>&2
  exit 2
fi

if [[ ! -x "${OBSERVER}" ]]; then
  echo "ERROR: missing or non-executable sandbox-log-observer at: ${OBSERVER}" 1>&2
  exit 2
fi

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

uuid() {
  /usr/bin/python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
}

step "sandbox-log-observer JSON (show)"
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

step "sandbox-log-observer JSONL (stream)"
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

step "run-xpc --observe (no stream)"
RUN_XPC_OBSERVE_JSON="${OUT_DIR}/run-xpc-observe.json"
"${EJ}" run-xpc --observe --profile minimal capabilities_snapshot > "${RUN_XPC_OBSERVE_JSON}"

/usr/bin/python3 - "${RUN_XPC_OBSERVE_JSON}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data_section = data.get("data") or {}

status = data_section.get("log_observer_status")
if status != "requested_written":
    raise SystemExit(f"expected log_observer_status=requested_written; got {status!r}")

observer_path = data_section.get("log_observer_path")
if not observer_path:
    raise SystemExit("missing log_observer_path")
if not Path(observer_path).exists():
    raise SystemExit(f"missing observer report file: {observer_path}")

report = data_section.get("log_observer_report") or {}
if report.get("kind") != "sandbox_log_observer_report":
    raise SystemExit(f"unexpected log_observer_report kind: {report.get('kind')!r}")
report_data = report.get("data") or {}
if report_data.get("observer_schema_version") != 1:
    raise SystemExit(f"unexpected observer_schema_version: {report_data.get('observer_schema_version')!r}")
if report_data.get("mode") not in ("show", "stream"):
    raise SystemExit(f"unexpected observer mode: {report_data.get('mode')!r}")
PY

step "run-xpc --log-stream stdout with json-out"
STREAM_STDOUT_JSON="${OUT_DIR}/log-stream-stdout.json"
STREAM_PROBE_JSON="${OUT_DIR}/run-xpc-stdout.json"
RUN_XPC_EXIT_CODE=0
"${EJ}" run-xpc --log-stream stdout --json-out "${STREAM_PROBE_JSON}" --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9 > "${STREAM_STDOUT_JSON}" || RUN_XPC_EXIT_CODE="$?"
echo "run-xpc exit_code=${RUN_XPC_EXIT_CODE} (expected: 1 for denial-shaped probe)"

/usr/bin/python3 - "${STREAM_STDOUT_JSON}" "${STREAM_PROBE_JSON}" <<'PY'
import json
import sys
from pathlib import Path

log_path = Path(sys.argv[1])
probe_path = Path(sys.argv[2])
log = json.loads(log_path.read_text(encoding="utf-8"))
if log.get("kind") != "sandbox_log_stream_report":
    raise SystemExit(f"unexpected log stream kind: {log.get('kind')!r}")

probe = json.loads(probe_path.read_text(encoding="utf-8"))
data = probe.get("data") or {}
if data.get("log_capture_path") not in ("stdout", "-"):
    raise SystemExit(f"expected log_capture_path to be stdout; got {data.get('log_capture_path')!r}")
if data.get("log_capture_status") is None:
    raise SystemExit("missing log_capture_status")
if not data.get("log_observer_path"):
    raise SystemExit("missing log_observer_path")
PY

step "run-xpc --log-stream stdout requires --json-out"
BAD_EXIT=0
"${EJ}" run-xpc --log-stream stdout --profile minimal capabilities_snapshot > "${OUT_DIR}/bad-stdout.json" 2> "${OUT_DIR}/bad-stdout.err" || BAD_EXIT="$?"
if [[ "${BAD_EXIT}" -eq 0 ]]; then
  echo "expected run-xpc to fail without --json-out when --log-stream stdout is used" 1>&2
  exit 1
fi

echo "OK: ${OUT_DIR}"
