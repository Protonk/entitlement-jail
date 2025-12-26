#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EJ="${EJ_BIN:-${ROOT_DIR}/EntitlementJail.app/Contents/MacOS/entitlement-jail}"
OUT_DIR="${EJ_APP_SMOKE_OUT_DIR:-${ROOT_DIR}/tests/out/app-smoke}"

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

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

step "Deny-shaped probe with log capture"
LOG_PATH="${OUT_DIR}/logs/minimal_net_op.log"
RUN_XPC_JSON="${OUT_DIR}/run-xpc-minimal-net-op.json"
RUN_XPC_EXIT_CODE=0
"${EJ}" run-xpc --log-stream "${LOG_PATH}" --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9 >"${RUN_XPC_JSON}" || RUN_XPC_EXIT_CODE="$?"
echo "run-xpc exit_code=${RUN_XPC_EXIT_CODE} (expected: 1 for denial-shaped probe)"

/usr/bin/python3 - "${RUN_XPC_JSON}" "${LOG_PATH}" <<'PY'
import json
import sys
from pathlib import Path

run_json_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
observer_path = Path(str(log_path) + ".observer.json")

data = json.loads(run_json_path.read_text(encoding="utf-8"))
data_section = data.get("data") or {}

result = data.get("result") or {}
normalized_outcome = result.get("normalized_outcome")
errno = result.get("errno")

if normalized_outcome != "permission_error":
    raise SystemExit(f"expected result.normalized_outcome='permission_error' (denial-shaped); got {normalized_outcome!r} (errno={errno!r})")
if errno not in (1, 13):
    raise SystemExit(f"expected result.errno in (EPERM=1, EACCES=13); got {errno!r}")

status = data_section.get("log_capture_status")
err = data_section.get("log_capture_error")
deny_evidence = data_section.get("deny_evidence")
observer_path_field = data_section.get("log_observer_path")

if status != "requested_written":
    raise SystemExit(f"expected data.log_capture_status=requested_written; got {status!r} (error={err!r})")
if err not in (None, ""):
    raise SystemExit(f"expected data.log_capture_error to be null/empty; got {err!r}")
if not log_path.exists():
    raise SystemExit(f"missing log capture file: {log_path}")
if not observer_path.exists():
    raise SystemExit(f"missing observer capture file: {observer_path}")
if observer_path_field != str(observer_path):
    raise SystemExit(f"expected data.log_observer_path={str(observer_path)!r}; got {observer_path_field!r}")

contents = log_path.read_text(encoding="utf-8", errors="replace")
report = json.loads(contents)
report_kind = report.get("kind")
report_data = report.get("data") or {}
log_stdout = report_data.get("log_stdout") or ""
log_stderr = report_data.get("log_stderr") or ""
log_error = report_data.get("log_error") or ""
stream_observed_deny = report_data.get("observed_deny")

lower = "\n".join([log_stdout, log_stderr, str(log_error)]).lower()
if "cannot run while sandboxed" in lower:
    raise SystemExit("log capture shows 'Cannot run while sandboxed' (expected unsandboxed host-side log access)")
if report_kind != "sandbox_log_stream_report":
    raise SystemExit(f"unexpected log capture kind: {report_kind!r}")

observer = json.loads(observer_path.read_text(encoding="utf-8", errors="replace"))
observer_kind = observer.get("kind")
observer_data = observer.get("data") or {}
observer_observed_deny = observer_data.get("observed_deny")
deny_lines = observer_data.get("deny_lines") or []

if observer_kind != "sandbox_log_observer_report":
    raise SystemExit(f"unexpected observer kind: {observer_kind!r}")
if not isinstance(deny_lines, list):
    raise SystemExit(f"expected observer deny_lines list; got {type(deny_lines)}")
if observer_observed_deny is True and len(deny_lines) == 0:
    raise SystemExit("expected deny_lines entries when observed_deny=true")

if deny_evidence not in ("captured", "not_found"):
    raise SystemExit(f"unexpected data.deny_evidence value: {deny_evidence!r}")
if deny_evidence == "captured" and not (stream_observed_deny or observer_observed_deny):
    raise SystemExit("expected stream or observer observed_deny=true when deny_evidence=captured")
if deny_evidence == "captured":
    stream_has_deny = "deny" in log_stdout.lower()
    observer_has_deny = len(deny_lines) > 0
    if not (stream_has_deny or observer_has_deny):
        raise SystemExit("expected deny evidence in stream or observer output; got no match")
if deny_evidence == "not_found":
    print("note: deny evidence not found (this can happen on systems that do not persist sandbox denials in the unified log store)")
PY

step "Attach-friendly sandbox_check (pid-ready + attach-report)"
ATTACH_DIR="${OUT_DIR}/attach"
mkdir -p "${ATTACH_DIR}"
ATTACH_REPORT="${ATTACH_DIR}/attach.jsonl"
ATTACH_STDERR="${ATTACH_DIR}/run-xpc.stderr"
ATTACH_RUN_JSON="${ATTACH_DIR}/run-xpc-sandbox-check.json"

"${EJ}" run-xpc --attach 10 --hold-open 0 --attach-report "${ATTACH_REPORT}" --profile minimal sandbox_check --operation file-read-data --path /etc/hosts >"${ATTACH_RUN_JSON}" 2>"${ATTACH_STDERR}" &
ATTACH_RUN_PID="$!"

WAIT_PATH=""
for _ in $(seq 1 200); do
  if [[ -f "${ATTACH_REPORT}" ]]; then
    WAIT_PATH="$(/usr/bin/python3 - "${ATTACH_REPORT}" <<'PY'
import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        ev = json.loads(line)
    except Exception:
        continue
    if ev.get("kind") == "attach_event" and ev.get("event") == "wait_ready":
        wait_path = ev.get("wait_path") or ""
        if wait_path:
            print(wait_path)
            break
PY
)"
  fi
  if [[ -n "${WAIT_PATH}" ]]; then
    break
  fi
  sleep 0.05
done

if [[ -z "${WAIT_PATH}" ]]; then
  echo "missing wait_path in attach report: ${ATTACH_REPORT}" 1>&2
  echo "stderr:" 1>&2
  sed -n '1,200p' "${ATTACH_STDERR}" 1>&2 || true
  kill "${ATTACH_RUN_PID}" 2>/dev/null || true
  wait "${ATTACH_RUN_PID}" 2>/dev/null || true
  exit 1
fi

SERVICE_PID=""
for _ in $(seq 1 200); do
  if [[ -f "${ATTACH_REPORT}" ]]; then
    SERVICE_PID="$(/usr/bin/python3 - "${ATTACH_REPORT}" <<'PY'
import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        ev = json.loads(line)
    except Exception:
        continue
    if ev.get("kind") == "attach_event" and ev.get("event") == "pid_ready":
        pid = ev.get("pid")
        if isinstance(pid, int) and pid > 0:
            print(pid)
            break
PY
)"
  fi
  if [[ -n "${SERVICE_PID}" ]]; then
    break
  fi
  sleep 0.05
done

if [[ -z "${SERVICE_PID}" ]]; then
  echo "missing pid in attach report: ${ATTACH_REPORT}" 1>&2
  echo "stderr:" 1>&2
  sed -n '1,200p' "${ATTACH_STDERR}" 1>&2 || true
  kill "${ATTACH_RUN_PID}" 2>/dev/null || true
  wait "${ATTACH_RUN_PID}" 2>/dev/null || true
  exit 1
fi

# The FIFO is created by the service; wait briefly so the writer doesn't race with FIFO creation.
for _ in $(seq 1 200); do
  if [[ -p "${WAIT_PATH}" ]]; then
    break
  fi
  sleep 0.05
done

printf go > "${WAIT_PATH}"
wait "${ATTACH_RUN_PID}"

/usr/bin/python3 - "${ATTACH_RUN_JSON}" "${ATTACH_REPORT}" "${ATTACH_STDERR}" <<'PY'
import json
import sys
from pathlib import Path

run_json_path = Path(sys.argv[1])
attach_report_path = Path(sys.argv[2])
stderr_path = Path(sys.argv[3])

data = json.loads(run_json_path.read_text(encoding="utf-8", errors="replace"))
result = data.get("result") or {}
if result.get("ok") is not True:
    raise SystemExit(f"expected run-xpc ok=true; got {result!r}")

details = (data.get("data") or {}).get("details") or {}
if details.get("probe_family") != "sandbox_check":
    raise SystemExit(f"expected data.details.probe_family='sandbox_check'; got {details.get('probe_family')!r}")
if not (details.get("sandbox_check_rc") or ""):
    raise SystemExit("expected data.details.sandbox_check_rc to be present")

events = []
for line in attach_report_path.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        ev = json.loads(line)
    except Exception:
        continue
    if ev.get("kind") == "attach_event":
        events.append(ev)

have_wait = any(ev.get("event") == "wait_ready" and (ev.get("wait_path") or "") for ev in events)
have_pid = any(ev.get("event") == "pid_ready" and isinstance(ev.get("pid"), int) for ev in events)
if not have_wait:
    raise SystemExit("expected attach report to include wait_ready with wait_path")
if not have_pid:
    raise SystemExit("expected attach report to include pid_ready with pid")

stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
if "[client] pid-ready" not in stderr:
    raise SystemExit("expected pid-ready status line on stderr")
PY

step "Preload dylib (instrumentation hookpoint)"
PREFLIGHT_JSON="${EJ_PREFLIGHT_JSON:-${ROOT_DIR}/tests/out/preflight.json}"
TEST_DYLIB="${ROOT_DIR}/tests/fixtures/TestDylib/out/testdylib.dylib"
RUN_PRELOAD=0
if [[ -f "${PREFLIGHT_JSON}" ]]; then
  RUN_PRELOAD="$(/usr/bin/python3 - "${PREFLIGHT_JSON}" <<'PY'
import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
try:
    data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
except Exception:
    print(0)
    raise SystemExit(0)

dylib_signed = ((data.get("test_dylib") or {}).get("signed") is True)
svc = (data.get("services") or {}).get("get-task-allow") or {}
disable_lv = ((svc.get("entitlements") or {}).get("disable_library_validation") is True)
print(1 if (dylib_signed and disable_lv) else 0)
PY
)"
fi

if [[ "${RUN_PRELOAD}" != "1" ]]; then
  echo "skip preload test: missing signed test dylib or disable-library-validation entitlement"
else
  PRELOAD_DIR="${OUT_DIR}/preload"
  mkdir -p "${PRELOAD_DIR}"
  PRELOAD_JSON="${PRELOAD_DIR}/run-xpc-preload-dylib.json"
  "${EJ}" run-xpc --profile get-task-allow --preload-dylib "${TEST_DYLIB}" --preload-dylib-stage sandbox_check --operation file-read-data --path /etc/hosts >"${PRELOAD_JSON}"

  /usr/bin/python3 - "${PRELOAD_JSON}" "${TEST_DYLIB}" <<'PY'
import json
import sys
from pathlib import Path

run_json_path = Path(sys.argv[1])
dylib_path = sys.argv[2]

data = json.loads(run_json_path.read_text(encoding="utf-8", errors="replace"))
result = data.get("result") or {}
if result.get("ok") is not True:
    raise SystemExit(f"expected run-xpc ok=true; got {result!r}")

details = (data.get("data") or {}).get("details") or {}
if details.get("preload_dylib_outcome") != "ok":
    raise SystemExit(f"expected data.details.preload_dylib_outcome='ok'; got {details.get('preload_dylib_outcome')!r}")

preload_path = details.get("preload_dylib_path") or ""
if not isinstance(preload_path, str) or not preload_path:
    raise SystemExit("expected data.details.preload_dylib_path to be present")
if not preload_path.endswith(".dylib"):
    raise SystemExit(f"expected data.details.preload_dylib_path to end with .dylib; got {preload_path!r}")
if not Path(preload_path).exists():
    raise SystemExit(f"expected staged preload dylib to exist at {preload_path!r}")
PY
fi

step "Repo --out write (run-matrix)"
MATRIX_DIR="${OUT_DIR}/matrix-baseline"
mkdir -p "${MATRIX_DIR}"
echo "sentinel" >"${MATRIX_DIR}/sentinel.txt"

RUN_MATRIX_ENVELOPE="${OUT_DIR}/run-matrix-envelope.json"
"${EJ}" run-matrix --group baseline --out "${MATRIX_DIR}" capabilities_snapshot >"${RUN_MATRIX_ENVELOPE}"

if [[ ! -f "${MATRIX_DIR}/run-matrix.json" ]]; then
  echo "missing: ${MATRIX_DIR}/run-matrix.json" 1>&2
  exit 1
fi
if [[ ! -f "${MATRIX_DIR}/run-matrix.table.txt" ]]; then
  echo "missing: ${MATRIX_DIR}/run-matrix.table.txt" 1>&2
  exit 1
fi

/usr/bin/python3 - "${RUN_MATRIX_ENVELOPE}" "${MATRIX_DIR}" <<'PY'
import json
import sys
from pathlib import Path

envelope_path = Path(sys.argv[1])
expected = Path(sys.argv[2])

data = json.loads(envelope_path.read_text(encoding="utf-8"))
out_dir = (data.get("data") or {}).get("output_dir")
if out_dir != str(expected):
    raise SystemExit(f"expected data.output_dir={str(expected)!r}; got {out_dir!r}")

group_id = (data.get("data") or {}).get("group_id")
if group_id != "baseline":
    raise SystemExit(f"expected data.group_id='baseline'; got {group_id!r}")
profiles = (data.get("data") or {}).get("profiles") or []
if profiles != ["minimal"]:
    raise SystemExit(f"expected data.profiles=['minimal']; got {profiles!r}")
PY

echo "OK: ${OUT_DIR}"
