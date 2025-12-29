#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

CURRENT_STEP=""

test_begin "smoke" "xpc.session_smoke"

fail() {
  test_fail "${CURRENT_STEP:-xpc session smoke failed}"
}

trap fail ERR

step() {
  CURRENT_STEP="$1"
  test_step "$1" "${2:-$1}"
}

EJ="${EJ_BIN:-${ROOT_DIR}/EntitlementJail.app/Contents/MacOS/entitlement-jail}"
OUT_DIR="${EJ_TEST_ARTIFACTS}"

if [[ ! -x "${EJ}" ]]; then
  test_fail "missing or non-executable EntitlementJail launcher at: ${EJ}"
fi

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

CONTROL_FIFO="${OUT_DIR}/control.fifo"
rm -f "${CONTROL_FIFO}"
mkfifo "${CONTROL_FIFO}"

SESSION_JSONL="${OUT_DIR}/session.jsonl"
SESSION_STDERR="${OUT_DIR}/session.stderr"

step "open_session" "open session (attach wait)"
exec 3<> "${CONTROL_FIFO}"

"${EJ}" xpc session --profile minimal --variant injectable --wait fifo:auto --wait-timeout-ms 10000 0<&3 >"${SESSION_JSONL}" 2>"${SESSION_STDERR}" &
SESSION_PID="$!"

python3 - "${SESSION_JSONL}" <<'PY'
import json
import sys
import time
from pathlib import Path

p = Path(sys.argv[1])
deadline = time.time() + 10.0

have_ready = False
while time.time() < deadline:
    if p.exists() and p.stat().st_size > 0:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("kind") == "xpc_session_event":
                data = obj.get("data") or {}
                if data.get("event") == "session_ready":
                    have_ready = True
                    break
    if have_ready:
        break
    time.sleep(0.05)

if not have_ready:
    raise SystemExit("timed out waiting for session_ready event")
PY

WAIT_PATH="$(python3 - "${SESSION_JSONL}" <<'PY'
import json
import sys
from pathlib import Path

p = Path(sys.argv[1])
token = None
wait_path = None
pid = None

for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get("kind") != "xpc_session_event":
        continue
    data = obj.get("data") or {}
    if data.get("event") == "session_ready":
        token = data.get("session_token")
        pid = data.get("pid")
        wait_path = data.get("wait_path")
        break

if not token:
    raise SystemExit("missing session_token in session_ready")
if not isinstance(pid, int) or pid <= 0:
    raise SystemExit(f"missing/invalid pid in session_ready: {pid!r}")
if not wait_path or not isinstance(wait_path, str):
    raise SystemExit("missing wait_path in session_ready (expected --wait fifo:auto)")

print(wait_path)
PY
)"

step "trigger_wait_fifo" "trigger wait FIFO"
# Wait for FIFO creation (the service creates it).
for _ in $(seq 1 200); do
  if [[ -p "${WAIT_PATH}" ]]; then
    break
  fi
  sleep 0.05
done

if [[ ! -p "${WAIT_PATH}" ]]; then
  sed -n '1,200p' "${SESSION_STDERR}" 1>&2 || true
  kill "${SESSION_PID}" 2>/dev/null || true
  wait "${SESSION_PID}" 2>/dev/null || true
  test_fail "expected wait_path to be a FIFO" "{\"wait_path\":\"${WAIT_PATH}\"}"
fi

printf go > "${WAIT_PATH}"

python3 - "${SESSION_JSONL}" <<'PY'
import json
import sys
import time
from pathlib import Path

p = Path(sys.argv[1])
deadline = time.time() + 10.0

while time.time() < deadline:
    if p.exists() and p.stat().st_size > 0:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("kind") != "xpc_session_event":
                continue
            data = obj.get("data") or {}
            if data.get("event") == "trigger_received":
                raise SystemExit(0)
    time.sleep(0.05)

raise SystemExit("timed out waiting for trigger_received event")
PY

step "run_probes" "run two probes inside the session"
printf '%s\n' '{"command":"run_probe","probe_id":"sandbox_check","argv":["--operation","file-read-data","--path","/etc/hosts"]}' >&3
printf '%s\n' '{"command":"run_probe","probe_id":"capabilities_snapshot"}' >&3

python3 - "${SESSION_JSONL}" <<'PY'
import json
import sys
import time
from pathlib import Path

p = Path(sys.argv[1])
deadline = time.time() + 15.0

session_token = None
probe_ids = []
service_pids = []

def scan():
    global session_token
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("kind") == "xpc_session_event":
            data = obj.get("data") or {}
            if data.get("event") == "session_ready":
                session_token = data.get("session_token") or session_token
        if obj.get("kind") == "probe_response":
            data = obj.get("data") or {}
            details = (data.get("details") or {})
            if session_token and details.get("session_token") != session_token:
                raise SystemExit("probe_response missing/mismatched details.session_token")
            probe_id = data.get("probe_id")
            if probe_id:
                probe_ids.append(probe_id)
            pid = details.get("service_pid") or details.get("pid")
            if pid:
                service_pids.append(pid)

while time.time() < deadline:
    if p.exists() and p.stat().st_size > 0:
        scan()
        if "sandbox_check" in probe_ids and "capabilities_snapshot" in probe_ids:
            break
    time.sleep(0.05)

if "sandbox_check" not in probe_ids or "capabilities_snapshot" not in probe_ids:
    raise SystemExit(f"missing expected probe_response entries; saw probe_ids={probe_ids!r}")

service_pids = [p for p in service_pids if str(p).strip()]
if len(set(service_pids)) != 1:
    raise SystemExit(f"expected a stable service pid across probes; saw {sorted(set(service_pids))!r}")
PY

step "close_session" "close session"
printf '%s\n' '{"command":"close_session"}' >&3
exec 3>&-

wait "${SESSION_PID}"

test_pass "smoke artifacts written" "{\"out_dir\":\"${OUT_DIR}\"}"
