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

data = json.loads(run_json_path.read_text(encoding="utf-8"))

result = data.get("result") or {}
normalized_outcome = result.get("normalized_outcome")
errno = result.get("errno")

if normalized_outcome != "permission_error":
    raise SystemExit(f"expected result.normalized_outcome='permission_error' (denial-shaped); got {normalized_outcome!r} (errno={errno!r})")
if errno not in (1, 13):
    raise SystemExit(f"expected result.errno in (EPERM=1, EACCES=13); got {errno!r}")

status = (data.get("data") or {}).get("log_capture_status")
err = (data.get("data") or {}).get("log_capture_error")
deny_evidence = (data.get("data") or {}).get("deny_evidence")

if status != "requested_written":
    raise SystemExit(f"expected data.log_capture_status=requested_written; got {status!r} (error={err!r})")
if err not in (None, ""):
    raise SystemExit(f"expected data.log_capture_error to be null/empty; got {err!r}")
if not log_path.exists():
    raise SystemExit(f"missing log capture file: {log_path}")

contents = log_path.read_text(encoding="utf-8", errors="replace")
lower = contents.lower()
if "cannot run while sandboxed" in lower:
    raise SystemExit("log capture shows 'Cannot run while sandboxed' (expected unsandboxed host-side log access)")

if deny_evidence not in ("captured", "not_found"):
    raise SystemExit(f"unexpected data.deny_evidence value: {deny_evidence!r}")
if deny_evidence == "captured" and "deny" not in lower:
    raise SystemExit("expected deny evidence to include a sandbox denial line (substring 'deny'); got no match")
if deny_evidence == "not_found":
    print("note: deny evidence not found (this can happen on systems that do not persist sandbox denials in the unified log store)")
PY

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
PY

echo "OK: ${OUT_DIR}"
