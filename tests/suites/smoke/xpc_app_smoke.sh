#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

CURRENT_STEP=""

test_begin "smoke" "xpc.app_smoke"

fail() {
  test_fail "${CURRENT_STEP:-xpc app smoke failed}"
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

step "xpc_run_minimal_capabilities" "xpc run (minimal capabilities_snapshot)"
CAP_JSON="${OUT_DIR}/xpc-run-minimal-capabilities.json"
"${EJ}" xpc run --profile minimal capabilities_snapshot >"${CAP_JSON}"

/usr/bin/python3 - "${CAP_JSON}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8", errors="replace"))

if data.get("kind") != "probe_response":
    raise SystemExit(f"unexpected kind: {data.get('kind')!r}")
result = data.get("result") or {}
if result.get("ok") is not True:
    raise SystemExit(f"expected ok=true; got {result!r}")
details = ((data.get("data") or {}).get("details") or {})
if details.get("probe_family") != "capabilities_snapshot":
    raise SystemExit(f"expected data.details.probe_family='capabilities_snapshot'; got {details.get('probe_family')!r}")
PY

step "xpc_run_minimal_net_op" "xpc run (denial-shaped minimal net_op)"
NET_JSON="${OUT_DIR}/xpc-run-minimal-net-op.json"
NET_EXIT=0
"${EJ}" xpc run --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9 >"${NET_JSON}" || NET_EXIT="$?"
test_step "net_op_exit_code" "xpc run exit_code=${NET_EXIT} (expected: 1 for denial-shaped probe)"

/usr/bin/python3 - "${NET_JSON}" "${NET_EXIT}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
exit_code = int(sys.argv[2])

data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
if data.get("kind") != "probe_response":
    raise SystemExit(f"unexpected kind: {data.get('kind')!r}")

result = data.get("result") or {}
normalized_outcome = result.get("normalized_outcome")
errno = result.get("errno")

if exit_code != 1:
    raise SystemExit(f"expected exit code 1 for denial-shaped probe, got {exit_code}")
if normalized_outcome != "permission_error":
    raise SystemExit(f"expected normalized_outcome='permission_error'; got {normalized_outcome!r} (errno={errno!r})")
if errno not in (1, 13):
    raise SystemExit(f"expected errno in (EPERM=1, EACCES=13); got {errno!r}")
PY

step "run_matrix_baseline" "repo --out write (run-matrix baseline)"
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

data = json.loads(envelope_path.read_text(encoding="utf-8", errors="replace"))
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

test_pass "smoke artifacts written" "{\"out_dir\":\"${OUT_DIR}\"}"
