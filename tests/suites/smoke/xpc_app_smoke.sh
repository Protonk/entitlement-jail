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

PW="${PW_BIN:-${ROOT_DIR}/PolicyWitness.app/Contents/MacOS/policy-witness}"
OUT_DIR="${PW_TEST_ARTIFACTS}"

if [[ ! -x "${PW}" ]]; then
  test_fail "missing or non-executable PolicyWitness launcher at: ${PW}"
fi

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

step "xpc_run_minimal_capabilities" "xpc run (minimal capabilities_snapshot)"
CAP_JSON="${OUT_DIR}/xpc-run-minimal-capabilities.json"
"${PW}" xpc run --profile minimal capabilities_snapshot >"${CAP_JSON}"

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
"${PW}" xpc run --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9 >"${NET_JSON}" || NET_EXIT="$?"
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

step "xpc_run_inherit_child" "xpc run (temporary_exception inherit_child)"
INHERIT_JSON="${OUT_DIR}/xpc-run-inherit-child.json"
INHERIT_PATH="${HOME}/Documents/pw_smoke_inherit_child.txt"
mkdir -p "${HOME}/Documents"
printf "policy-witness smoke\n" >"${INHERIT_PATH}"
"${PW}" xpc run --profile temporary_exception inherit_child --scenario dynamic_extension --path "${INHERIT_PATH}" --allow-unsafe-path >"${INHERIT_JSON}"

/usr/bin/python3 - "${INHERIT_JSON}" <<'PY'
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
witness = (data.get("data") or {}).get("witness") or {}
run_id = witness.get("run_id")
if not run_id:
    raise SystemExit("missing witness.run_id")
parent_pid = witness.get("parent_pid")
child_pid = witness.get("child_pid")
if not isinstance(parent_pid, int) or parent_pid <= 0:
    raise SystemExit(f"invalid witness.parent_pid: {parent_pid!r}")
if not isinstance(child_pid, int) or child_pid <= 0:
    raise SystemExit(f"invalid witness.child_pid: {child_pid!r}")
for field in ("child_path", "service_bundle_id", "process_name", "child_bundle_id", "child_team_id"):
    if not witness.get(field):
        raise SystemExit(f"missing witness.{field}")
protocol_version = witness.get("protocol_version")
cap_namespace = witness.get("capability_namespace")
if protocol_version != 1:
    raise SystemExit(f"expected protocol_version=1; got {protocol_version!r}")
if cap_namespace != "inherit_child.cap.v1":
    raise SystemExit(f"expected capability_namespace='inherit_child.cap.v1'; got {cap_namespace!r}")
child_event_fd = witness.get("child_event_fd")
child_rights_fd = witness.get("child_rights_fd")
if not isinstance(child_event_fd, int):
    raise SystemExit(f"invalid witness.child_event_fd: {child_event_fd!r}")
if not isinstance(child_rights_fd, int):
    raise SystemExit(f"invalid witness.child_rights_fd: {child_rights_fd!r}")
entitlements = witness.get("child_entitlements")
if not isinstance(entitlements, dict):
    raise SystemExit("missing witness.child_entitlements")
if entitlements.get("com.apple.security.app-sandbox") is not True:
    raise SystemExit("missing child_entitlements app-sandbox=true")
if entitlements.get("com.apple.security.inherit") is not True:
    raise SystemExit("missing child_entitlements inherit=true")
if witness.get("inherit_contract_ok") is not True:
    raise SystemExit(f"expected inherit_contract_ok=true; got {witness.get('inherit_contract_ok')!r}")
sandbox_status = witness.get("sandbox_log_capture_status")
if not isinstance(sandbox_status, str):
    raise SystemExit("missing witness.sandbox_log_capture_status")
if witness.get("protocol_error") is not None:
    raise SystemExit(f"unexpected protocol_error in witness: {witness.get('protocol_error')!r}")
events = witness.get("events") or []
if not isinstance(events, list) or not events:
    raise SystemExit("expected witness.events to be a non-empty list")

cap_results = witness.get("capability_results") or []
if not isinstance(cap_results, list) or not cap_results:
    raise SystemExit("expected witness.capability_results to be a non-empty list")

delta_found = False
for cap in cap_results:
    child_acquire = cap.get("child_acquire") or {}
    child_use = cap.get("child_use") or {}
    if child_acquire.get("rc") is None or child_use.get("rc") is None:
        continue
    if child_acquire.get("rc") != child_use.get("rc"):
        delta_found = True
        break
    if child_acquire.get("errno") != child_use.get("errno"):
        delta_found = True
        break
if not delta_found:
    raise SystemExit("expected at least one capability delta (child_acquire != child_use)")

callsite_found = False
backtrace_found = False
acquire_idx = None
use_idx = None
ready_idx = None
sentinel_idx = None
sentinel_lines = []
for idx, event in enumerate(events):
    details = event.get("details") or {}
    if event.get("phase") == "child_sentinel":
        sentinel_lines.append(details.get("line", ""))
        if sentinel_idx is None:
            sentinel_idx = idx
    if event.get("phase") == "child_ready" and ready_idx is None:
        ready_idx = idx
    if event.get("phase") == "child_acquire_attempt" and details.get("cap_id") == "file_fd":
        if acquire_idx is None:
            acquire_idx = idx
    if event.get("phase") == "child_use_attempt" and details.get("cap_id") == "file_fd":
        if use_idx is None:
            use_idx = idx
    if event.get("actor") == "child" and event.get("errno") in (1, 13) and event.get("callsite_id"):
        callsite_found = True
        if event.get("backtrace") or event.get("backtrace_error"):
            backtrace_found = True
if not callsite_found:
    raise SystemExit("expected at least one deny event with callsite_id")
if not backtrace_found:
    raise SystemExit("expected at least one deny event with backtrace or backtrace_error")
if acquire_idx is None or use_idx is None or acquire_idx >= use_idx:
    raise SystemExit("expected child acquire attempt to precede child use attempt")
if ready_idx is None or ready_idx >= acquire_idx:
    raise SystemExit("expected child_ready before child acquire attempt")
if sentinel_idx is None or sentinel_idx >= ready_idx:
    raise SystemExit("expected child_sentinel before child_ready (sentinel proves the child reached user code)")
if len(sentinel_lines) != 1:
    raise SystemExit(f"expected exactly one child_sentinel line; got {len(sentinel_lines)}")
line = sentinel_lines[0]
def find_kv(line, key):
    for part in line.split(" "):
        if part.startswith(key + "="):
            return part.split("=", 1)[1]
    return None
sent_event_fd = find_kv(line, "event_fd")
sent_rights_fd = find_kv(line, "rights_fd")
sent_proto = find_kv(line, "protocol_version")
sent_ns = find_kv(line, "cap_namespace")
if sent_event_fd is None or sent_rights_fd is None:
    raise SystemExit("sentinel missing event_fd/rights_fd")
if sent_proto is None or sent_ns is None:
    raise SystemExit("sentinel missing protocol_version/cap_namespace")
if int(sent_event_fd) != child_event_fd:
    raise SystemExit("sentinel event_fd does not match witness.child_event_fd")
if int(sent_rights_fd) != child_rights_fd:
    raise SystemExit("sentinel rights_fd does not match witness.child_rights_fd")
if int(sent_event_fd) == int(sent_rights_fd) or child_event_fd == child_rights_fd:
    raise SystemExit("expected distinct event bus and rights bus fds (two-channel design)")
if int(sent_proto) != protocol_version:
    raise SystemExit("sentinel protocol_version mismatch")
if sent_ns != cap_namespace:
    raise SystemExit("sentinel cap_namespace mismatch")
PY

step "xpc_run_inherit_child_stop_markers" "xpc run (stop-on-entry/deny inherit_child)"
STOP_JSON="${OUT_DIR}/xpc-run-inherit-child-stop-markers.json"
STOP_DENY_PATH="/private/var/db/launchd.db/com.apple.launchd/overrides.plist"
"${PW}" xpc run --profile temporary_exception inherit_child --scenario dynamic_extension --path "${STOP_DENY_PATH}" --allow-unsafe-path --stop-on-entry --stop-on-deny --stop-auto-resume >"${STOP_JSON}"

/usr/bin/python3 - "${STOP_JSON}" <<'PY'
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
witness = (data.get("data") or {}).get("witness") or {}
events = witness.get("events") or []
phases = [event.get("phase") for event in events]
if "child_stop_on_entry" not in phases:
    raise SystemExit("missing child_stop_on_entry event")
if "child_stopped" not in phases:
    raise SystemExit("missing parent child_stopped event")
if "child_resumed" not in phases:
    raise SystemExit("missing parent child_resumed event")
denies = [event for event in events if event.get("errno") in (1, 13)]
if denies and "child_stop_on_deny" not in phases:
    raise SystemExit("missing child_stop_on_deny event despite deny events")
PY

step "xpc_run_inherit_child_matrix_basic" "xpc run (matrix_basic inherit_child allowed-shaped)"
MATRIX_JSON="${OUT_DIR}/xpc-run-inherit-child-matrix-basic.json"
"${PW}" xpc run --profile minimal inherit_child --scenario matrix_basic --path-class tmp --target specimen_file --name pw_matrix_child.txt --create >"${MATRIX_JSON}"

/usr/bin/python3 - "${MATRIX_JSON}" <<'PY'
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
witness = (data.get("data") or {}).get("witness") or {}
cap_results = witness.get("capability_results") or []
expected_caps = {"file_fd", "dir_fd", "socket_fd"}
seen_caps = {cap.get("cap_id") for cap in cap_results}
missing = expected_caps - seen_caps
if missing:
    raise SystemExit(f"missing capability_results entries: {sorted(missing)}")
allowed_found = False
for cap in cap_results:
    child_acquire = cap.get("child_acquire") or {}
    child_use = cap.get("child_use") or {}
    if child_acquire.get("rc") is None or child_use.get("rc") is None:
        raise SystemExit(f"missing acquire/use rc for {cap.get('cap_id')}")
    if cap.get("notes") in (None, ""):
        raise SystemExit(f"missing notes for {cap.get('cap_id')}")
    if child_acquire.get("rc") == 0 and child_use.get("rc") == 0:
        allowed_found = True
if not allowed_found:
    raise SystemExit("expected at least one allowed-shaped capability (acquire=ok/use=ok)")
PY

step "xpc_run_inherit_child_protocol_violation" "xpc run (protocol bad cap_id)"
PROTO_JSON="${OUT_DIR}/xpc-run-inherit-child-protocol-violation.json"
PROTO_EXIT=0
"${PW}" xpc run --profile minimal inherit_child --scenario matrix_basic --path-class tmp --target specimen_file --name pw_protocol_bad.txt --create --protocol-bad-cap-id >"${PROTO_JSON}" || PROTO_EXIT="$?"
test_step "protocol_violation_exit_code" "xpc run exit_code=${PROTO_EXIT} (expected: 1 for protocol violation)"

/usr/bin/python3 - "${PROTO_JSON}" "${PROTO_EXIT}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
exit_code = int(sys.argv[2])
data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
if data.get("kind") != "probe_response":
    raise SystemExit(f"unexpected kind: {data.get('kind')!r}")
result = data.get("result") or {}
if exit_code != 1:
    raise SystemExit(f"expected exit code 1 for protocol violation, got {exit_code}")
if result.get("normalized_outcome") != "child_protocol_violation":
    raise SystemExit(f"expected normalized_outcome='child_protocol_violation'; got {result.get('normalized_outcome')!r}")
witness = (data.get("data") or {}).get("witness") or {}
protocol_error = witness.get("protocol_error")
if not protocol_error:
    raise SystemExit("missing witness.protocol_error")
if protocol_error.get("expected") is None or protocol_error.get("observed") is None:
    raise SystemExit("protocol_error missing expected/observed")
PY

step "xpc_run_inherit_child_bookmark" "xpc run (bookmark_ferry inherit_child)"
BOOKMARK_JSON="${OUT_DIR}/xpc-run-inherit-child-bookmark.json"
"${PW}" xpc run --profile bookmarks_app_scope inherit_child --scenario bookmark_ferry --path-class tmp --target specimen_file --name pw_bookmark_child.txt --create --bookmark-move >"${BOOKMARK_JSON}"

/usr/bin/python3 - "${BOOKMARK_JSON}" <<'PY'
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
witness = (data.get("data") or {}).get("witness") or {}
cap_results = witness.get("capability_results") or []
bookmark = None
for cap in cap_results:
    if cap.get("cap_id") == "bookmark":
        bookmark = cap
        break
if not bookmark:
    raise SystemExit("missing bookmark capability_results entry")

child_acquire = bookmark.get("child_acquire") or {}
child_use = bookmark.get("child_use") or {}
if child_acquire.get("rc") is None or child_use.get("rc") is None:
    raise SystemExit("missing bookmark child_acquire/child_use rc")
if child_acquire.get("rc") == child_use.get("rc") and child_acquire.get("errno") == child_use.get("errno"):
    raise SystemExit("expected bookmark acquire/use delta")

bookmark_details = bookmark.get("bookmark") or {}
if bookmark_details.get("resolve_rc") != 0:
    raise SystemExit(f"expected resolve_rc=0; got {bookmark_details.get('resolve_rc')!r}")
if bookmark_details.get("start_accessing") is not True:
    raise SystemExit(f"expected start_accessing=true; got {bookmark_details.get('start_accessing')!r}")
if bookmark_details.get("access_rc") != 0:
    raise SystemExit(f"expected access_rc=0; got {bookmark_details.get('access_rc')!r}")
PY

step "xpc_run_inherit_child_bookmark_invalid" "xpc run (bookmark_ferry invalid payload)"
BOOKMARK_BAD_JSON="${OUT_DIR}/xpc-run-inherit-child-bookmark-invalid.json"
"${PW}" xpc run --profile bookmarks_app_scope inherit_child --scenario bookmark_ferry --path-class tmp --target specimen_file --name pw_bookmark_bad.txt --create --bookmark-invalid >"${BOOKMARK_BAD_JSON}"

/usr/bin/python3 - "${BOOKMARK_BAD_JSON}" <<'PY'
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
witness = (data.get("data") or {}).get("witness") or {}
cap_results = witness.get("capability_results") or []
bookmark = None
for cap in cap_results:
    if cap.get("cap_id") == "bookmark":
        bookmark = cap
        break
if not bookmark:
    raise SystemExit("missing bookmark capability_results entry")
details = bookmark.get("bookmark") or {}
if details.get("resolve_rc") in (None, 0):
    raise SystemExit(f"expected resolve_rc != 0 for invalid bookmark; got {details.get('resolve_rc')!r}")
if not details.get("resolve_error_domain") and not details.get("resolve_error"):
    raise SystemExit("expected resolve_error_domain or resolve_error for invalid bookmark")
if details.get("resolve_error_code") is None:
    raise SystemExit("expected resolve_error_code for invalid bookmark")
PY

step "xpc_run_inherit_child_lineage" "xpc run (lineage_basic inherit_child)"
LINEAGE_JSON="${OUT_DIR}/xpc-run-inherit-child-lineage.json"
"${PW}" xpc run --profile minimal inherit_child --scenario lineage_basic >"${LINEAGE_JSON}"

/usr/bin/python3 - "${LINEAGE_JSON}" <<'PY'
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
witness = (data.get("data") or {}).get("witness") or {}
events = witness.get("events") or []
grandchild_seen = False
for event in events:
    if event.get("actor") == "grandchild":
        lineage = event.get("lineage") or {}
        if lineage.get("depth") == 2:
            grandchild_seen = True
            break
if not grandchild_seen:
    raise SystemExit("missing grandchild events with lineage depth=2")
PY

step "xpc_run_inherit_child_bad_entitlements" "xpc run (inherit_bad_entitlements scenario)"
BAD_JSON="${OUT_DIR}/xpc-run-inherit-child-bad-entitlements.json"
"${PW}" xpc run --profile minimal inherit_child --scenario inherit_bad_entitlements >"${BAD_JSON}"

/usr/bin/python3 - "${BAD_JSON}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8", errors="replace"))

if data.get("kind") != "probe_response":
    raise SystemExit(f"unexpected kind: {data.get('kind')!r}")
result = data.get("result") or {}
if result.get("normalized_outcome") != "child_abort_expected":
    raise SystemExit(f"expected normalized_outcome='child_abort_expected'; got {result.get('normalized_outcome')!r}")

witness = (data.get("data") or {}).get("witness") or {}
if witness.get("inherit_contract_ok") is not False:
    raise SystemExit(f"expected inherit_contract_ok=false; got {witness.get('inherit_contract_ok')!r}")
events = witness.get("events") or []
if not isinstance(events, list):
    raise SystemExit("missing witness.events")
child_emitted = [event for event in events if event.get("actor") == "child"]
if child_emitted:
    raise SystemExit("expected no child-emitted events (child died before writing), not a sandbox deny")
if not isinstance(witness.get("child_bundle_id"), str) or not isinstance(witness.get("child_team_id"), str):
    raise SystemExit("missing guardrail fields child_bundle_id/child_team_id despite early abort")
entitlements = witness.get("child_entitlements") or {}
if "com.apple.security.files.user-selected.read-only" not in entitlements:
    raise SystemExit("missing expected bad entitlement in child_entitlements")
exit_status = witness.get("child_exit_status")
if exit_status is None or exit_status < 128:
    raise SystemExit(f"expected child_exit_status to be signal-like; got {exit_status!r}")
summary = witness.get("outcome_summary") or ""
if "expected abort" not in summary:
    raise SystemExit("missing expected abort summary in witness.outcome_summary")
PY

step "xpc_run_inherit_child_sandbox_logs" "xpc run (capture sandbox logs)"
LOG_JSON="${OUT_DIR}/xpc-run-inherit-child-sandbox-logs.json"
"${PW}" xpc run --capture-sandbox-logs --profile minimal inherit_child --scenario matrix_basic --path-class tmp --target specimen_file --name pw_log_child.txt --create >"${LOG_JSON}"

/usr/bin/python3 - "${LOG_JSON}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
if data.get("kind") != "probe_response":
    raise SystemExit(f"unexpected kind: {data.get('kind')!r}")
witness = (data.get("data") or {}).get("witness") or {}
status = witness.get("sandbox_log_capture_status")
if status not in ("captured", "requested_unavailable"):
    raise SystemExit(f"unexpected sandbox_log_capture_status: {status!r}")
capture = witness.get("sandbox_log_capture") or {}
if status == "captured":
    if "observer_path" not in capture:
        raise SystemExit("missing sandbox_log_capture.observer_path")
else:
    if "error" not in capture:
        raise SystemExit("missing sandbox_log_capture.error")
PY

step "run_matrix_baseline" "repo --out write (run-matrix baseline)"
MATRIX_DIR="${OUT_DIR}/matrix-baseline"
mkdir -p "${MATRIX_DIR}"
echo "sentinel" >"${MATRIX_DIR}/sentinel.txt"

RUN_MATRIX_ENVELOPE="${OUT_DIR}/run-matrix-envelope.json"
"${PW}" run-matrix --group baseline --out "${MATRIX_DIR}" capabilities_snapshot >"${RUN_MATRIX_ENVELOPE}"

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
