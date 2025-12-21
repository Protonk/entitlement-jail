#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

warn() {
  echo "WARN: $*" 1>&2
}

info() {
  echo "==> $*"
}

timestamp() {
  date +"%Y%m%d-%H%M%S"
}

timestamp_iso() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

timestamp_local() {
  date +"%Y-%m-%d %H:%M:%S"
}

extract_pid_info() {
  local json_path="$1"
  /usr/bin/python3 - <<'PY' "${json_path}"
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception as exc:
    print(f"parse_error={exc}")
    sys.exit(0)

details = data.get("details") or {}
def norm(val):
    return val if isinstance(val, str) else ""

for key in ("service_pid", "probe_pid", "pid", "process_name"):
    print(f"{key}={norm(details.get(key, ''))}")
PY
}

capture_host_log_for_pid() {
  local label="$1"
  local pid_role="$2"
  local pid="$3"
  local process_name="$4"
  local start_iso="$5"
  local end_iso="$6"
  local start_local="$7"
  local end_local="$8"
  local out_dir="$9"

  local role_suffix=""
  case "${pid_role}" in
    service) role_suffix=".service" ;;
    probe) role_suffix=".probe" ;;
    pid) role_suffix=".pid" ;;
    *) role_suffix="" ;;
  esac

  local log_path="${out_dir}/${label}.host${role_suffix}.log"
  local meta_path="${out_dir}/${label}.host${role_suffix}.logmeta.json"
  local predicate="(eventMessage CONTAINS[c] \"Sandbox: ${process_name}(${pid})\") AND (eventMessage CONTAINS[c] \"deny\")"
  local log_err_path="${log_path}.err"

  set +e
  /usr/bin/log show --style syslog --start "${start_local}" --end "${end_local}" --predicate "${predicate}" >"${log_path}" 2>"${log_err_path}"
  local log_rc=$?
  set -e

  local log_err=""
  if [[ -s "${log_err_path}" ]]; then
    log_err="$(cat "${log_err_path}")"
  fi
  rm -f "${log_err_path}"

  /usr/bin/python3 - <<'PY' "${log_path}" "${meta_path}" "${predicate}" "${process_name}" "${pid}" "${pid_role}" "${start_iso}" "${end_iso}" "${start_local}" "${end_local}" "${log_rc}" "${log_err}"
import json
import re
import sys

log_path = sys.argv[1]
meta_path = sys.argv[2]
predicate = sys.argv[3]
process_name = sys.argv[4]
pid = sys.argv[5]
pid_role = sys.argv[6]
start_iso = sys.argv[7]
end_iso = sys.argv[8]
start_local = sys.argv[9]
end_local = sys.argv[10]
log_rc = int(sys.argv[11])
log_err = sys.argv[12]

deny_op = None
log_text = ""
try:
    with open(log_path, "r", encoding="utf-8") as fh:
        log_text = fh.read()
except FileNotFoundError:
    log_text = ""

for pat in (r"deny\\(\\d+\\)\\s+([^\\s]+)", r"deny\\s+([^\\s]+)"):
    match = re.search(pat, log_text)
    if match:
        deny_op = match.group(1)
        break

if log_rc != 0:
    result = "log_show_failed"
elif deny_op:
    result = "deny_observed"
else:
    result = "no_sandbox_deny_observed_in_window"

meta = {
    "start_iso8601": start_iso,
    "end_iso8601": end_iso,
    "start_local": start_local,
    "end_local": end_local,
    "predicate": predicate,
    "term": f"{process_name}({pid})",
    "pid": pid,
    "process_name": process_name,
    "pid_role": pid_role,
    "observed_deny": deny_op is not None,
    "deny_op": deny_op,
    "result": result,
    "log_ref": log_path.split("/")[-1],
    "log_show_rc": log_rc,
    "log_show_error": log_err or None,
    "evidence": "host_log_capture",
}

with open(meta_path, "w", encoding="utf-8") as fh:
    json.dump(meta, fh, indent=2)
PY
}

capture_host_logs() {
  local label="$1"
  local json_path="$2"
  local start_iso="$3"
  local end_iso="$4"
  local start_local="$5"
  local end_local="$6"
  local out_dir="$7"

  local service_pid=""
  local probe_pid=""
  local pid=""
  local process_name=""
  local parse_error=""

  while IFS='=' read -r key value; do
    case "${key}" in
      service_pid) service_pid="${value}" ;;
      probe_pid) probe_pid="${value}" ;;
      pid) pid="${value}" ;;
      process_name) process_name="${value}" ;;
      parse_error) parse_error="${value}" ;;
    esac
  done < <(extract_pid_info "${json_path}")

  local meta_path="${out_dir}/${label}.host.logmeta.json"
  if [[ -n "${parse_error}" ]]; then
    /usr/bin/python3 - <<'PY' "${meta_path}" "${start_iso}" "${end_iso}" "${start_local}" "${end_local}" "${parse_error}"
import json
import sys

meta_path = sys.argv[1]
start_iso = sys.argv[2]
end_iso = sys.argv[3]
start_local = sys.argv[4]
end_local = sys.argv[5]
err = sys.argv[6]

meta = {
    "start_iso8601": start_iso,
    "end_iso8601": end_iso,
    "start_local": start_local,
    "end_local": end_local,
    "predicate": None,
    "term": None,
    "pid_role": None,
    "observed_deny": False,
    "deny_op": None,
    "result": "json_parse_failed",
    "log_ref": None,
    "log_show_rc": None,
    "log_show_error": err,
    "evidence": "host_log_capture",
}

with open(meta_path, "w", encoding="utf-8") as fh:
    json.dump(meta, fh, indent=2)
PY
    warn "failed to parse JSON for host log capture: ${json_path}"
    return
  fi

  if [[ -z "${process_name}" ]]; then
    process_name="unknown_process"
  fi

  if [[ -n "${service_pid}" && -n "${probe_pid}" && "${service_pid}" == "${probe_pid}" ]]; then
    capture_host_log_for_pid "${label}" "service+probe" "${service_pid}" "${process_name}" "${start_iso}" "${end_iso}" "${start_local}" "${end_local}" "${out_dir}"
    return
  fi

  if [[ -n "${service_pid}" ]]; then
    capture_host_log_for_pid "${label}" "service" "${service_pid}" "${process_name}" "${start_iso}" "${end_iso}" "${start_local}" "${end_local}" "${out_dir}"
  fi
  if [[ -n "${probe_pid}" && "${probe_pid}" != "${service_pid}" ]]; then
    capture_host_log_for_pid "${label}" "probe" "${probe_pid}" "${process_name}" "${start_iso}" "${end_iso}" "${start_local}" "${end_local}" "${out_dir}"
  fi

  if [[ -z "${service_pid}" && -z "${probe_pid}" && -n "${pid}" ]]; then
    capture_host_log_for_pid "${label}" "pid" "${pid}" "${process_name}" "${start_iso}" "${end_iso}" "${start_local}" "${end_local}" "${out_dir}"
    return
  fi

  if [[ -z "${service_pid}" && -z "${probe_pid}" && -z "${pid}" ]]; then
    /usr/bin/python3 - <<'PY' "${meta_path}" "${start_iso}" "${end_iso}" "${start_local}" "${end_local}"
import json
import sys

meta_path = sys.argv[1]
start_iso = sys.argv[2]
end_iso = sys.argv[3]
start_local = sys.argv[4]
end_local = sys.argv[5]

meta = {
    "start_iso8601": start_iso,
    "end_iso8601": end_iso,
    "start_local": start_local,
    "end_local": end_local,
    "predicate": None,
    "term": None,
    "pid_role": None,
    "observed_deny": False,
    "deny_op": None,
    "result": "missing_pid",
    "log_ref": None,
    "log_show_rc": None,
    "log_show_error": "missing pid in response details",
    "evidence": "host_log_capture",
}

with open(meta_path, "w", encoding="utf-8") as fh:
    json.dump(meta, fh, indent=2)
PY
    warn "missing pid in response details for host log capture: ${json_path}"
  fi
}

classify_inapp_log_capture() {
  local log_path="$1"
  local meta_path="$2"

  local classification="in_app_log_capture"
  local note=""
  if /usr/bin/grep -q "Cannot run while sandboxed" "${log_path}" 2>/dev/null; then
    classification="tool_refusal_sandboxed_log"
    note="log show blocked by app sandbox"
  elif /usr/bin/grep -q "log show error:" "${log_path}" 2>/dev/null; then
    classification="log_show_error"
    note="log show reported an error"
  fi

  /usr/bin/python3 - <<'PY' "${meta_path}" "${classification}" "${note}" "${log_path}"
import json
import sys

meta_path = sys.argv[1]
classification = sys.argv[2]
note = sys.argv[3] if sys.argv[3] else None
log_path = sys.argv[4]

meta = {
    "classification": classification,
    "note": note,
    "log_ref": log_path.split("/")[-1],
    "evidence": "diagnostic_only",
}

with open(meta_path, "w", encoding="utf-8") as fh:
    json.dump(meta, fh, indent=2)
PY
}

write_log_index() {
  local label="$1"
  local out_dir="$2"
  /usr/bin/python3 - <<'PY' "${label}" "${out_dir}"
import glob
import json
import os
import sys

label = sys.argv[1]
out_dir = sys.argv[2]

host_entries = []
for meta_path in sorted(glob.glob(os.path.join(out_dir, f"{label}.host*.logmeta.json"))):
    try:
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except Exception:
        meta = {}
    host_entries.append({
        "meta_ref": os.path.basename(meta_path),
        "log_ref": meta.get("log_ref"),
        "pid_role": meta.get("pid_role"),
        "result": meta.get("result"),
    })

inapp_entry = None
inapp_meta = os.path.join(out_dir, f"{label}.inapp.logmeta.json")
if os.path.exists(inapp_meta):
    try:
        with open(inapp_meta, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except Exception:
        meta = {}
    inapp_entry = {
        "meta_ref": os.path.basename(inapp_meta),
        "log_ref": meta.get("log_ref"),
        "classification": meta.get("classification"),
    }

index = {
    "label": label,
    "host_log_capture": host_entries,
    "in_app_log_capture": inapp_entry,
    "note": "host-side captures are evidence; in-app capture is diagnostic only",
}

out_path = os.path.join(out_dir, f"{label}.log-index.json")
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(index, fh, indent=2)
PY
}

run_xpc_smoke() {
  local label="$1"
  local service_id="$2"
  local probe_id="$3"
  shift 3

  local inapp_log="${LOG_BASE}/${label}.inapp.log"
  local out_json="${OUT_DIR}/${label}.json"
  local start_iso
  local start_local
  local end_iso
  local end_local

  start_iso="$(timestamp_iso)"
  start_local="$(timestamp_local)"
  set +e
  "${EJ}" run-xpc --log-sandbox "${inapp_log}" "${service_id}" "${probe_id}" "$@" >"${out_json}"
  local rc=$?
  set -e
  end_iso="$(timestamp_iso)"
  end_local="$(timestamp_local)"

  capture_host_logs "${label}" "${out_json}" "${start_iso}" "${end_iso}" "${start_local}" "${end_local}" "${OUT_DIR}"

  if [[ -f "${inapp_log}" ]]; then
    cp "${inapp_log}" "${OUT_DIR}/${label}.inapp.log"
    classify_inapp_log_capture "${OUT_DIR}/${label}.inapp.log" "${OUT_DIR}/${label}.inapp.logmeta.json"
  else
    warn "missing in-app log capture: ${inapp_log}"
  fi

  write_log_index "${label}" "${OUT_DIR}"

  return "${rc}"
}

OUT_DIR="${ROOT_DIR}/experiments/out/smoke-$(timestamp)"
mkdir -p "${OUT_DIR}"

info "Building experiments (substrate + harness)"
"${ROOT_DIR}/experiments/build-experiments.sh"

info "Running substrate probes"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe probe_catalog >"${OUT_DIR}/substrate_probe_catalog.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe capabilities_snapshot >"${OUT_DIR}/substrate_capabilities_snapshot.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe world_shape >"${OUT_DIR}/substrate_world_shape.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe fs_op --op stat --path-class tmp >"${OUT_DIR}/substrate_fs_op_stat.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe userdefaults_op --op read >"${OUT_DIR}/substrate_userdefaults_read.json"

info "Running tri-run smoke plan (baseline/policy/entitlement)"
SMOKE_ATLAS="$("${ROOT_DIR}/experiments/bin/ej-harness" run --plan "${ROOT_DIR}/experiments/plans/tri-run-smoke.json")"
echo "Smoke atlas: ${SMOKE_ATLAS}"

APP="${ROOT_DIR}/EntitlementJail.app"
EJ="${APP}/Contents/MacOS/entitlement-jail"
PROBE_SERVICE_ID="${EJ_PROBE_SERVICE_ID:-com.yourteam.entitlement-jail.ProbeService_minimal}"
APP_BUNDLE_ID="$(
  /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "${APP}/Contents/Info.plist" 2>/dev/null \
  || echo "com.yourteam.entitlement-jail"
)"

APP_OK=1
if [[ ! -x "${EJ}" ]]; then
  warn "EntitlementJail.app is missing or not executable at ${EJ}; skipping run-xpc smoke checks."
  APP_OK=0
fi

if [[ "${APP_OK}" == "1" ]]; then
  if ! /usr/bin/codesign --verify --deep --strict "${APP}" >/dev/null 2>&1; then
    warn "EntitlementJail.app failed codesign verification; run-xpc smoke checks may fail."
    APP_OK=0
  fi
fi

if [[ "${APP_OK}" == "1" ]]; then
  info "Running run-xpc smoke checks"
  LOG_BASE="${HOME}/Library/Containers/${APP_BUNDLE_ID}/Data/tmp/ej-smoke-$(basename "${OUT_DIR}")"
  mkdir -p "${LOG_BASE}"
  XPC_RC=0
  run_xpc_smoke "entitlement_probe_catalog" "${PROBE_SERVICE_ID}" "probe_catalog" || XPC_RC=$?
  run_xpc_smoke "entitlement_fs_op_stat" "${PROBE_SERVICE_ID}" "fs_op" --op stat --path-class tmp || XPC_RC=$?

  if [[ "${XPC_RC}" != "0" ]]; then
    warn "run-xpc smoke checks failed (rc=${XPC_RC})"
    exit "${XPC_RC}"
  fi
else
  warn "Skipping run-xpc smoke checks; substrate/harness checks still completed."
fi

echo "Smoke artifacts: ${OUT_DIR}"
