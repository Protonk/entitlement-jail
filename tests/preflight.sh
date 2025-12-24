#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_PATH=""

usage() {
  cat <<'EOF'
usage:
  tests/preflight.sh [--out <path>]

notes:
  - emits a JSON report used by integration tests to decide what to skip
  - does not execute any artifacts (codesign inspection only)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      OUT_PATH="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" 1>&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${OUT_PATH}" ]]; then
  OUT_PATH="${ROOT_DIR}/tests/out/preflight.json"
fi

mkdir -p "$(dirname "${OUT_PATH}")"

APP_PATH="${ROOT_DIR}/EntitlementJail.app"
INSPECTOR_PATH="${EJ_INSPECTOR_BIN:-${ROOT_DIR}/runner/target/debug/ej-inspector}"
DYLIB_PATH="${ROOT_DIR}/tests/fixtures/TestDylib/out/testdylib.dylib"

/usr/bin/python3 - "${OUT_PATH}" "${APP_PATH}" "${INSPECTOR_PATH}" "${DYLIB_PATH}" <<'PY'
import json
import os
import plistlib
import subprocess
import sys

out_path, app_path, inspector_path, dylib_path = sys.argv[1:5]

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=False)

def extract_plist(data):
    if not data:
        return None
    start = data.find(b"<plist")
    end = data.rfind(b"</plist>")
    if start == -1 or end == -1:
        return None
    payload = data[start:end + len(b"</plist>")]
    try:
        return plistlib.loads(payload)
    except Exception:
        return None

def codesign_verify(path, deep=False):
    if not os.path.exists(path):
        return False, "missing"
    cmd = ["/usr/bin/codesign", "--verify", "--strict"]
    if deep:
        cmd.append("--deep")
    cmd.append(path)
    proc = run(cmd)
    if proc.returncode == 0:
        return True, None
    err = (proc.stderr or proc.stdout or b"").decode("utf-8", errors="ignore").strip()
    return False, err or "codesign verify failed"

def codesign_entitlements(path):
    if not os.path.exists(path):
        return None, "missing"
    proc = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", path])
    blob = (proc.stdout or b"") + (proc.stderr or b"")
    plist = extract_plist(blob)
    if plist is None:
        err = (proc.stderr or proc.stdout or b"").decode("utf-8", errors="ignore").strip()
        return None, err or "entitlements not found"
    return plist, None

ENT_KEYS = {
    "get_task_allow": "com.apple.security.get-task-allow",
    "disable_library_validation": "com.apple.security.cs.disable-library-validation",
    "allow_dyld_environment_variables": "com.apple.security.cs.allow-dyld-environment-variables",
    "allow_jit": "com.apple.security.cs.allow-jit",
    "allow_unsigned_executable_memory": "com.apple.security.cs.allow-unsigned-executable-memory",
    "network_client": "com.apple.security.network.client",
    "cs_debugger": "com.apple.security.cs.debugger",
}

def service_record(service_name):
    bin_path = os.path.join(
        app_path,
        "Contents",
        "XPCServices",
        f"{service_name}.xpc",
        "Contents",
        "MacOS",
        service_name,
    )
    exists = os.path.exists(bin_path)
    signed, sign_error = codesign_verify(bin_path) if exists else (False, "missing")
    entitlements, ent_error = codesign_entitlements(bin_path) if exists else (None, "missing")
    ent_map = {}
    if entitlements:
        for alias, key in ENT_KEYS.items():
            if key in entitlements:
                ent_map[alias] = bool(entitlements.get(key))
    return {
        "path": bin_path,
        "exists": exists,
        "signed": signed,
        "sign_error": sign_error,
        "entitlements": ent_map,
        "entitlements_error": ent_error if entitlements is None else None,
    }

services = {
    "minimal": service_record("ProbeService_minimal"),
    "debuggable": service_record("ProbeService_debuggable"),
    "fully_injectable": service_record("ProbeService_fully_injectable"),
    "plugin_host_relaxed": service_record("ProbeService_plugin_host_relaxed"),
    "jit_map_jit": service_record("ProbeService_jit_map_jit"),
    "jit_rwx_legacy": service_record("ProbeService_jit_rwx_legacy"),
    "net_client": service_record("ProbeService_net_client"),
}

app_exists = os.path.exists(app_path)
app_signed, app_error = codesign_verify(app_path, deep=True) if app_exists else (False, "missing")

inspector_exists = os.path.exists(inspector_path)
inspector_signed, inspector_error = codesign_verify(inspector_path) if inspector_exists else (False, "missing")
inspector_entitlements, inspector_ent_error = codesign_entitlements(inspector_path) if inspector_exists else (None, "missing")
inspector_cs_debugger = bool(inspector_entitlements.get(ENT_KEYS["cs_debugger"])) if inspector_entitlements else False

dylib_exists = os.path.exists(dylib_path)
dylib_signed, dylib_error = codesign_verify(dylib_path) if dylib_exists else (False, "missing")

report = {
    "schema_version": 1,
    "app": {
        "path": app_path,
        "exists": app_exists,
        "signed": app_signed,
        "sign_error": app_error,
    },
    "services": services,
    "inspector": {
        "path": inspector_path,
        "exists": inspector_exists,
        "signed": inspector_signed,
        "sign_error": inspector_error,
        "cs_debugger": inspector_cs_debugger,
        "entitlements_error": inspector_ent_error if inspector_entitlements is None else None,
    },
    "test_dylib": {
        "path": dylib_path,
        "exists": dylib_exists,
        "signed": dylib_signed,
        "sign_error": dylib_error,
    },
}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, sort_keys=True)
PY

echo "Preflight: ${OUT_PATH}"
