#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

CURRENT_STEP=""

test_begin "smoke" "quarantine.default_create"

fail() {
  test_fail "${CURRENT_STEP:-quarantine smoke failed}"
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

step "resolve_bundle_id" "resolve quarantine_default bundle id"
BUNDLE_ID="$("${EJ}" show-profile quarantine_default | /usr/bin/python3 -c 'import json,sys; data=json.load(sys.stdin); print(((data.get("data") or {}).get("profile") or {}).get("bundle_id") or "")')"

if [[ -z "${BUNDLE_ID}" ]]; then
  test_fail "failed to resolve quarantine_default bundle id"
fi

step "quarantine_lab_create" "quarantine-lab text create_new"
OUT_JSON="${OUT_DIR}/quarantine-default-text.json"
"${EJ}" quarantine-lab "${BUNDLE_ID}" text --dir tmp --name ej_quarantine_smoke.txt --operation create_new --no-exec >"${OUT_JSON}"

/usr/bin/python3 - "${OUT_JSON}" "${BUNDLE_ID}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
bundle_id = sys.argv[2]
data = json.loads(path.read_text(encoding="utf-8", errors="replace"))

if data.get("schema_version") != 2:
    raise SystemExit(f"unexpected schema_version: {data.get('schema_version')!r}")
if data.get("kind") != "quarantine_response":
    raise SystemExit(f"unexpected kind: {data.get('kind')!r}")

result = data.get("result") or {}
if result.get("ok") is not True:
    raise SystemExit(f"expected ok=true; got {result!r}")
if result.get("normalized_outcome") != "wrote_new":
    raise SystemExit(f"expected normalized_outcome='wrote_new'; got {result.get('normalized_outcome')!r}")

payload = data.get("data") or {}
if payload.get("service_bundle_id") != bundle_id:
    raise SystemExit(f"expected service_bundle_id={bundle_id!r}; got {payload.get('service_bundle_id')!r}")

layer = payload.get("layer_attribution") or {}
if layer.get("other") != "seatbelt:process_exec_not_attempted":
    raise SystemExit(f"expected layer_attribution.other to be seatbelt:process_exec_not_attempted; got {layer.get('other')!r}")
PY

test_pass "smoke artifacts written" "{\"out_dir\":\"${OUT_DIR}\"}"
