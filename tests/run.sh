#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

testlib_init

RUN_START_MS="$(now_ms)"
RUN_OUT_RAW="${PW_TEST_OUT_DIR}"
RUN_OUT="$(
  PW_TEST_ROOT="${ROOT_DIR}" \
  PW_TEST_OUT_RAW="${RUN_OUT_RAW}" \
  /usr/bin/python3 - <<'PY'
import os
import os.path

root = os.environ["PW_TEST_ROOT"]
raw = os.environ["PW_TEST_OUT_RAW"]

if os.path.isabs(raw):
    out = os.path.normpath(raw)
else:
    out = os.path.normpath(os.path.join(root, raw))

print(os.path.abspath(out))
PY
)"
RUN_JSON="${RUN_OUT}/run.json"

if [[ -z "${RUN_OUT}" ]]; then
  echo "ERROR: PW_TEST_OUT_DIR resolved to an empty path" 1>&2
  exit 2
fi
if [[ "${RUN_OUT}" == "/" ]]; then
  echo "ERROR: refusing to use '/' as PW_TEST_OUT_DIR" 1>&2
  exit 2
fi

DEFAULT_OUT="${ROOT_DIR}/tests/out"
case "${RUN_OUT}" in
  "${DEFAULT_OUT}"| "${DEFAULT_OUT}/"*)
    ;;
  *)
    echo "ERROR: PW_TEST_OUT_DIR must be within ${DEFAULT_OUT} (got: ${RUN_OUT})" 1>&2
    exit 2
    ;;
esac

PW_TEST_OUT_DIR="${RUN_OUT}"
PW_TEST_EVENTS="${PW_TEST_OUT_DIR}/events.jsonl"
export PW_TEST_OUT_DIR PW_TEST_EVENTS

# This repo's test loops are designed to be agent-friendly: overwrite the prior run
# so external tooling can just read stable paths under tests/out/.
rm -rf "${RUN_OUT}"
mkdir -p "${RUN_OUT}"

suites=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)
      suites+=("${2:?missing suite name}")
      shift 2
      ;;
    --all)
      suites=()
      shift 1
      ;;
    -h|--help)
      cat <<'EOF'
usage:
  tests/run.sh --all
  tests/run.sh --suite <preflight|unit|integration|smoke> [--suite <name> ...]
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $1" 1>&2
      exit 2
      ;;
  esac
done

if [[ ${#suites[@]} -eq 0 ]]; then
  suites=(preflight unit integration smoke)
fi

failures=0

for suite in "${suites[@]}"; do
  suite_script="${ROOT_DIR}/tests/suites/${suite}/run.sh"
  if [[ ! -x "${suite_script}" ]]; then
    echo "missing suite runner: ${suite_script}" 1>&2
    failures=1
    continue
  fi

  echo "==> [suite] ${suite}"
  set +e
  bash "${suite_script}"
  status=$?
  set -e

  if [[ ${status} -ne 0 ]]; then
    failures=1
  fi
done

RUN_END_MS="$(now_ms)"
DURATION_MS=$((RUN_END_MS - RUN_START_MS))

PW_RUN_START_MS="${RUN_START_MS}" \
PW_RUN_END_MS="${RUN_END_MS}" \
PW_RUN_DURATION_MS="${DURATION_MS}" \
PW_RUN_ID="${PW_TEST_RUN_ID}" \
PW_RUN_OUT="${RUN_OUT}" \
/usr/bin/python3 - <<'PY'
import json
import os
from pathlib import Path

def maybe_int(value):
    try:
        return int(value)
    except Exception:
        return None

run_out = Path(os.environ["PW_RUN_OUT"])
reports = []
for report_path in sorted(run_out.glob("suites/*/*/report.json")):
    try:
        reports.append(json.loads(report_path.read_text(encoding="utf-8")))
    except Exception:
        reports.append({
            "schema_version": 1,
            "suite": "unknown",
            "test_id": report_path.parent.name,
            "status": "fail",
            "message": "failed to parse report.json",
            "duration_ms": None,
            "artifacts_dir": str(report_path.parent / "artifacts"),
            "notes": ["parse_error"],
        })

counts = {"pass": 0, "fail": 0, "skip": 0, "total": 0}
suite_counts = {}
for report in reports:
    status = report.get("status")
    if status not in ("pass", "fail", "skip"):
        status = "fail"
    counts[status] += 1
    counts["total"] += 1
    suite = report.get("suite") or "unknown"
    suite_counts.setdefault(suite, {"pass": 0, "fail": 0, "skip": 0, "total": 0})
    suite_counts[suite][status] += 1
    suite_counts[suite]["total"] += 1

run = {
    "schema_version": 1,
    "run_id": os.environ.get("PW_RUN_ID", ""),
    "started_at_unix_ms": maybe_int(os.environ.get("PW_RUN_START_MS")),
    "finished_at_unix_ms": maybe_int(os.environ.get("PW_RUN_END_MS")),
    "duration_ms": maybe_int(os.environ.get("PW_RUN_DURATION_MS")),
    "ok": counts["fail"] == 0,
    "counts": counts,
    "suites": suite_counts,
    "reports": reports,
}

run_path = run_out / "run.json"
run_path.write_text(json.dumps(run, indent=2, sort_keys=True), encoding="utf-8")
print(f"Test run summary: {run_path}")
PY

if [[ ${failures} -ne 0 ]]; then
  exit 1
fi
