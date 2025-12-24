#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${EJ_SMOKE_OUT_DIR:-${ROOT_DIR}/experiments/out/test}"
HARNESS_OUT_DIR="${OUT_DIR}/harness"

CURRENT_STEP=""

fail() {
  echo "FAIL: ${CURRENT_STEP}" 1>&2
}

trap fail ERR

step() {
  CURRENT_STEP="$1"
  echo "==> $1"
}

pass() {
  echo "OK: $1"
}

step "Preparing smoke artifacts"
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"
pass "Preparing smoke artifacts"

step "Building experiments (substrate + harness)"
"${ROOT_DIR}/experiments/build-experiments.sh"
pass "Building experiments (substrate + harness)"

step "Running substrate probes"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe probe_catalog >"${OUT_DIR}/substrate_probe_catalog.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe capabilities_snapshot >"${OUT_DIR}/substrate_capabilities_snapshot.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe world_shape >"${OUT_DIR}/substrate_world_shape.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe fs_op --op stat --path-class tmp >"${OUT_DIR}/substrate_fs_op_stat.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe userdefaults_op --op read >"${OUT_DIR}/substrate_userdefaults_read.json"
pass "Running substrate probes"

step "Running tri-run smoke plan"
mkdir -p "${HARNESS_OUT_DIR}"
SMOKE_ATLAS="$("${ROOT_DIR}/experiments/bin/ej-harness" run --plan "${ROOT_DIR}/experiments/plans/tri-run-smoke.json" --out-dir "${HARNESS_OUT_DIR}")"
echo "Smoke atlas: ${SMOKE_ATLAS}"
pass "Running tri-run smoke plan"

echo "Smoke artifacts: ${OUT_DIR}"
