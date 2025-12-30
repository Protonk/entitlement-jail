#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "${ROOT_DIR}/tests/lib/testlib.sh"

CURRENT_STEP=""

test_begin "smoke" "experiments.tri_run"

fail() {
  test_fail "${CURRENT_STEP:-experiments tri-run failed}"
}

trap fail ERR

step() {
  CURRENT_STEP="$1"
  test_step "$1" "${2:-$1}"
}

OUT_DIR="${EJ_TEST_ARTIFACTS}"
HARNESS_OUT_DIR="${OUT_DIR}/harness"

step "prepare_artifacts" "prepare smoke artifacts"
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

step "build_experiments" "build experiments (substrate + harness)"
"${ROOT_DIR}/experiments/build-experiments.sh"

step "substrate_probes" "run substrate probes"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe probe_catalog >"${OUT_DIR}/substrate_probe_catalog.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe capabilities_snapshot >"${OUT_DIR}/substrate_capabilities_snapshot.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe world_shape >"${OUT_DIR}/substrate_world_shape.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe fs_op --op stat --path-class tmp >"${OUT_DIR}/substrate_fs_op_stat.json"
"${ROOT_DIR}/experiments/bin/witness-substrate" probe userdefaults_op --op read >"${OUT_DIR}/substrate_userdefaults_read.json"

step "tri_run_plan" "run tri-run smoke plan"
mkdir -p "${HARNESS_OUT_DIR}"
SMOKE_ATLAS="$("${ROOT_DIR}/experiments/bin/ej-harness" run --plan "${ROOT_DIR}/experiments/plans/tri-run-smoke.json" --out-dir "${HARNESS_OUT_DIR}")"
test_step "tri_run_atlas" "tri-run atlas: ${SMOKE_ATLAS}"

step "tri_run_sandbox_extension_semantics" "run tri-run sandbox-extension semantics plan"
SEMANTICS_OUT_DIR="${HARNESS_OUT_DIR}/sandbox-extension-semantics"
mkdir -p "${SEMANTICS_OUT_DIR}"
SEMANTICS_ATLAS="$("${ROOT_DIR}/experiments/bin/ej-harness" run --plan "${ROOT_DIR}/experiments/plans/tri-run-sandbox-extension-semantics.json" --nodes "${ROOT_DIR}/experiments/nodes/entitlement-lattice-sandbox-extension-semantics.json" --out-dir "${SEMANTICS_OUT_DIR}")"
test_step "tri_run_sandbox_extension_semantics_atlas" "tri-run sandbox-extension semantics atlas: ${SEMANTICS_ATLAS}"

test_pass "smoke artifacts written" "{\"out_dir\":\"${OUT_DIR}\"}"
