#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

set +e
bash "${ROOT_DIR}/tests/suites/preflight/preflight.sh"
status=$?
set -e

if [[ ${status} -ne 0 ]]; then
  exit 1
fi
