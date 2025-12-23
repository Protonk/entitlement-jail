#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SWIFT_MODULE_CACHE="${SWIFT_MODULE_CACHE:-${ROOT_DIR}/.tmp/swift-module-cache}"
SWIFT_OPT_LEVEL="${SWIFT_OPT_LEVEL:--O}"

SWIFTC_PATH="$(/usr/bin/xcrun --sdk macosx --find swiftc 2>/dev/null || true)"
if [[ -z "${SWIFTC_PATH}" ]]; then
  echo "ERROR: swiftc was not found (install Xcode Command Line Tools)" 1>&2
  exit 2
fi

SWIFTC=(/usr/bin/xcrun --sdk macosx swiftc)

mkdir -p "${SWIFT_MODULE_CACHE}"
mkdir -p "${ROOT_DIR}/experiments/bin"

echo "==> Building witness substrate"
"${SWIFTC[@]}" \
  -module-cache-path "${SWIFT_MODULE_CACHE}" \
  "${SWIFT_OPT_LEVEL}" \
  -o "${ROOT_DIR}/experiments/bin/witness-substrate" \
  "${ROOT_DIR}/xpc/ProbeAPI.swift" \
  "${ROOT_DIR}/xpc/InProcessProbeCore.swift" \
  "${ROOT_DIR}/experiments/substrate/main.swift"

chmod +x "${ROOT_DIR}/experiments/bin/witness-substrate"

echo "==> Building tri-run harness"
"${SWIFTC[@]}" \
  -module-cache-path "${SWIFT_MODULE_CACHE}" \
  "${SWIFT_OPT_LEVEL}" \
  -o "${ROOT_DIR}/experiments/bin/ej-harness" \
  "${ROOT_DIR}/xpc/ProbeAPI.swift" \
  "${ROOT_DIR}/experiments/harness/main.swift"

chmod +x "${ROOT_DIR}/experiments/bin/ej-harness"

echo "DONE:"
echo "  - experiments/bin/witness-substrate"
echo "  - experiments/bin/ej-harness"
