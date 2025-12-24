#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
OUT_DYLIB="${OUT_DIR}/testdylib.dylib"

mkdir -p "${OUT_DIR}"
cc -dynamiclib -o "${OUT_DYLIB}" "${SCRIPT_DIR}/testdylib.c"

if [ -z "${IDENTITY:-}" ]; then
  echo "ERROR: IDENTITY is not set (use the same Developer ID Application identity as the app build)" 1>&2
  exit 2
fi

codesign --force --timestamp --options runtime -s "${IDENTITY}" "${OUT_DYLIB}"
echo "built: ${OUT_DYLIB}"
