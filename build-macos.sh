#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./build-macos.sh
#   IDENTITY='Developer ID Application: ...' ./build-macos.sh
#
# Produces:
#   EntitlementJail.app
#   EntitlementJail.zip  (ready for notarytool submit)

APP_NAME="EntitlementJail"
APP_BUNDLE="${APP_NAME}.app"
ZIP_NAME="${APP_NAME}.zip"

# Paths in this repo
RUNNER_MANIFEST="runner/Cargo.toml"
ENTITLEMENTS_PLIST="EntitlementJail.entitlements"
INFO_PLIST_TEMPLATE="Info.plist"

# Optional: embed extra payloads if present
EMBED_FENCERUNNER_PATH="${EMBED_FENCERUNNER_PATH:-}"   # e.g. /path/to/fencerunner
EMBED_PROBES_DIR="${EMBED_PROBES_DIR:-}"               # e.g. /path/to/probes

# Signing identity. Prefer env override; otherwise require user to set it.
IDENTITY="${IDENTITY:-}"

if [[ -z "${IDENTITY}" ]]; then
  cat <<'EOF' 1>&2
ERROR: IDENTITY is not set.

Set it to your Developer ID Application identity string, for example:
  IDENTITY='Developer ID Application: Adam Hyland (42D369QV8E)' ./build-macos.sh

You can find valid identities via:
  security find-identity -v -p codesigning
EOF
  exit 2
fi

echo "==> Building Rust runner"
cargo build --manifest-path "${RUNNER_MANIFEST}" --release

# Find the built binary. (Assumes standard Cargo layout.)
RUNNER_BIN="runner/target/release/runner"
if [[ ! -x "${RUNNER_BIN}" ]]; then
  echo "ERROR: expected runner binary at ${RUNNER_BIN}" 1>&2
  exit 2
fi

echo "==> Assembling app bundle: ${APP_BUNDLE}"
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

# Copy Info.plist
if [[ ! -f "${INFO_PLIST_TEMPLATE}" ]]; then
  echo "ERROR: missing ${INFO_PLIST_TEMPLATE} at repo root" 1>&2
  exit 2
fi
cp "${INFO_PLIST_TEMPLATE}" "${APP_BUNDLE}/Contents/Info.plist"

# Install main executable
cp "${RUNNER_BIN}" "${APP_BUNDLE}/Contents/MacOS/entitlement-jail"
chmod +x "${APP_BUNDLE}/Contents/MacOS/entitlement-jail"

# Optional: embed fencerunner
if [[ -n "${EMBED_FENCERUNNER_PATH}" ]]; then
  if [[ ! -x "${EMBED_FENCERUNNER_PATH}" ]]; then
    echo "ERROR: EMBED_FENCERUNNER_PATH is set but not executable: ${EMBED_FENCERUNNER_PATH}" 1>&2
    exit 2
  fi
  echo "==> Embedding fencerunner: ${EMBED_FENCERUNNER_PATH}"
  cp "${EMBED_FENCERUNNER_PATH}" "${APP_BUNDLE}/Contents/MacOS/fencerunner"
  chmod +x "${APP_BUNDLE}/Contents/MacOS/fencerunner"
fi

# Optional: embed probes directory
if [[ -n "${EMBED_PROBES_DIR}" ]]; then
  if [[ ! -d "${EMBED_PROBES_DIR}" ]]; then
    echo "ERROR: EMBED_PROBES_DIR is set but not a directory: ${EMBED_PROBES_DIR}" 1>&2
    exit 2
  fi
  echo "==> Embedding probes dir: ${EMBED_PROBES_DIR}"
  rsync -a --delete "${EMBED_PROBES_DIR}/" "${APP_BUNDLE}/Contents/Resources/probes/"
fi

# Sanity check entitlements
if [[ ! -f "${ENTITLEMENTS_PLIST}" ]]; then
  echo "ERROR: missing entitlements plist: ${ENTITLEMENTS_PLIST}" 1>&2
  exit 2
fi

echo "==> Codesigning (Developer ID + hardened runtime + entitlements)"
# Sign nested code first if you embed anything executable beyond the main binary.
# --deep is convenient here; if you later add more embedded executables/frameworks,
# consider an explicit signing pass over each nested code item.
codesign \
  --force \
  --deep \
  --options runtime \
  --timestamp \
  --entitlements "${ENTITLEMENTS_PLIST}" \
  -s "${IDENTITY}" \
  "${APP_BUNDLE}"

echo "==> Verifying signature + entitlements"
codesign --verify --deep --strict --verbose=2 "${APP_BUNDLE}"
codesign --display --entitlements - "${APP_BUNDLE}" >/dev/null

echo "==> Creating zip (for notarization): ${ZIP_NAME}"
rm -f "${ZIP_NAME}"
/usr/bin/ditto -c -k --keepParent "${APP_BUNDLE}" "${ZIP_NAME}"

echo
echo "DONE:"
echo "  - ${APP_BUNDLE}"
echo "  - ${ZIP_NAME}"
echo
echo "Next (notarize with your saved profile):"
cat <<EOF
  xcrun notarytool submit "${ZIP_NAME}" --keychain-profile "dev-profile" --wait
  xcrun stapler staple "${APP_BUNDLE}"
  spctl -a -vv "${APP_BUNDLE}"
EOF
