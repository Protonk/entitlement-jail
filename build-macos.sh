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
INHERIT_ENTITLEMENTS_PLIST="EntitlementJail.inherit.entitlements"
INFO_PLIST_TEMPLATE="Info.plist"

# Optional: embed extra payloads if present
EMBED_FENCERUNNER_PATH="${EMBED_FENCERUNNER_PATH:-}"   # e.g. /path/to/fencerunner
EMBED_PROBES_DIR="${EMBED_PROBES_DIR:-}"               # e.g. /path/to/probes
BUILD_XPC="${BUILD_XPC:-1}"                            # set to 0 to skip building embedded XPC services/client

# XPC source layout (in this repo)
XPC_ROOT="xpc"
XPC_API_FILE="${XPC_ROOT}/ProbeAPI.swift"
XPC_PROBE_CORE_FILE="${XPC_ROOT}/InProcessProbeCore.swift"
XPC_CLIENT_MAIN="${XPC_ROOT}/client/main.swift"
XPC_QUARANTINE_CLIENT_MAIN="${XPC_ROOT}/quarantine-client/main.swift"
XPC_SERVICES_DIR="${XPC_ROOT}/services"
# Swift/Clang module cache must be writable; the harness sandbox often blocks the default path under ~/.cache.
SWIFT_MODULE_CACHE="${SWIFT_MODULE_CACHE:-.tmp/swift-module-cache}"

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
mkdir -p "${APP_BUNDLE}/Contents/Helpers"
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
  cp "${EMBED_FENCERUNNER_PATH}" "${APP_BUNDLE}/Contents/Helpers/fencerunner"
  chmod +x "${APP_BUNDLE}/Contents/Helpers/fencerunner"
fi

# Optional: embed probes directory
if [[ -n "${EMBED_PROBES_DIR}" ]]; then
  if [[ ! -d "${EMBED_PROBES_DIR}" ]]; then
    echo "ERROR: EMBED_PROBES_DIR is set but not a directory: ${EMBED_PROBES_DIR}" 1>&2
    exit 2
  fi
  echo "==> Embedding probes dir: ${EMBED_PROBES_DIR}"
  mkdir -p "${APP_BUNDLE}/Contents/Helpers/Probes"
  rsync -a --delete "${EMBED_PROBES_DIR}/" "${APP_BUNDLE}/Contents/Helpers/Probes/"
fi

# Optional: build and embed XPC services + client
if [[ "${BUILD_XPC}" == "1" ]]; then
  SWIFTC_PATH="$(/usr/bin/xcrun --sdk macosx --find swiftc 2>/dev/null || true)"
  if [[ -z "${SWIFTC_PATH}" ]]; then
    echo "ERROR: BUILD_XPC=1 but swiftc was not found (install Xcode Command Line Tools)" 1>&2
    exit 2
  fi
  SWIFTC=(/usr/bin/xcrun --sdk macosx swiftc)
  if [[ ! -f "${XPC_API_FILE}" ]] || [[ ! -f "${XPC_PROBE_CORE_FILE}" ]] || [[ ! -f "${XPC_CLIENT_MAIN}" ]]; then
    echo "ERROR: BUILD_XPC=1 but XPC sources are missing under ${XPC_ROOT}/" 1>&2
    exit 2
  fi

  echo "==> Building embedded XPC client (must live under Contents/MacOS so Bundle.main resolves to the app)"
  mkdir -p "${SWIFT_MODULE_CACHE}"
  "${SWIFTC[@]}" -module-cache-path "${SWIFT_MODULE_CACHE}" -O -o "${APP_BUNDLE}/Contents/MacOS/xpc-probe-client" "${XPC_API_FILE}" "${XPC_CLIENT_MAIN}"
  chmod +x "${APP_BUNDLE}/Contents/MacOS/xpc-probe-client"

  if [[ -f "${XPC_QUARANTINE_CLIENT_MAIN}" ]]; then
    echo "==> Building embedded XPC quarantine client"
    "${SWIFTC[@]}" -module-cache-path "${SWIFT_MODULE_CACHE}" -O -o "${APP_BUNDLE}/Contents/MacOS/xpc-quarantine-client" "${XPC_API_FILE}" "${XPC_QUARANTINE_CLIENT_MAIN}"
    chmod +x "${APP_BUNDLE}/Contents/MacOS/xpc-quarantine-client"
  fi

  if [[ -d "${XPC_SERVICES_DIR}" ]]; then
    echo "==> Building embedded XPC services"
    mkdir -p "${APP_BUNDLE}/Contents/XPCServices"
    for svc_dir in "${XPC_SERVICES_DIR}"/*; do
      [[ -d "${svc_dir}" ]] || continue
      svc_name="$(basename "${svc_dir}")"
      svc_info="${svc_dir}/Info.plist"
      svc_main="${svc_dir}/main.swift"
      svc_bundle="${APP_BUNDLE}/Contents/XPCServices/${svc_name}.xpc"

      if [[ ! -f "${svc_info}" ]] || [[ ! -f "${svc_main}" ]]; then
        echo "ERROR: XPC service ${svc_name} is missing Info.plist or main.swift" 1>&2
        exit 2
      fi

      mkdir -p "${svc_bundle}/Contents/MacOS"
      cp "${svc_info}" "${svc_bundle}/Contents/Info.plist"
      "${SWIFTC[@]}" -module-cache-path "${SWIFT_MODULE_CACHE}" -O -o "${svc_bundle}/Contents/MacOS/${svc_name}" "${XPC_API_FILE}" "${XPC_PROBE_CORE_FILE}" "${svc_main}"
      chmod +x "${svc_bundle}/Contents/MacOS/${svc_name}"
    done
  fi
fi

# Sanity check entitlements
if [[ ! -f "${ENTITLEMENTS_PLIST}" ]]; then
  echo "ERROR: missing entitlements plist: ${ENTITLEMENTS_PLIST}" 1>&2
  exit 2
fi
if [[ ! -f "${INHERIT_ENTITLEMENTS_PLIST}" ]]; then
  echo "ERROR: missing inherit entitlements plist: ${INHERIT_ENTITLEMENTS_PLIST}" 1>&2
  exit 2
fi

sign_macho_inherit() {
  local target="$1"
  if [[ ! -e "${target}" ]]; then
    return 0
  fi
  if /usr/bin/file -b "${target}" | /usr/bin/grep -q "Mach-O"; then
    codesign \
      --force \
      --options runtime \
      --timestamp \
      --entitlements "${INHERIT_ENTITLEMENTS_PLIST}" \
      -s "${IDENTITY}" \
      "${target}"
  fi
}

echo "==> Codesigning embedded helper tools (App Sandbox inheritance)"
if [[ -d "${APP_BUNDLE}/Contents/Helpers" ]]; then
  while IFS= read -r -d '' f; do
    sign_macho_inherit "${f}"
  done < <(find "${APP_BUNDLE}/Contents/Helpers" -type f -print0)
fi

echo "==> Codesigning embedded MacOS helper tools (App Sandbox inheritance)"
sign_macho_inherit "${APP_BUNDLE}/Contents/MacOS/xpc-probe-client"
sign_macho_inherit "${APP_BUNDLE}/Contents/MacOS/xpc-quarantine-client"

echo "==> Codesigning embedded XPC services"
if [[ "${BUILD_XPC}" == "1" ]] && [[ -d "${XPC_SERVICES_DIR}" ]]; then
  for svc_dir in "${XPC_SERVICES_DIR}"/*; do
    [[ -d "${svc_dir}" ]] || continue
    svc_name="$(basename "${svc_dir}")"
    svc_entitlements="${svc_dir}/Entitlements.plist"
    svc_bundle="${APP_BUNDLE}/Contents/XPCServices/${svc_name}.xpc"

    if [[ ! -d "${svc_bundle}" ]]; then
      echo "ERROR: expected XPC service bundle at ${svc_bundle}" 1>&2
      exit 2
    fi
    if [[ ! -f "${svc_entitlements}" ]]; then
      echo "ERROR: XPC service ${svc_name} is missing Entitlements.plist" 1>&2
      exit 2
    fi

    codesign \
      --force \
      --options runtime \
      --timestamp \
      --entitlements "${svc_entitlements}" \
      -s "${IDENTITY}" \
      "${svc_bundle}"
  done
fi

echo "==> Codesigning (Developer ID + hardened runtime + entitlements)"
# Sign nested code first if you embed anything executable beyond the main binary.
codesign \
  --force \
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
