#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./build.sh
#   IDENTITY='Developer ID Application: ...' ./build.sh
#   PW_INSPECTION=0 IDENTITY='Developer ID Application: ...' ./build.sh
#
# Produces:
#   PolicyWitness.app
#   PolicyWitness.zip  (ready for notarytool submit)

APP_NAME="PolicyWitness"
APP_BUNDLE="${APP_NAME}.app"
ZIP_NAME="${APP_NAME}.zip"

# Paths in this repo
RUNNER_MANIFEST="runner/Cargo.toml"
ENTITLEMENTS_PLIST="PolicyWitness.entitlements"
INHERIT_ENTITLEMENTS_PLIST="PolicyWitness.inherit.entitlements"
BAD_INHERIT_ENTITLEMENTS_PLIST="PolicyWitness.inherit.bad.entitlements"
INSPECTOR_ENTITLEMENTS_PLIST="Inspector.entitlements"
INFO_PLIST_TEMPLATE="Info.plist"

# Optional: embed extra payloads if present
EMBED_FENCERUNNER_PATH="${EMBED_FENCERUNNER_PATH:-}"   # e.g. /path/to/fencerunner
EMBED_PROBES_DIR="${EMBED_PROBES_DIR:-}"               # e.g. /path/to/probes
BUILD_XPC="${BUILD_XPC:-1}"                            # set to 0 to skip building embedded XPC services/client

# XPC source layout (in this repo)
XPC_ROOT="xpc"
XPC_API_FILE="${XPC_ROOT}/ProbeAPI.swift"
XPC_PROBE_CORE_FILE="${XPC_ROOT}/InProcessProbeCore.swift"
XPC_SESSION_HOST_FILE="${XPC_ROOT}/ProbeServiceSessionHost.swift"
XPC_QUARANTINE_SERVICE_HOST_FILE="${XPC_ROOT}/QuarantineLabServiceHost.swift"
XPC_CLIENT_MAIN="${XPC_ROOT}/client/main.swift"
XPC_QUARANTINE_CLIENT_MAIN="${XPC_ROOT}/quarantine-client/main.swift"
XPC_INHERIT_CHILD_MAIN="${XPC_ROOT}/child/main.swift"
XPC_SERVICES_DIR="${XPC_ROOT}/services"
XPC_ENTITLEMENTS_OVERLAY_DIR="${XPC_ROOT}/entitlements_overlays"
INJECTABLE_OVERLAY_PLIST="${XPC_ENTITLEMENTS_OVERLAY_DIR}/injectable.plist"
INJECTABLE_SUFFIX="__injectable"
INJECTABLE_BUNDLE_SUFFIX=".injectable"
INJECTABLE_ENTITLEMENTS_DIR=".tmp/injectable-entitlements"
# Swift/Clang module cache must be writable; the harness sandbox often blocks the default path under ~/.cache.
SWIFT_MODULE_CACHE="${SWIFT_MODULE_CACHE:-.tmp/swift-module-cache}"
SWIFT_OPT_LEVEL="${SWIFT_OPT_LEVEL:-}"
SWIFT_DEBUG_FLAGS="${SWIFT_DEBUG_FLAGS:-}"
PW_INSPECTION="${PW_INSPECTION:-1}"

if [[ "${PW_INSPECTION}" == "1" ]]; then
  if [[ -z "${SWIFT_OPT_LEVEL}" ]]; then
    SWIFT_OPT_LEVEL="-Onone"
  fi
  if [[ -z "${SWIFT_DEBUG_FLAGS}" ]]; then
    SWIFT_DEBUG_FLAGS="-g"
  fi
  if [[ -z "${RUSTFLAGS:-}" ]]; then
    export RUSTFLAGS="-C debuginfo=2 -C force-frame-pointers=yes -C opt-level=1"
  fi
fi

if [[ -z "${SWIFT_OPT_LEVEL}" ]]; then
  SWIFT_OPT_LEVEL="-O"
fi

# Signing identity. Prefer env override; otherwise require user to set it.
IDENTITY="${IDENTITY:-}"

if [[ -z "${IDENTITY}" ]]; then
  cat <<'EOF' 1>&2
ERROR: IDENTITY is not set.

Set it to your Developer ID Application identity string, for example:
  IDENTITY='Developer ID Application: Adam Hyland (42D369QV8E)' ./build.sh

You can find valid identities via:
  security find-identity -v -p codesigning
EOF
  exit 2
fi

if ! /usr/bin/security find-identity -v -p codesigning 2>/dev/null | /usr/bin/grep -Fq "\"${IDENTITY}\""; then
  cat <<EOF 1>&2
ERROR: codesigning identity not found in your keychain:
  ${IDENTITY}

Run:
  security find-identity -v -p codesigning

Then ensure the identity is installed/unlocked (or set IDENTITY to one of the listed identities).
EOF
  exit 2
fi

validate_injectable_overlay() {
  if [[ ! -f "${INJECTABLE_OVERLAY_PLIST}" ]]; then
    echo "ERROR: missing injectable entitlements overlay: ${INJECTABLE_OVERLAY_PLIST}" 1>&2
    exit 2
  fi
  /usr/bin/python3 - "${INJECTABLE_OVERLAY_PLIST}" <<'PY'
import plistlib
import sys

path = sys.argv[1]
with open(path, "rb") as fh:
    data = plistlib.load(fh)
if not isinstance(data, dict):
    print(f"ERROR: injectable overlay is not a plist dict: {path}", file=sys.stderr)
    sys.exit(2)
expected = {
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.allow-unsigned-executable-memory",
}
keys = set(data.keys())
if keys != expected:
    missing = sorted(expected - keys)
    extra = sorted(keys - expected)
    print(f"ERROR: injectable overlay keys mismatch in {path}", file=sys.stderr)
    if missing:
        print(f"  missing: {', '.join(missing)}", file=sys.stderr)
    if extra:
        print(f"  extra: {', '.join(extra)}", file=sys.stderr)
    sys.exit(2)
for key in expected:
    if data.get(key) is not True:
        print(f"ERROR: injectable overlay key {key} must be true in {path}", file=sys.stderr)
        sys.exit(2)
PY
}

merge_entitlements() {
  local base_path="$1"
  local out_path="$2"
  /usr/bin/python3 - "${base_path}" "${INJECTABLE_OVERLAY_PLIST}" "${out_path}" <<'PY'
import plistlib
import sys

base_path, overlay_path, out_path = sys.argv[1:4]

with open(base_path, "rb") as fh:
    base = plistlib.load(fh)
if not isinstance(base, dict):
    print(f"ERROR: base entitlements not a plist dict: {base_path}", file=sys.stderr)
    sys.exit(2)
with open(overlay_path, "rb") as fh:
    overlay = plistlib.load(fh)
if not isinstance(overlay, dict):
    print(f"ERROR: overlay entitlements not a plist dict: {overlay_path}", file=sys.stderr)
    sys.exit(2)

merged = dict(base)
for key in overlay.keys():
    merged[key] = True

ordered = {key: merged[key] for key in sorted(merged.keys())}
with open(out_path, "wb") as fh:
    plistlib.dump(ordered, fh, fmt=plistlib.FMT_XML, sort_keys=False)
    fh.write(b"\n")
PY
}

echo "==> Building Rust runner + tools"
cargo build --manifest-path "${RUNNER_MANIFEST}" --release \
  --bin policy-witness \
  --bin quarantine-observer \
  --bin sandbox-log-observer \
  --bin pw-inspector

# Find the built binary. (Assumes standard Cargo layout.)
RUNNER_BIN="runner/target/release/policy-witness"
if [[ ! -x "${RUNNER_BIN}" ]]; then
  echo "ERROR: expected policy-witness binary at ${RUNNER_BIN}" 1>&2
  exit 2
fi
QUARANTINE_OBSERVER_BIN="runner/target/release/quarantine-observer"
if [[ ! -x "${QUARANTINE_OBSERVER_BIN}" ]]; then
  echo "ERROR: expected quarantine-observer binary at ${QUARANTINE_OBSERVER_BIN}" 1>&2
  exit 2
fi
SANDBOX_LOG_OBSERVER_BIN="runner/target/release/sandbox-log-observer"
if [[ ! -x "${SANDBOX_LOG_OBSERVER_BIN}" ]]; then
  echo "ERROR: expected sandbox-log-observer binary at ${SANDBOX_LOG_OBSERVER_BIN}" 1>&2
  exit 2
fi
PW_INSPECTOR_BIN="runner/target/release/pw-inspector"
if [[ ! -x "${PW_INSPECTOR_BIN}" ]]; then
  echo "ERROR: expected pw-inspector binary at ${PW_INSPECTOR_BIN}" 1>&2
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
cp "${RUNNER_BIN}" "${APP_BUNDLE}/Contents/MacOS/policy-witness"
chmod +x "${APP_BUNDLE}/Contents/MacOS/policy-witness"

# Embed observer tooling (runs outside the App Sandbox boundary when launched from Terminal)
cp "${SANDBOX_LOG_OBSERVER_BIN}" "${APP_BUNDLE}/Contents/MacOS/sandbox-log-observer"
chmod +x "${APP_BUNDLE}/Contents/MacOS/sandbox-log-observer"

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
  validate_injectable_overlay
  SWIFTC_PATH="$(/usr/bin/xcrun --sdk macosx --find swiftc 2>/dev/null || true)"
  if [[ -z "${SWIFTC_PATH}" ]]; then
    echo "ERROR: BUILD_XPC=1 but swiftc was not found (install Xcode Command Line Tools)" 1>&2
    exit 2
  fi
  SWIFTC=(/usr/bin/xcrun --sdk macosx swiftc)
  if [[ ! -f "${XPC_API_FILE}" ]] || [[ ! -f "${XPC_PROBE_CORE_FILE}" ]] || [[ ! -f "${XPC_SESSION_HOST_FILE}" ]] || [[ ! -f "${XPC_QUARANTINE_SERVICE_HOST_FILE}" ]] || [[ ! -f "${XPC_CLIENT_MAIN}" ]] || [[ ! -f "${XPC_INHERIT_CHILD_MAIN}" ]]; then
    echo "ERROR: BUILD_XPC=1 but XPC sources are missing under ${XPC_ROOT}/" 1>&2
    exit 2
  fi

  echo "==> Building embedded XPC client (must live under Contents/MacOS so Bundle.main resolves to the app)"
  mkdir -p "${SWIFT_MODULE_CACHE}"
  SWIFT_FLAGS=("${SWIFT_OPT_LEVEL}")
  if [[ -n "${SWIFT_DEBUG_FLAGS}" ]]; then
    SWIFT_FLAGS+=("${SWIFT_DEBUG_FLAGS}")
  fi
  "${SWIFTC[@]}" -module-cache-path "${SWIFT_MODULE_CACHE}" "${SWIFT_FLAGS[@]}" -o "${APP_BUNDLE}/Contents/MacOS/xpc-probe-client" "${XPC_API_FILE}" "${XPC_CLIENT_MAIN}"
  chmod +x "${APP_BUNDLE}/Contents/MacOS/xpc-probe-client"

  if [[ -f "${XPC_QUARANTINE_CLIENT_MAIN}" ]]; then
    echo "==> Building embedded XPC quarantine client"
    "${SWIFTC[@]}" -module-cache-path "${SWIFT_MODULE_CACHE}" "${SWIFT_FLAGS[@]}" -o "${APP_BUNDLE}/Contents/MacOS/xpc-quarantine-client" "${XPC_API_FILE}" "${XPC_QUARANTINE_CLIENT_MAIN}"
    chmod +x "${APP_BUNDLE}/Contents/MacOS/xpc-quarantine-client"
  fi

  echo "==> Building inherit-child helper"
  "${SWIFTC[@]}" -module-cache-path "${SWIFT_MODULE_CACHE}" "${SWIFT_FLAGS[@]}" -o "${APP_BUNDLE}/Contents/MacOS/pw-inherit-child" "${XPC_API_FILE}" "${XPC_INHERIT_CHILD_MAIN}"
  chmod +x "${APP_BUNDLE}/Contents/MacOS/pw-inherit-child"
  echo "==> Building inherit-child helper (bad entitlements)"
  "${SWIFTC[@]}" -module-cache-path "${SWIFT_MODULE_CACHE}" "${SWIFT_FLAGS[@]}" -o "${APP_BUNDLE}/Contents/MacOS/pw-inherit-child-bad" "${XPC_API_FILE}" "${XPC_INHERIT_CHILD_MAIN}"
  chmod +x "${APP_BUNDLE}/Contents/MacOS/pw-inherit-child-bad"

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

      svc_sources=()
      if [[ "${svc_name}" == ProbeService_* ]]; then
        svc_sources=("${XPC_API_FILE}" "${XPC_PROBE_CORE_FILE}" "${XPC_SESSION_HOST_FILE}" "${svc_main}")
      elif [[ "${svc_name}" == QuarantineLab_* ]]; then
        svc_sources=("${XPC_API_FILE}" "${XPC_QUARANTINE_SERVICE_HOST_FILE}" "${svc_main}")
      else
        echo "ERROR: unknown XPC service family: ${svc_name} (expected ProbeService_* or QuarantineLab_*)" 1>&2
        exit 2
      fi

      "${SWIFTC[@]}" -module-cache-path "${SWIFT_MODULE_CACHE}" "${SWIFT_FLAGS[@]}" -o "${svc_bundle}/Contents/MacOS/${svc_name}" "${svc_sources[@]}"
      chmod +x "${svc_bundle}/Contents/MacOS/${svc_name}"

      twin_name="${svc_name}${INJECTABLE_SUFFIX}"
      twin_bundle="${APP_BUNDLE}/Contents/XPCServices/${twin_name}.xpc"
      rm -rf "${twin_bundle}"
      cp -R "${svc_bundle}" "${twin_bundle}"

      base_bundle_id="$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "${svc_info}")"
      if [[ -z "${base_bundle_id}" ]]; then
        echo "ERROR: missing CFBundleIdentifier in ${svc_info}" 1>&2
        exit 2
      fi

      mv "${twin_bundle}/Contents/MacOS/${svc_name}" "${twin_bundle}/Contents/MacOS/${twin_name}"
      /usr/libexec/PlistBuddy \
        -c "Set :CFBundleExecutable ${twin_name}" \
        -c "Set :CFBundleIdentifier ${base_bundle_id}${INJECTABLE_BUNDLE_SUFFIX}" \
        -c "Set :CFBundleName ${twin_name}" \
        "${twin_bundle}/Contents/Info.plist"
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
if [[ ! -f "${BAD_INHERIT_ENTITLEMENTS_PLIST}" ]]; then
  echo "ERROR: missing bad inherit entitlements plist: ${BAD_INHERIT_ENTITLEMENTS_PLIST}" 1>&2
  exit 2
fi
if [[ ! -f "${INSPECTOR_ENTITLEMENTS_PLIST}" ]]; then
  echo "ERROR: missing inspector entitlements plist: ${INSPECTOR_ENTITLEMENTS_PLIST}" 1>&2
  exit 2
fi

sign_macho_inherit() {
  local target="$1"
  local identifier="${2:-}"
  if [[ ! -e "${target}" ]]; then
    return 0
  fi
  if /usr/bin/file -b "${target}" | /usr/bin/grep -q "Mach-O"; then
    codesign \
      --force \
      --options runtime \
      --timestamp \
      --entitlements "${INHERIT_ENTITLEMENTS_PLIST}" \
      ${identifier:+--identifier "${identifier}"} \
      -s "${IDENTITY}" \
      "${target}"
  fi
}

sign_macho_inherit_bad() {
  local target="$1"
  local identifier="${2:-}"
  if [[ ! -e "${target}" ]]; then
    return 0
  fi
  if /usr/bin/file -b "${target}" | /usr/bin/grep -q "Mach-O"; then
    codesign \
      --force \
      --options runtime \
      --timestamp \
      --entitlements "${BAD_INHERIT_ENTITLEMENTS_PLIST}" \
      ${identifier:+--identifier "${identifier}"} \
      -s "${IDENTITY}" \
      "${target}"
  fi
}

sign_macho_plain() {
  local target="$1"
  if [[ ! -e "${target}" ]]; then
    return 0
  fi
  if /usr/bin/file -b "${target}" | /usr/bin/grep -q "Mach-O"; then
    codesign \
      --force \
      --options runtime \
      --timestamp \
      -s "${IDENTITY}" \
      "${target}"
  fi
}

sign_macho_entitlements() {
  local target="$1"
  local entitlements="$2"
  if [[ ! -e "${target}" ]]; then
    return 0
  fi
  if /usr/bin/file -b "${target}" | /usr/bin/grep -q "Mach-O"; then
    codesign \
      --force \
      --options runtime \
      --timestamp \
      --entitlements "${entitlements}" \
      -s "${IDENTITY}" \
      "${target}"
  fi
}

echo "==> Codesigning embedded helper tools (plain; unsandboxed host-side)"
if [[ -d "${APP_BUNDLE}/Contents/Helpers" ]]; then
  while IFS= read -r -d '' f; do
    sign_macho_plain "${f}"
  done < <(find "${APP_BUNDLE}/Contents/Helpers" -type f -print0)
fi

echo "==> Codesigning embedded MacOS tools (plain; unsandboxed host-side)"
sign_macho_plain "${APP_BUNDLE}/Contents/MacOS/xpc-probe-client"
sign_macho_plain "${APP_BUNDLE}/Contents/MacOS/xpc-quarantine-client"
sign_macho_plain "${APP_BUNDLE}/Contents/MacOS/sandbox-log-observer"
sign_macho_inherit "${APP_BUNDLE}/Contents/MacOS/pw-inherit-child"
sign_macho_inherit_bad "${APP_BUNDLE}/Contents/MacOS/pw-inherit-child-bad"

echo "==> Codesigning embedded XPC services"
if [[ "${BUILD_XPC}" == "1" ]] && [[ -d "${XPC_SERVICES_DIR}" ]]; then
  mkdir -p "${INJECTABLE_ENTITLEMENTS_DIR}"
  for svc_dir in "${XPC_SERVICES_DIR}"/*; do
    [[ -d "${svc_dir}" ]] || continue
    svc_name="$(basename "${svc_dir}")"
    svc_entitlements="${svc_dir}/Entitlements.plist"
    svc_bundle="${APP_BUNDLE}/Contents/XPCServices/${svc_name}.xpc"
    twin_name="${svc_name}${INJECTABLE_SUFFIX}"
    twin_bundle="${APP_BUNDLE}/Contents/XPCServices/${twin_name}.xpc"
    twin_entitlements="${INJECTABLE_ENTITLEMENTS_DIR}/${twin_name}.entitlements.plist"

    if [[ ! -d "${svc_bundle}" ]]; then
      echo "ERROR: expected XPC service bundle at ${svc_bundle}" 1>&2
      exit 2
    fi
    if [[ ! -f "${svc_entitlements}" ]]; then
      echo "ERROR: XPC service ${svc_name} is missing Entitlements.plist" 1>&2
      exit 2
    fi
    if [[ ! -d "${twin_bundle}" ]]; then
      echo "ERROR: expected injectable XPC service bundle at ${twin_bundle}" 1>&2
      exit 2
    fi

    if [[ "${svc_name}" == ProbeService_* ]]; then
      # Embed the inherit-child helper inside the service bundle so the sandbox can exec it.
      inherit_child_src="${APP_BUNDLE}/Contents/MacOS/pw-inherit-child"
      inherit_child_bad_src="${APP_BUNDLE}/Contents/MacOS/pw-inherit-child-bad"
      if [[ ! -x "${inherit_child_src}" ]]; then
        echo "ERROR: missing inherit child helper at ${inherit_child_src}" 1>&2
        exit 2
      fi
      if [[ ! -x "${inherit_child_bad_src}" ]]; then
        echo "ERROR: missing bad inherit child helper at ${inherit_child_bad_src}" 1>&2
        exit 2
      fi
      inherit_child_dst="${svc_bundle}/Contents/MacOS/pw-inherit-child"
      inherit_child_twin_dst="${twin_bundle}/Contents/MacOS/pw-inherit-child"
      inherit_child_bad_dst="${svc_bundle}/Contents/MacOS/pw-inherit-child-bad"
      inherit_child_bad_twin_dst="${twin_bundle}/Contents/MacOS/pw-inherit-child-bad"
      cp "${inherit_child_src}" "${inherit_child_dst}"
      cp "${inherit_child_src}" "${inherit_child_twin_dst}"
      cp "${inherit_child_bad_src}" "${inherit_child_bad_dst}"
      cp "${inherit_child_bad_src}" "${inherit_child_bad_twin_dst}"
      svc_bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${svc_bundle}/Contents/Info.plist" 2>/dev/null || true)"
      twin_bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "${twin_bundle}/Contents/Info.plist" 2>/dev/null || true)"
      sign_macho_inherit "${inherit_child_dst}" "${svc_bundle_id}"
      sign_macho_inherit "${inherit_child_twin_dst}" "${twin_bundle_id}"
      sign_macho_inherit_bad "${inherit_child_bad_dst}" "${svc_bundle_id}"
      sign_macho_inherit_bad "${inherit_child_bad_twin_dst}" "${twin_bundle_id}"
    fi

    codesign \
      --force \
      --options runtime \
      --timestamp \
      --entitlements "${svc_entitlements}" \
      -s "${IDENTITY}" \
      "${svc_bundle}"

    merge_entitlements "${svc_entitlements}" "${twin_entitlements}"
    codesign \
      --force \
      --options runtime \
      --timestamp \
      --entitlements "${twin_entitlements}" \
      -s "${IDENTITY}" \
      "${twin_bundle}"
  done
fi

echo "==> Writing evidence manifest (signed BOM)"
/usr/bin/python3 "tests/build-evidence.py" \
  --app-bundle "${APP_BUNDLE}" \
  --app-entitlements "${ENTITLEMENTS_PLIST}"

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

echo "==> Codesigning observer tools (not embedded)"
sign_macho_plain "${QUARANTINE_OBSERVER_BIN}"
sign_macho_plain "${SANDBOX_LOG_OBSERVER_BIN}"
sign_macho_entitlements "${PW_INSPECTOR_BIN}" "${INSPECTOR_ENTITLEMENTS_PLIST}"

echo "==> Creating zip (for notarization): ${ZIP_NAME}"
rm -f "${ZIP_NAME}"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "${APP_BUNDLE}" "${ZIP_NAME}"

echo
echo "DONE:"
echo "  - ${APP_BUNDLE}"
echo "  - ${ZIP_NAME}"
echo "  - ${QUARANTINE_OBSERVER_BIN}"
echo "  - ${SANDBOX_LOG_OBSERVER_BIN}"
echo "  - ${PW_INSPECTOR_BIN}"
echo
echo "Next (notarize with your saved profile):"
cat <<EOF
  xcrun notarytool submit "${ZIP_NAME}" --keychain-profile "dev-profile" --wait
  xcrun stapler staple "${APP_BUNDLE}"
  xcrun stapler validate -v "${APP_BUNDLE}"
  spctl -a -vv --type execute "${APP_BUNDLE}"
EOF
