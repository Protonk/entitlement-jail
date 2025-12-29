# Signing and notarization

This repo distributes `EntitlementJail.zip`, a ZIP containing a **stapled** `EntitlementJail.app` (notarization ticket embedded in the app).

We notarize an archive upload, staple the `.app`, then re-zip the stapled `.app` for distribution.

`build.sh` is the canonical implementation of how EntitlementJail is assembled, signed, and packaged. This document is the “why + debug guide”: what the build is doing, what matters for correctness, and how to diagnose signing/notarization failures without reinventing the script.

For usage/behavior contracts, see:

- User guide: [EntitlementJail.md](EntitlementJail.md)
- CLI contract: [runner/README.md](runner/README.md)

## Fast path
>build.sh prints the exact commands needed after building.

Build, sign, and package:

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build
```

Notarize the produced zip:

```sh
xcrun notarytool submit EntitlementJail.zip --keychain-profile "dev-profile" --wait
```

Do not rebuild, modify, or re-sign anything between submit and staple.

Staple + validate the app:

```sh
xcrun stapler staple EntitlementJail.app
xcrun stapler validate -v EntitlementJail.app
spctl -a -vv --type execute EntitlementJail.app
```

Create the **distribution zip** from the stapled app (stapling changes bundle contents, so zip after stapling):

```sh
rm -f EntitlementJail.zip
ditto -c -k --sequesterRsrc --keepParent EntitlementJail.app EntitlementJail.zip
```

If you don’t already have a Notary keychain profile, create one once (choose a profile name; the examples use `dev-profile`):

```sh
xcrun notarytool store-credentials "dev-profile" \
  --apple-id "you@example.com" \
  --team-id "TEAMID" \
  --password "app-specific-password"
```

## What build.sh does

Use this section to orient yourself and treat [build.sh](build.sh) as the authoritative reference.

1. **Validates `IDENTITY`**
   - Checks that the requested Developer ID Application identity exists in your keychain (`security find-identity -p codesigning`).
2. **Builds Rust binaries** from `runner/`
   - Launcher + helper tools (`runner`, `quarantine-observer`, `sandbox-log-observer`, `ej-inspector`).
3. **Assembles `EntitlementJail.app` layout**
   - Installs the launcher at `Contents/MacOS/entitlement-jail`.
   - Embeds `sandbox-log-observer` at `Contents/MacOS/sandbox-log-observer`.
   - Optionally embeds additional helper payloads under `Contents/Helpers/` (see `EMBED_FENCERUNNER_PATH`, `EMBED_PROBES_DIR` in the script).
4. **Builds Swift client helpers and XPC services** (when `BUILD_XPC=1`)
   - Builds `xpc-probe-client` and `xpc-quarantine-client` into `Contents/MacOS/`.
   - Enumerates `xpc/services/*` and builds each directory into `Contents/XPCServices/<ServiceName>.xpc`.
5. **Signs nested code (inside-out)**
   - Plain-signs embedded tools under `Contents/Helpers/` (Mach‑O only).
   - Plain-signs host-side tools under `Contents/MacOS/` (`xpc-probe-client`, `xpc-quarantine-client`, `sandbox-log-observer`).
   - Signs each XPC service bundle with its own `xpc/services/<ServiceName>/Entitlements.plist`.
   - Generates and signs each `__injectable` twin with the merged base entitlements + `xpc/entitlements_overlays/injectable.plist`.
6. **Generates Evidence**
   - Runs `tests/build-evidence.py` to produce the Evidence manifests inside the bundle.
7. **Signs the outer `.app`**
   - Signs `EntitlementJail.app` with hardened runtime and `EntitlementJail.entitlements` (empty by default).
8. **Verifies the resulting signature**
   - Uses strict verification (including `--deep`) as a sanity check.
9. **Creates `EntitlementJail.zip`**
   - Packages the app with `ditto -c -k --sequesterRsrc --keepParent`.
10. **Signs non-embedded helper tools**
   - Signs `runner/target/release/quarantine-observer` and `runner/target/release/sandbox-log-observer` (standalone).
   - Signs `runner/target/release/ej-inspector` with `Inspector.entitlements` (`com.apple.security.cs.debugger`). This tool is debugger-side and must not be embedded in the `.app`.

If any of these steps need to change, change `build.sh` first and then update the surrounding docs/tests.

## Important concepts

### Entitlements are the experimental variable

The host-side launcher (`EntitlementJail.app/Contents/MacOS/entitlement-jail`) is intentionally **not sandboxed** in the default build. It is signed with hardened runtime but no sandbox entitlement.
- `EntitlementJail.entitlements` exists for explicitness and is empty by default.
The sandbox boundary lives in the embedded XPC services:
- Each `EntitlementJail.app/Contents/XPCServices/<ServiceName>.xpc` is signed with the entitlements in `xpc/services/<ServiceName>/Entitlements.plist`.
- Each `EntitlementJail.app/Contents/XPCServices/<ServiceName>__injectable.xpc` is signed with the merged base entitlements + the fixed injectable overlay.
- Changing entitlements means adding/changing a service under `xpc/services/` (not “run arbitrary code by path”).

### Inside-out signing

Notarization expects that *every* executable inside the bundle is correctly signed. The order matters:

1. Sign nested executables first (embedded helper tools, embedded Swift clients, each XPC service).
2. Generate Evidence (which inspects the now-signed binaries).
3. Sign the outer `EntitlementJail.app` last.

This is why `build.sh` signs nested code explicitly and only uses `--deep` during verification.

### Hardened runtime and timestamp

The canonical signing invocations in `build.sh` include:

- `--options runtime` (hardened runtime)
- `--timestamp` (secure timestamp)

If notarization fails with “missing secure timestamp” or runtime-related complaints, treat it as “some nested thing wasn’t signed the way the script expects”.

### One Team ID

All embedded code (launcher, embedded clients, XPC services, embedded tools) should be signed with the **same** Developer ID Application identity (same Team ID).

Mixing Team IDs frequently breaks assumptions about “belongs to this app”, and can produce confusing runtime behavior even when `codesign` looks superficially OK.

### Evidence is part of the signed specimen

During the build, `tests/build-evidence.py` writes:

- `EntitlementJail.app/Contents/Resources/Evidence/manifest.json`
- `EntitlementJail.app/Contents/Resources/Evidence/profiles.json`
- `EntitlementJail.app/Contents/Resources/Evidence/symbols.json`

Key property: `profiles.json` is derived from **actual signed entitlements** extracted via `codesign -d --entitlements` from the embedded binaries.

Implications:

- If you change any embedded executable, any XPC service entitlements, or re-sign parts of the bundle, Evidence can become stale.
- Because Evidence lives *inside* the bundle, it is also covered by the outer app signature. Editing Evidence after signing invalidates the app signature.
- Practical rule: if you need to “fix signing”, rebuild with `make build` so signatures and Evidence stay coherent.

## Inspection commands

Useful when diagnosing failures.

Verify the app signature (strict, includes nested code):

```sh
codesign --verify --deep --strict --verbose=4 EntitlementJail.app
```

Show signing identity and Team ID:

```sh
codesign -dv --verbose=4 EntitlementJail.app 2>&1 | grep -E "Authority=|TeamIdentifier="
```

Show entitlements for a specific binary:

```sh
codesign -d --entitlements - -- EntitlementJail.app/Contents/MacOS/entitlement-jail
codesign -d --entitlements - -- EntitlementJail.app/Contents/MacOS/xpc-probe-client
codesign -d --entitlements - -- EntitlementJail.app/Contents/XPCServices/ProbeService_minimal.xpc/Contents/MacOS/ProbeService_minimal
```

Gatekeeper assessment:

```sh
spctl -a -vv --type execute EntitlementJail.app
```

Notarization logs (use the id printed by `notarytool submit`):

```sh
xcrun notarytool log <submission-id> --keychain-profile "dev-profile"
```

## Troubleshooting

- `ERROR: codesigning identity not found in your keychain`
  - `IDENTITY` doesn’t match exactly what `security find-identity -v -p codesigning` prints, or your keychain is locked.
- Notary: `Invalid: not signed with a valid Developer ID certificate`
  - Something was signed with Apple Development / ad hoc instead of a Developer ID Application identity.
- Notary: `missing secure timestamp`
  - A nested executable was signed without `--timestamp` (or wasn’t re-signed after being rebuilt/copied).
- `codesign --verify ...` reports `a sealed resource is missing or invalid` / `resource envelope is obsolete`
  - The bundle was modified after signing (including adding/removing files, or stapling and then validating an older zip).
  - Rebuild, or ensure the order is: sign → notarize → staple → zip (distribution zip).
- `xcrun stapler staple ...` fails (especially `Error 65`)
  - You’re stapling an app whose cdhash doesn’t match what you submitted; re-run `make build`, submit, then staple without rebuilding in between.
- XPC services won’t launch / `NSXPCConnection` fails to connect
  - Often indicates a signing/entitlements mismatch in the `.xpc` bundle or its executable.
  - Confirm the service executable exists at `.../<ServiceName>.xpc/Contents/MacOS/<ServiceName>` and inspect its entitlements with `codesign -d --entitlements -`.
- `verify-evidence` failures after “fixing signing”
  - Evidence is derived from signed entitlements/hashes during the build. If you re-sign or modify the bundle without regenerating Evidence, it can go stale.
  - The supported fix is to rebuild with `make build` so Evidence and signatures agree.
