# Signing and notarization

This repo distributes `PolicyWitness.zip`, a ZIP containing a **stapled** `PolicyWitness.app` (notarization ticket embedded in the app).

We notarize an archive upload, staple the `.app`, then re-zip the stapled `.app` for distribution.

`build.sh` is the canonical implementation of how PolicyWitness is assembled, signed, and packaged. This document is the “why + debug guide”: what the build is doing, what matters for correctness, and how to diagnose signing/notarization failures without reinventing the script.

For usage/behavior contracts, see:

- User guide: [PolicyWitness.md](PolicyWitness.md)
- CLI contract: [runner/README.md](runner/README.md)

## Fast path
>build.sh prints the exact commands needed after building.

Build, sign, and package:

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build
```

Notarize the produced zip:

```sh
xcrun notarytool submit PolicyWitness.zip --keychain-profile "dev-profile" --wait
```

Do not rebuild, modify, or re-sign anything between submit and staple.

Staple + validate the app:

```sh
xcrun stapler staple PolicyWitness.app
xcrun stapler validate -v PolicyWitness.app
spctl -a -vv --type execute PolicyWitness.app
```

Create the **distribution zip** from the stapled app (stapling changes bundle contents, so zip after stapling):

```sh
rm -f PolicyWitness.zip
ditto -c -k --sequesterRsrc --keepParent PolicyWitness.app PolicyWitness.zip
```

## What build.sh does

Use this section to orient yourself and treat [build.sh](build.sh) as the authoritative reference. For XPC layout details, see [xpc/README.md](xpc/README.md).

1. **Validates `IDENTITY`**
   - Checks that the requested Developer ID Application identity exists in your keychain (`security find-identity -p codesigning`).
2. **Builds Rust binaries** from `runner/`
   - Launcher + helper tools (`policy-witness`, `quarantine-observer`, `sandbox-log-observer`, `pw-inspector`).
3. **Assembles `PolicyWitness.app` layout**
   - Installs the launcher at `Contents/MacOS/policy-witness`.
   - Embeds `sandbox-log-observer` at `Contents/MacOS/sandbox-log-observer`.
   - Optionally embeds additional helper payloads under `Contents/Helpers/` (see `EMBED_FENCERUNNER_PATH`, `EMBED_PROBES_DIR` in the script).
4. **Builds Swift client helpers and XPC services** (when `BUILD_XPC=1`)
   - Builds `xpc-probe-client`, `xpc-quarantine-client`, `pw-inherit-child`, and `pw-inherit-child-bad` into `Contents/MacOS/`.
   - Enumerates `xpc/services/*` and builds each directory into `Contents/XPCServices/<ServiceName>.xpc`.
   - Copies `pw-inherit-child` and `pw-inherit-child-bad` into each `ProbeService_*` bundle so sandboxed services can `posix_spawn` them.
5. **Signs nested code (inside-out)**
   - Plain-signs embedded tools under `Contents/Helpers/` (Mach‑O only).
   - Plain-signs host-side tools under `Contents/MacOS/` (`xpc-probe-client`, `xpc-quarantine-client`, `sandbox-log-observer`).
   - Signs `pw-inherit-child` (good) with inherit entitlements (`PolicyWitness.inherit.entitlements`).
   - Signs `pw-inherit-child-bad` (canary) with intentionally contaminated inherit entitlements (`PolicyWitness.inherit.bad.entitlements`).
   - Re-signs the per-service embedded copies with `--identifier <service bundle id>` so security-scoped bookmark behavior is stable and attributable to the service identity.
   - Signs each XPC service bundle with its own `xpc/services/<ServiceName>/Entitlements.plist`.
   - Generates and signs each `__injectable` twin with the merged base entitlements + `xpc/entitlements_overlays/injectable.plist`.
6. **Generates Evidence**
   - Runs `tests/build-evidence.py` to produce the Evidence manifests inside the bundle.
7. **Signs the outer `.app`**
   - Signs `PolicyWitness.app` with hardened runtime and `PolicyWitness.entitlements` (empty by default).
8. **Verifies the resulting signature**
   - Uses strict verification (including `--deep`) as a sanity check.
9. **Creates `PolicyWitness.zip`**
   - Packages the app with `ditto -c -k --sequesterRsrc --keepParent`.
10. **Signs non-embedded helper tools**
   - Signs `runner/target/release/quarantine-observer` and `runner/target/release/sandbox-log-observer` (standalone).
   - Signs `runner/target/release/pw-inspector` with `Inspector.entitlements` (`com.apple.security.cs.debugger`). This tool is debugger-side and must not be embedded in the `.app`.

If any of these steps need to change, change `build.sh` first and then update the surrounding docs/tests.

## Important concepts

### Entitlements are the experimental variable

The host-side launcher (`PolicyWitness.app/Contents/MacOS/policy-witness`) is intentionally **not sandboxed** in the default build. It is signed with hardened runtime but no sandbox entitlement.
- `PolicyWitness.entitlements` exists for explicitness and is empty by default.
The sandbox boundary lives in the embedded XPC services:
- Each `PolicyWitness.app/Contents/XPCServices/<ServiceName>.xpc` is signed with the entitlements in `xpc/services/<ServiceName>/Entitlements.plist`.
- Each `PolicyWitness.app/Contents/XPCServices/<ServiceName>__injectable.xpc` is signed with the merged base entitlements + the fixed injectable overlay.
- Changing entitlements means adding/changing a service under `xpc/services/` (not “run arbitrary code by path”).

The `inherit_child` helpers are not part of the “entitlements as the variable” axis:

- `pw-inherit-child` must be signed with **only** App Sandbox + `inherit` (no other `com.apple.security.*` keys).
- `pw-inherit-child-bad` intentionally violates the inheritance contract so the OS predictably aborts it (used as a signing/twinning regression canary).

### Inside-out signing

	Notarization expects that *every* executable inside the bundle is correctly signed. The order matters:

	1. Sign nested executables first (embedded helper tools, embedded Swift clients, each XPC service).
	2. Generate Evidence (which inspects the signed binaries).
	3. Sign the outer `PolicyWitness.app` last.

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

- `PolicyWitness.app/Contents/Resources/Evidence/manifest.json`
- `PolicyWitness.app/Contents/Resources/Evidence/profiles.json`
- `PolicyWitness.app/Contents/Resources/Evidence/symbols.json`

Key property: `profiles.json` is derived from **actual signed entitlements** extracted via `codesign -d --entitlements` from the embedded binaries.

This matters because the experiment knob is OS-enforced: each embedded XPC service is independently signed (base + `__injectable` variants are first-class), so “what the OS enforces” is exactly what Evidence inspects.

Implications:

- If you change any embedded executable, any XPC service entitlements, or re-sign parts of the bundle, Evidence can become stale.
- Because Evidence lives *inside* the bundle, it is also covered by the outer app signature. Editing Evidence after signing invalidates the app signature.
- Practical rule: if you need to “fix signing”, rebuild with `make build` so signatures and Evidence stay coherent.

`tests/build-evidence.py` also enforces guardrails for `inherit_child`:

- `pw-inherit-child` must have exactly the two inheritance entitlements (app-sandbox + inherit) in the app-level binary and in every per-service embedded copy (including injectable twins).
- `pw-inherit-child-bad` must carry the intended contaminating entitlement and is expected to fail the inheritance contract at runtime (abort canary).
- That canary is an intentional signing/twinning regression tripwire: expected abort outcomes remain distinct in `normalized_outcome`, and guardrail witness fields (bundle id, team id, entitlements, contract_ok) keep early aborts diagnosable.

## Inspection commands

Useful when diagnosing failures.

Verify the app signature (strict, includes nested code):

```sh
codesign --verify --deep --strict --verbose=4 PolicyWitness.app
```

Show signing identity and Team ID:

```sh
codesign -dv --verbose=4 PolicyWitness.app 2>&1 | grep -E "Authority=|TeamIdentifier="
```

Show entitlements for a specific binary:

```sh
codesign -d --entitlements - -- PolicyWitness.app/Contents/MacOS/policy-witness
codesign -d --entitlements - -- PolicyWitness.app/Contents/MacOS/xpc-probe-client
codesign -d --entitlements - -- PolicyWitness.app/Contents/XPCServices/ProbeService_minimal.xpc/Contents/MacOS/ProbeService_minimal
codesign -d --entitlements - -- PolicyWitness.app/Contents/XPCServices/ProbeService_minimal.xpc/Contents/MacOS/pw-inherit-child
codesign -d --entitlements - -- PolicyWitness.app/Contents/XPCServices/ProbeService_minimal.xpc/Contents/MacOS/pw-inherit-child-bad
```

Gatekeeper assessment:

```sh
spctl -a -vv --type execute PolicyWitness.app
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
- `bookmark_op` / `bookmark_roundtrip` / `inherit_child --scenario bookmark_ferry` fails with `bookmark_resolve_failed` (often mentioning ScopedBookmarksAgent) even though `com.apple.security.files.bookmarks.app-scope` is present
  - Treat this as a likely **code identity mismatch** (bookmark created under one bundle id, resolved under another) or a helper binary signed with the wrong identifier.
  - For `inherit_child`, the per-service embedded helper at `.../ProbeService_*.xpc/Contents/MacOS/pw-inherit-child` must be signed with `--identifier <service bundle id>` (build.sh does this); copying/re-signing without `--identifier` is a common way to break bookmark_ferry determinism.
  - Inspect identifier + Team ID: `codesign -dv --verbose=4 <path> 2>&1 | grep -E 'Identifier=|TeamIdentifier='`.
- `verify-evidence` failures after “fixing signing”
  - Evidence is derived from signed entitlements/hashes during the build. If you re-sign or modify the bundle without regenerating Evidence, it can go stale.
  - The supported fix is to rebuild with `make build` so Evidence and signatures agree.
