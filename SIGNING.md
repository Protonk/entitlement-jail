# Signing (research use)

This document is the canonical reference for identities, entitlements, signing order, packaging/notarization (optional), and troubleshooting for this repo.

## Entitlements + targets

- Main app entitlements live in `EntitlementJail.entitlements` and should enable the App Sandbox (`com.apple.security.app-sandbox`) but must **not** set `com.apple.security.inherit` (see [Apple Developer: Enabling App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html?utm_source=chatgpt.com)).
- Sandboxed child-process inheritance helpers must be signed with **exactly** `com.apple.security.app-sandbox` + `com.apple.security.inherit` (and no other entitlements). This repo provides `EntitlementJail.inherit.entitlements` for that purpose (see [Apple Developer: Enabling App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html?utm_source=chatgpt.com)).
- XPC services are separate signed targets with their own entitlement plists under `xpc/services/<ServiceName>/Entitlements.plist` (treat the service entitlements as the experimental variable).
- Every Mach-O executable inside a sandboxed app bundle (helpers, XPC services, etc.) needs explicit signing/sandboxing attention; don’t assume the outer app signature “covers” nested executables (see [Apple Developer QA1773: Common app sandboxing issues](https://developer.apple.com/library/archive/qa/qa1773/_index.html?utm_source=chatgpt.com)).
- The XPC client helper tools (`xpc-probe-client`, `xpc-quarantine-client`) are embedded under `EntitlementJail.app/Contents/MacOS/` to preserve app bundle context for XPC lookup; they must be signed for sandbox inheritance like other embedded helpers.

Team ID expectation:

- Sign the app, embedded helpers, and embedded XPC services with the **same Team ID** (i.e. the same signing identity). Mixing Team IDs breaks assumptions around “belongs to this app” behavior (including inheritance).

## Preferred path: Makefile

`make build` wraps `build-macos.sh`, which assembles `EntitlementJail.app`, signs nested code first, then signs the outer `.app`, and produces `EntitlementJail.zip`.

- `IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build`

## Manual signing (no `--deep` for signing)

Use this when you want to re-sign an existing `EntitlementJail.app` or debug signing issues. This sequence is “inside-out” (nested code first, outer app last) and avoids shell pitfalls (no line continuations; identity always quoted).

```sh
APP="EntitlementJail.app"
ID='Developer ID Application: YOUR NAME (TEAMID)'

APP_ENT="EntitlementJail.entitlements"
INHERIT_ENT="EntitlementJail.inherit.entitlements"

codesign -f --options runtime --timestamp --entitlements "$INHERIT_ENT" -s "$ID" "$APP/Contents/MacOS/xpc-probe-client"
codesign -f --options runtime --timestamp --entitlements "$INHERIT_ENT" -s "$ID" "$APP/Contents/MacOS/xpc-quarantine-client"

codesign -f --options runtime --timestamp --entitlements "xpc/services/QuarantineLab_default/Entitlements.plist" -s "$ID" "$APP/Contents/XPCServices/QuarantineLab_default.xpc"
codesign -f --options runtime --timestamp --entitlements "xpc/services/QuarantineLab_net_client/Entitlements.plist" -s "$ID" "$APP/Contents/XPCServices/QuarantineLab_net_client.xpc"
codesign -f --options runtime --timestamp --entitlements "xpc/services/QuarantineLab_downloads_rw/Entitlements.plist" -s "$ID" "$APP/Contents/XPCServices/QuarantineLab_downloads_rw.xpc"
codesign -f --options runtime --timestamp --entitlements "xpc/services/QuarantineLab_user_selected_executable/Entitlements.plist" -s "$ID" "$APP/Contents/XPCServices/QuarantineLab_user_selected_executable.xpc"
codesign -f --options runtime --timestamp --entitlements "xpc/services/ProbeService_minimal/Entitlements.plist" -s "$ID" "$APP/Contents/XPCServices/ProbeService_minimal.xpc"
codesign -f --options runtime --timestamp --entitlements "xpc/services/ProbeService_net_client/Entitlements.plist" -s "$ID" "$APP/Contents/XPCServices/ProbeService_net_client.xpc"
codesign -f --options runtime --timestamp --entitlements "xpc/services/ProbeService_downloads_rw/Entitlements.plist" -s "$ID" "$APP/Contents/XPCServices/ProbeService_downloads_rw.xpc"
codesign -f --options runtime --timestamp --entitlements "xpc/services/ProbeService_user_selected_executable/Entitlements.plist" -s "$ID" "$APP/Contents/XPCServices/ProbeService_user_selected_executable.xpc"

codesign -f --options runtime --timestamp --entitlements "$APP_ENT" -s "$ID" "$APP"

codesign --verify --deep --strict --verbose=4 "$APP"
```

Notes:

- Do not add `com.apple.security.inherit` to the main app; only inheritance helpers should carry it (see [Apple Developer: Enabling App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html?utm_source=chatgpt.com)).
- Avoid `codesign --deep` for signing: sign known nested executables explicitly, then sign the outer app. (Using `--deep` for verification is fine.)

## Packaging (`ditto`)

If you create a `.zip` for notarization/distribution, use `ditto`. The archive itself is not signed; the signed content is the `.app` inside (see [Apple Developer Forums: Packaging Mac Software for Distrib…](https://developer.apple.com/forums/thread/701581?utm_source=chatgpt.com)).

```sh
APP="EntitlementJail.app"
ditto -c -k --sequesterRsrc --keepParent "$APP" EntitlementJail.zip
```

## Optional: notarize a ZIP

This is optional for research use. If you choose to notarize:

1. Zip the `.app` with `ditto` (see [Apple Developer Forums: Packaging Mac Software for Distrib…](https://developer.apple.com/forums/thread/701581?utm_source=chatgpt.com)).
2. Submit and wait:

```sh
xcrun notarytool submit EntitlementJail.zip --keychain-profile 'AC_PROFILE' --wait
```

3. Staple and validate. Stapling attaches a notarization ticket to the **app bundle**, not to the ZIP (see [Apple Help: Upload a macOS app to be notarized](https://help.apple.com/xcode/mac/current/en.lproj/dev88332a81e.html?utm_source=chatgpt.com)).

```sh
APP="EntitlementJail.app"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
```

If you distribute a ZIP, staple the `.app` first and then re-zip it (stapling changes the bundle contents) (see [Apple Help: Upload a macOS app to be notarized](https://help.apple.com/xcode/mac/current/en.lproj/dev88332a81e.html?utm_source=chatgpt.com)).

## Troubleshooting

- `Invalid: not signed with a valid Developer ID certificate` → you likely signed with an Apple Development identity or ad hoc (`-s -`); re-sign with a `Developer ID Application: ...` identity.
- `missing secure timestamp` → add `--timestamp` to every signing invocation.
- `codesign` segfault / unstable behavior → retry from a clean shell; if name-based identity resolution is flaky, sign with the cert’s SHA-1 hash from `security find-identity -v -p codesigning` (use that hex string as the `-s` argument).
