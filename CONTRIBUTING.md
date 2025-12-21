# CONTRIBUTING

Contributions here are experiments, not product features: keep entitlements as the independent variable by adding or modifying **XPC services**, and keep probes in-process (no exec-by-path). When you add probes, use `baseDetails(...)` so every response carries `service_pid`/`probe_pid` and can be tied to **host-side** sandbox log capture; in-app log capture is diagnostic only and not evidence.

The worked examples below cover the two most common extension paths: adding an entitlement-variant XPC service and adding a new probe. As you follow them, keep the discovery surfaces in sync (`probe_catalog`, per-probe `--help`, and the substrate usage list) so other agents can run the examples without reading source first.

## Worked example 1: add a new XPC service (entitlement lattice)

### Goal: add `ProbeService_echo` (a minimal service that does not exec anything)

We’ll add a new XPC service named `ProbeService_echo` that implements the existing `ProbeServiceProtocol` (defined in `xpc/ProbeAPI.swift`) and simply echoes the request in the JSON response.

Why this is a good “first service”:

- It is launchd-managed (XPC), not a child-process inheritance helper.
- It exercises the entire pipeline: build → embed into the `.app` → sign → connect over NSXPC → get a JSON response.
- It does **not** execute any probes or artifacts, so it’s safe to run while you’re getting the workflow right.

### Step 1: add the service directory + files

Create a new directory:

- `xpc/services/ProbeService_echo/`

Add these three files:

### `xpc/services/ProbeService_echo/Info.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>ProbeService_echo</string>
  <key>CFBundleIdentifier</key>
  <string>com.yourteam.entitlement-jail.ProbeService_echo</string>
  <key>CFBundleName</key>
  <string>ProbeService_echo</string>
  <key>CFBundlePackageType</key>
  <string>XPC!</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>XPCService</key>
  <dict>
    <key>ServiceType</key>
    <string>Application</string>
  </dict>
</dict>
</plist>
```

### `xpc/services/ProbeService_echo/Entitlements.plist`

Start minimal (App Sandbox only). Treat this file as the experimental variable later.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.app-sandbox</key>
  <true/>
</dict>
</plist>
```

### `xpc/services/ProbeService_echo/main.swift`

This service:

- Receives a JSON request (`RunProbeRequest`) as `Data`
- Decodes it (best effort)
- Returns a JSON response (`RunProbeResponse`) with a human-readable “echo” in `stdout`

```swift
import Foundation

final class ProbeServiceEcho: NSObject, ProbeServiceProtocol {
    func runProbe(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        let response: RunProbeResponse
        do {
            let decoded = try decodeJSON(RunProbeRequest.self, from: request)
            let stdout = """
            ProbeService_echo
            service_bundle_id=\(Bundle.main.bundleIdentifier ?? "unknown")
            probe_id=\(decoded.probe_id)
            argv=\(decoded.argv.joined(separator: " "))
            """
            response = RunProbeResponse(
                rc: 0,
                stdout: stdout,
                stderr: "",
                normalized_outcome: "echo",
                sandbox_log_excerpt_ref: nil
            )
        } catch {
            response = RunProbeResponse(
                rc: 2,
                stdout: "",
                stderr: "bad request: \(error)",
                normalized_outcome: "bad_request",
                sandbox_log_excerpt_ref: nil
            )
        }

        do {
            reply(try encodeJSON(response))
        } catch {
            let fallback = #"{"rc":2,"stdout":"","stderr":"failed to encode response","normalized_outcome":"encode_failed","sandbox_log_excerpt_ref":null}"#
            reply(Data(fallback.utf8))
        }
    }
}

final class ServiceDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: ProbeServiceProtocol.self)
        newConnection.exportedObject = ProbeServiceEcho()
        newConnection.resume()
        return true
    }
}

let listener = NSXPCListener.service()
let delegate = ServiceDelegate()
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
```

### Step 2: build + embed the app (XPC included)

The build script discovers services by enumerating `xpc/services/*`, embeds each one into the `.app`, signs nested code, then signs the outer app bundle.

Run:

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' ./build-macos.sh
```

After this completes, you should have:

- `EntitlementJail.app/Contents/XPCServices/ProbeService_echo.xpc`

### Step 3: run/test the new service

This repo’s `run-xpc` mode delegates to the embedded helper `xpc-probe-client`, which expects the service to implement `ProbeServiceProtocol`.

Run:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc com.yourteam.entitlement-jail.ProbeService_echo hello one two
```

Expected result:

- A single JSON line printed to stdout
- `rc` should be `0`
- `stdout` should contain `ProbeService_echo`, the service bundle id, and your `probe_id`/`argv` echo

### Step 4: signing (what must be signed when you add a service)

If you use `./build-macos.sh`, signing is handled for you.

If you manually add/modify a service inside an existing `EntitlementJail.app`, you must sign **inside-out**:

1. Sign the new/changed `.xpc` bundle with its entitlements
2. Re-sign the outer `EntitlementJail.app` (because bundle contents changed)

Copy/pasteable manual signing sequence (no line continuations; identity always quoted):

```sh
APP="EntitlementJail.app"
ID='Developer ID Application: YOUR NAME (TEAMID)'

APP_ENT="EntitlementJail.entitlements"
INHERIT_ENT="EntitlementJail.inherit.entitlements"

codesign -f --options runtime --timestamp --entitlements "$INHERIT_ENT" -s "$ID" "$APP/Contents/MacOS/xpc-probe-client"
codesign -f --options runtime --timestamp --entitlements "$INHERIT_ENT" -s "$ID" "$APP/Contents/MacOS/xpc-quarantine-client"

for svc_dir in xpc/services/*; do
  svc_name="$(basename "$svc_dir")"
  ent="${svc_dir}/Entitlements.plist"
  codesign -f --options runtime --timestamp --entitlements "$ent" -s "$ID" "$APP/Contents/XPCServices/${svc_name}.xpc"
done

codesign -f --options runtime --timestamp --entitlements "$APP_ENT" -s "$ID" "$APP"

codesign --verify --deep --strict --verbose=4 "$APP"
```

Notes:

- Sign everything with the same Team ID (same signing identity). Mixing Team IDs breaks “belongs to this app” assumptions.
- Avoid using `codesign --deep` as a crutch for signing. Sign known nested items explicitly, then sign the outer app. (Using `--deep` for verification is fine.)

### Step 5: working with the `.app` after signing

- Any modification to `EntitlementJail.app` after signing (adding/removing/replacing a helper or `.xpc`) invalidates the signature; re-sign (inside-out) after changes.
- If you zip the `.app` for sharing/notarization, zip **after** signing:

```sh
APP="EntitlementJail.app"
ditto -c -k --sequesterRsrc --keepParent "$APP" EntitlementJail.zip
```

For deeper signing/notarization troubleshooting, see `SIGNING.md`.

## Worked example 2: add a new in-process probe (observer)

### Goal: add `process_identity` (UID/GID snapshot; no side effects)

This example adds a new probe to the shared in-process core and to the substrate usage list, so it can be used in baseline/policy/entitlement tri-runs.

### Step 1: register the probe in the catalog + dispatcher

In `xpc/InProcessProbeCore.swift`:

- Add a new `ProbeSpec` entry (so `probe_catalog` and `<probe-id> --help` work).
- Add a `case` in `run(...)` to dispatch to the new probe.

Example snippets:

```swift
// In the probeSpecs list:
ProbeSpec(
    probe_id: "process_identity",
    summary: "report uid/euid/gid/egid (observer)",
    usage: "process_identity",
    required_args: [],
    optional_args: [],
    examples: ["process_identity"],
    entitlement_hints: ["none (observer)"],
    notes: ["Returns UID/GID info in details."]
),
```

```swift
// In run(_:)
case "process_identity":
    return probeProcessIdentity()
```

### Step 2: implement the probe using `baseDetails`

Add a new function in `xpc/InProcessProbeCore.swift`:

```swift
private static func probeProcessIdentity() -> RunProbeResponse {
    let details = baseDetails([
        "probe_family": "process_identity",
        "uid": "\(getuid())",
        "euid": "\(geteuid())",
        "gid": "\(getgid())",
        "egid": "\(getegid())",
    ])
    return RunProbeResponse(
        rc: 0,
        stdout: "",
        stderr: "",
        normalized_outcome: "ok",
        errno: nil,
        error: nil,
        details: details,
        layer_attribution: nil,
        sandbox_log_excerpt_ref: nil
    )
}
```

`baseDetails(...)` ensures the response carries `service_pid`/`probe_pid`, which is the single source of truth for host-side log capture.

### Step 3: update substrate help text (and docs)

Add the new probe id to the usage list in `experiments/substrate/main.swift` so `witness-substrate --help` stays accurate. If the probe is user-facing, also update the built-in probe list in `runner/README.md`.

### Step 4: build + run

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' ./build-macos.sh
./experiments/bin/witness-substrate probe process_identity
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc com.yourteam.entitlement-jail.ProbeService_minimal process_identity
```

If a new probe is expected to trigger denies, run it via the harness (or `./scripts/ej-smoke.sh`) so host-side log capture can provide deny evidence; in-app log capture is diagnostic only.

## Smoke tests and unit tests

Quick sanity checks (no artifact execution beyond probes):

```sh
./scripts/ej-smoke.sh
```

Notes:

- The script warns (but does not fail) if `EntitlementJail.app` is missing or unsigned; substrate + harness checks still run.
- `run-xpc` smoke checks are only run when the app is present and passes `codesign --verify --deep --strict`.

Unit tests (runner helpers):

```sh
cargo test --manifest-path runner/Cargo.toml
```
