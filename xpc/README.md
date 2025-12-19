# XPC subsystem (architecture + extension manual)

This document is the authoritative reference for the XPC-based execution surfaces in this repo: how the XPC client helpers and XPC services fit together, and how to add new XPC services as research targets.

## Why XPC exists in this repo

The `EntitlementJail.app` main executable is a sandboxed Rust launcher. For entitlements-as-a-variable research, child-process sandbox inheritance is restrictive and brittle, and Apple’s guidance is to prefer XPC services for helper-like functionality (see [Apple Developer: Enabling App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html?utm_source=chatgpt.com)).

XPC gives you:

- A separate signed target per experiment (`.xpc`), each with its own entitlements.
- A launchd-managed process boundary that avoids common `process-exec*` failure modes associated with staged binaries.

## Components

### `ProbeAPI.swift`: shared protocol + types

`ProbeAPI.swift` defines:

- The NSXPC exported protocols:
  - `ProbeServiceProtocol` (`runProbe(_:withReply:)`)
  - `QuarantineLabProtocol` (`writeArtifact(_:withReply:)`)
- Codable request/response types for a JSON-over-XPC wire format:
  - `RunProbeRequest` / `RunProbeResponse`
  - `QuarantineWriteRequest` / `QuarantineWriteResponse`
  - Supporting types like `LayerAttribution` and `QuarantineXattrParsed`

Both requests and responses are serialized as JSON bytes (`Data`) rather than passing rich Objective‑C objects over XPC. This keeps the interface inspectable and stable, and makes it easy for callers to treat the service output as a structured research record.

### Client helpers (why the main binary delegates)

The sandboxed Rust launcher does not speak NSXPC directly. Instead it runs embedded Swift helper executables:

- `xpc/client/main.swift` → builds `Contents/Helpers/xpc-probe-client`
- `xpc/quarantine-client/main.swift` → builds `Contents/Helpers/xpc-quarantine-client`

The Rust launcher’s `run-xpc` / `quarantine-lab` commands simply invoke these helpers (see [runner/README.md](../runner/README.md)).

Client helper behavior (both follow the same pattern):

- Connect via `NSXPCConnection(serviceName: <bundle-id>)`.
- Send a JSON request as `Data`.
- Print the JSON response to stdout.
- Exit with the response `rc` (best-effort decode; falls back to exit code `1` on decode errors).

### Services (the experimental targets)

Services live under `xpc/services/<ServiceName>/` and are embedded into the app as:

- `EntitlementJail.app/Contents/XPCServices/<ServiceName>.xpc`

Each service is its own research target:

- `Info.plist` defines the service bundle id and executable.
- `Entitlements.plist` is the *experimental variable*.
- `main.swift` implements the exported protocol and returns JSON responses.

Current services:

- `ProbeService_minimal`: runs an embedded probe executable and returns `{rc, stdout, stderr, ...}`.
- `QuarantineLab_default`: writes/opens/copies artifacts and reports `com.apple.quarantine` deltas.
- `QuarantineLab_user_selected_executable`: identical code to `QuarantineLab_default`, but with different entitlements.

## Safe probe resolution (no traversal, no container staging)

XPC services that execute probes must only execute **bundle-embedded** probes, and must not accept arbitrary filesystem paths.

The reference policy in `ProbeService_minimal/main.swift` is:

- The caller passes a `probe_id` (a single path component).
- The service rejects empty ids and any id containing `/`, `\\`, `.` or `..` patterns.
- The service resolves probes *relative to the host app bundle*:
  - `EntitlementJail.app/Contents/Helpers/Probes/<probe_id>`
  - `EntitlementJail.app/Contents/Helpers/<probe_id>`
- The service executes only if `FileManager.isExecutableFile(atPath:)` is true.

This is deliberate: it prevents path traversal, and prevents reintroducing “stage into container then exec by path” patterns that are commonly blocked (and are easy to misattribute).

## Inheritance helpers vs XPC services

This repo supports both inheritance helpers (`run-embedded`) and XPC services (`run-xpc`), but they have different constraints.

- XPC services are the Apple-preferred structure for helper-like functionality, and are the recommended way to make entitlements a first-class experimental variable (see [Apple Developer: Enabling App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html?utm_source=chatgpt.com)).
- Sandbox inheritance for child processes has strict entitlement requirements: inheritance helpers must be signed with exactly `com.apple.security.app-sandbox` + `com.apple.security.inherit`, and the main app should not set `com.apple.security.inherit` (see [Apple Developer: Enabling App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html?utm_source=chatgpt.com)).

Signing details live in [SIGNING.md](../SIGNING.md).

## Adding a new XPC service (research target)

1. Create a new directory under `xpc/services/<ServiceName>/`.
2. Add:
   - `Info.plist` (unique `CFBundleIdentifier`, matching `CFBundleExecutable`)
   - `Entitlements.plist` (start with `com.apple.security.app-sandbox = true`, then add the entitlement(s) you want to study)
   - `main.swift` (implement an exported NSXPC protocol, usually one from `ProbeAPI.swift`)
3. Ensure your service does not accept arbitrary paths for execution. Follow the safe probe resolution policy above.
4. Build/embed/sign the app (see [SIGNING.md](../SIGNING.md)).

The build script discovers services by enumerating `xpc/services/*` and will embed/sign each service bundle it finds.

## Quarantine Lab matrix (what varies)

Quarantine Lab exists to keep quarantine/Gatekeeper observations separate from Seatbelt claims.

Services:

- `QuarantineLab_default`: App Sandbox only.
- `QuarantineLab_user_selected_executable`: App Sandbox + `com.apple.security.files.user-selected.executable`.

Operations (`--operation`):

- `create_new`: write a new artifact (default).
- `open_only`: open/read an existing path (or the derived output path) and report xattr delta.
- `open_existing_save`: read an existing path and save a copy to a new output path.

Payload classes (`<payload-class>`):

- `shell_script` (`.sh`, default executable)
- `command_file` (`.command`, default executable)
- `text` (`.txt`, not executable)
- `webarchive_like` (`.webarchive`-shaped payload; intended for writing/quarantine experiments, not WebArchive correctness)

Selection annotation (`--selection`):

- The “selection mechanism” field is metadata only. It does not grant access and does not change authorization; it exists to prevent “user selected it therefore it can execute” claims from sneaking in without an explicit, testable mechanism.
