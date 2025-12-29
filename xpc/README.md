# `xpc/` (Swift XPC subsystem: build + targets)

This is developer documentation for the Swift code under `xpc/`: the shared XPC wire types, the embedded XPC client helpers, and the XPC services that act as the repo’s “entitlements as a variable” targets.

This document is intentionally build/implementation-focused and avoids duplicating CLI flag documentation.

For usage/behavior contracts, see:

- User guide: [EntitlementJail.md](../EntitlementJail.md)
- CLI contract: [runner/README.md](../runner/README.md)
- Signing/build procedure: [SIGNING.md](../SIGNING.md)
- Contribution guide (includes a toy “add a service” example): [CONTRIBUTING.md](../CONTRIBUTING.md)

## What lives in `xpc/`

- `ProbeAPI.swift`
  - NSXPC exported protocols (`ProbeServiceProtocol`, `QuarantineLabProtocol`)
  - Codable request/response types (JSON-over-`Data`) used by both clients and services
- `InProcessProbeCore.swift`
  - The in-process probe implementations (dispatched by `probe_id`)
  - The safety gates around potentially destructive filesystem operations
  - Stable `ej_*` trace marker symbols used by external tooling
- `client/main.swift` → builds the embedded `xpc-probe-client`
- `quarantine-client/main.swift` → builds the embedded `xpc-quarantine-client`
- `QuarantineLabServiceHost.swift`
  - Shared Quarantine Lab service implementation (identical behavior across `QuarantineLab_*`)
- `services/<ServiceName>/…`
  - One directory per XPC service target: `Info.plist`, `Entitlements.plist`, `main.swift`

## How it builds into `EntitlementJail.app`

`xpc/` is built and embedded by [build.sh](../build.sh) when `BUILD_XPC=1` (default).

The build script finds `swiftc` via `xcrun` (Xcode Command Line Tools are required).

Note: `xcrun dyld_info` (not `dyldinfo`) is the tool for dyld cache inspection on this host.

### Outputs (bundle layout contract)

The build script produces:

- `EntitlementJail.app/Contents/MacOS/xpc-probe-client`
- `EntitlementJail.app/Contents/MacOS/xpc-quarantine-client`
- `EntitlementJail.app/Contents/XPCServices/<ServiceName>.xpc`
  - `…/<ServiceName>.xpc/Contents/MacOS/<ServiceName>` (the service executable)

The client helpers must live under `Contents/MacOS` so `Bundle.main` resolves to `EntitlementJail.app` (XPC lookup and path resolution depend on having the correct bundle context).

### What `build.sh` assumes about services

Service discovery/embedding is directory-driven:

- Every directory under `xpc/services/*` is treated as a service named `<ServiceName>`.
- The service bundle is written to `Contents/XPCServices/<ServiceName>.xpc`.
- The service executable is named exactly `<ServiceName>` and is placed at `…/<ServiceName>.xpc/Contents/MacOS/<ServiceName>`.
- Each service directory must contain: `Info.plist`, `Entitlements.plist`, `main.swift`.

If you change naming/layout here, you also need to update the build script, Evidence generation, and any docs/tests that assume the bundle layout.

Build composition is shared-source based:

- Client helpers are compiled from `ProbeAPI.swift` + their `main.swift`.
- Probe services (`ProbeService_*`) are compiled from:
  - `ProbeAPI.swift`
  - `InProcessProbeCore.swift`
  - `ProbeServiceSessionHost.swift`
  - `services/<ServiceName>/main.swift`
- Quarantine Lab services (`QuarantineLab_*`) are compiled from:
  - `ProbeAPI.swift`
  - `QuarantineLabServiceHost.swift`
  - `services/<ServiceName>/main.swift`

### Signing (what matters for XPC work)

- Each XPC service is signed with the entitlements in its own `xpc/services/<ServiceName>/Entitlements.plist`.
- Signing is “inside-out”: sign nested code first (clients/services/tools), then sign the outer `.app` last.

All signing procedure lives in [SIGNING.md](../SIGNING.md).

### Useful build knobs while iterating

`build.sh` respects:

- `EJ_INSPECTION=1` (default): builds Swift with `-Onone -g` and Rust with frame pointers + debuginfo (easier to inspect).
- `SWIFT_MODULE_CACHE` (default `./.tmp/swift-module-cache`): should be writable even in sandboxed harnesses.
- `SWIFT_OPT_LEVEL`, `SWIFT_DEBUG_FLAGS`: forwarded to `swiftc`.

## Runtime wiring (who talks to whom)

- `EntitlementJail.app/Contents/MacOS/entitlement-jail` (Rust launcher) does not speak NSXPC directly.
- For `entitlement-jail xpc {run,session}` / `quarantine-lab`, it invokes the embedded Swift client helpers:
  - `xpc-probe-client` opens an `NSXPCConnection(serviceName: <bundle-id>)` and calls `ProbeServiceProtocol`.
  - `xpc-quarantine-client` does the same for `QuarantineLabProtocol`.
- Services decode JSON request bytes, perform work, and reply with JSON response bytes.

CLI flag semantics and JSON envelope details are defined in [runner/README.md](../runner/README.md).

## Session mode (debug/attach)

EntitlementJail v2 uses **sessions** as the primary XPC surface for probes, so external tooling can attach deterministically without racing service startup.

Shape:

- Control plane: client → service (`ProbeServiceProtocol` session methods in `ProbeAPI.swift`)
- Event plane: service → client (`SessionEventSinkProtocol`, emitting JSON envelopes)

Where to look:

- Wire types/protocols: `xpc/ProbeAPI.swift`
- Service implementation: `xpc/ProbeServiceSessionHost.swift` (shared session host)
- Service entrypoints: `xpc/services/*/main.swift` (tiny; listener + delegate)
- Client implementation: `xpc/client/main.swift` (`xpc-probe-client session <bundle-id>`; JSONL stdin/stdout)
- Rust wrapper command: `runner/src/main.rs` (`entitlement-jail xpc session ...`)

## Targets in `xpc/services/` (three buckets)

The services fall into two service families (plus one “helper” bucket that is part of the XPC subsystem but not an XPC service).

### 1) Probe services (`ProbeService_*`)

All `ProbeService_*` targets are intended to share the *same* probe behavior. They should differ only in `Entitlements.plist`.

- `ProbeService_minimal` — App Sandbox only (baseline)
- `ProbeService_net_client` — `com.apple.security.network.client`
- `ProbeService_downloads_rw` — `com.apple.security.files.downloads.read-write`
- `ProbeService_user_selected_executable` — `com.apple.security.files.user-selected.executable`
- `ProbeService_bookmarks_app_scope` — `com.apple.security.files.bookmarks.app-scope` (scoped bookmarks agent access)
- `ProbeService_get-task-allow` — `com.apple.security.get-task-allow`
- `ProbeService_fully_injectable` — debugging/injection-friendly entitlement set (high concern; should require explicit acknowledgement via the repo’s risk gating)
- `ProbeService_fully_injectable_extensions` — `fully_injectable` + `com.apple.security.temporary-exception.sbpl` for `file-issue-extension` (high concern; extension issuance)

### 2) Quarantine Lab services (`QuarantineLab_*`)

These targets exist to observe quarantine/Gatekeeper-related metadata deltas without turning them into Seatbelt attribution claims. Like probe services, they should differ only in `Entitlements.plist`.

- `QuarantineLab_default` — App Sandbox only (baseline)
- `QuarantineLab_net_client` — `com.apple.security.network.client`
- `QuarantineLab_downloads_rw` — `com.apple.security.files.downloads.read-write`
- `QuarantineLab_user_selected_executable` — `com.apple.security.files.user-selected.executable`
- `QuarantineLab_bookmarks_app_scope` — `com.apple.security.files.bookmarks.app-scope`

User-facing `quarantine-lab` workflows are documented in [EntitlementJail.md](../EntitlementJail.md).

If you modify Quarantine Lab behavior, apply the same change across the whole `QuarantineLab_*` family so entitlements remain the primary variable.

### 3) Embedded client helpers (built from `xpc/`)

These are not XPC services, but they are part of the XPC subsystem and are required for the Rust launcher’s XPC commands.

- `xpc-probe-client` (from `xpc/client/main.swift`): wraps NSXPC calls, prints JSON envelopes to stdout, exits with the probe `rc` in one-shot mode.
- `xpc-quarantine-client` (from `xpc/quarantine-client/main.swift`): wraps NSXPC calls for Quarantine Lab, prints a JSON envelope, exits with the lab `rc`.

## Probe execution model (what a ProbeService is allowed to do)

Probe services are *not* a generic “run arbitrary code/path” facility. The constraints are intentional and are part of the research design.

- The caller provides a `probe_id` (an identifier), not a path to execute.
- Services should reject empty ids and any id containing path separators.
- Probes run **in-process** inside the XPC service (no staging into containers, no `exec by path`).
- Filesystem probes are safe-by-default: potentially destructive direct-path operations are gated to harness paths unless explicitly overridden.

The reference dispatch and safety gates live in `InProcessProbeCore.swift`.

## Sandbox extension probe (dev note)

The `sandbox_extension` probe’s consume/release path is intentionally defensive:

- When `--call-symbol` is not set, it auto-tries the common symbols (`sandbox_extension_consume`, `sandbox_consume_extension`, `sandbox_consume_fs_extension`, and `sandbox_release_fs_extension` when present) using conservative signature variants.
- The chosen symbol/variant and each attempt’s rc/errno are recorded in `details` (`call_symbol_selected`, `call_variant_selected`, `attempt_*`) so debugging tools can reproduce the exact path.
- dyld disassembly on this host indicates `sandbox_extension_release_file` and `sandbox_release_fs_extension` take only a token argument (single-arg); path/flags are not used.
- Wrapper/maintenance sub-ops map directly to SPI symbols: `issue_extension`, `issue_fs_extension`, `issue_fs_rw_extension`, `update_file` (path + flags), and `update_file_by_fileid` (token + file id + flags; some hosts expect a fileid pointer, see `--call-variant fileid_ptr_token`, or a selector value via `--call-variant payload_ptr_selector --selector <u64>`).
- Kernel disassembly on Sonoma 14.4.1 suggests `update_file_by_fileid` uses only the low 32 bits of an 8-byte payload (field0) as an internal id, treats field1 as a small selector (compared to 2), and requires field2 to be zero. This implies a plain fileid/token string may not be sufficient to make the call succeed without an internal handle.
- For a clean “denied → allowed” witness, use a world-readable file that App Sandbox blocks by default (for example `/private/var/db/launchd.db/com.apple.launchd/overrides.plist`). On Sonoma, `/etc/hosts` is often already readable and won’t show a before/after change.
- `issue_file` now exposes `token_fields_count` plus `token_field_8/9/10` (raw token fields) in `details`, and `update_file_by_fileid` includes `file_id_low32` and `file_id_stat_dev` when deriving ids from `--path`.
- `fs_op` supports `--no-cleanup` to keep harness artifacts (useful when testing rename/truncate + `update_file_by_fileid` flows).

If you need to pin behavior for ABI investigation, pass `--call-symbol` and `--call-variant` explicitly.

## Trace markers (`ej_*`)

Some probes call stable, C-callable marker functions such as `ej_probe_fs_op`. These symbols exist in the service Mach‑O and make it easy for external tools to locate probe boundaries.

The probe catalog includes a `trace_symbols` mapping; see [runner/README.md](../runner/README.md) / [EntitlementJail.md](../EntitlementJail.md) for how to request it.

## Adding a new XPC service (development workflow)

This repo’s preferred way to vary entitlements is “add a new `.xpc` target”.

See [CONTRIBUTING.md](../CONTRIBUTING.md#toy-example-adding-a-new-xpc-service) for a concrete, copy/paste “toy example” of adding a service.

Checklist for new services:

1. Create `xpc/services/<ServiceName>/` containing:
   - `Info.plist` (unique `CFBundleIdentifier`, and `CFBundleExecutable == <ServiceName>`)
   - `Entitlements.plist` (start from App Sandbox; add only the variable you want to study)
   - `main.swift` (keep it small; implement a protocol from `ProbeAPI.swift`)
2. Keep behavior identical across services in the same family:
   - If this is a new ProbeService variant, don’t fork probe logic in the wrapper — keep the change in entitlements.
3. Rebuild with signing (`make build`), so Evidence (`profiles.json`, entitlements extraction) stays accurate.
4. If you introduce “high concern” entitlements, update the risk classifier in [`tests/build-evidence.py`](../tests/build-evidence.py) so the CLI’s risk gating remains correct.
