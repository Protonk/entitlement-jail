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

`RunProbeResponse` carries correlation metadata (for example `correlation_id`, `probe_id`, `argv`), service identity/build fields, and timing/thread hints (`started_at_iso8601`, `ended_at_iso8601`, `thread_id`) when available. The XPC client wraps responses in the uniform JSON envelope described in `runner/README.md` and may annotate `log_capture_status` when `--log-sandbox` is used.

`RunProbeRequest` supports an optional `wait_spec` block to block **before** probe execution (used by `run-xpc --wait-*` / `--attach`).

### Client helpers (why the main binary delegates)

The sandboxed Rust launcher does not speak NSXPC directly. Instead it runs embedded Swift helper executables:

- `xpc/client/main.swift` → builds `Contents/MacOS/xpc-probe-client` (must live under `Contents/MacOS` so `Bundle.main` resolves to `EntitlementJail.app`)
- `xpc/quarantine-client/main.swift` → builds `Contents/MacOS/xpc-quarantine-client` (same reason)

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

- `ProbeService_minimal`: runs built-in probes **in-process** and returns `{rc, normalized_outcome, details, ...}`.
- `ProbeService_net_client`: identical code to `ProbeService_minimal`, but with `com.apple.security.network.client`.
- `ProbeService_downloads_rw`: identical code to `ProbeService_minimal`, but with `com.apple.security.files.downloads.read-write`.
- `ProbeService_user_selected_executable`: identical code to `ProbeService_minimal`, but with `com.apple.security.files.user-selected.executable`.
- `ProbeService_bookmarks_app_scope`: identical code to `ProbeService_minimal`, but with `com.apple.security.files.bookmarks.app-scope` (enables `mach-lookup` to `com.apple.scopedbookmarksagent.xpc`, used by security-scoped bookmark creation/resolution).
- `ProbeService_debuggable`: identical code to `ProbeService_minimal`, but with `com.apple.security.get-task-allow`.
- `ProbeService_plugin_host_relaxed`: identical code to `ProbeService_minimal`, but with `com.apple.security.cs.disable-library-validation`.
- `ProbeService_dyld_env_enabled`: identical code to `ProbeService_minimal`, but with `com.apple.security.cs.allow-dyld-environment-variables`.
- `ProbeService_fully_injectable`: identical code to `ProbeService_minimal`, but with `com.apple.security.get-task-allow` + `com.apple.security.cs.disable-library-validation` + `com.apple.security.cs.allow-dyld-environment-variables` + `com.apple.security.cs.allow-jit` + `com.apple.security.cs.allow-unsigned-executable-memory`.
- `ProbeService_jit_map_jit`: identical code to `ProbeService_minimal`, but with `com.apple.security.cs.allow-jit`.
- `ProbeService_jit_rwx_legacy`: identical code to `ProbeService_minimal`, but with `com.apple.security.cs.allow-unsigned-executable-memory`.
- `QuarantineLab_default`: writes/opens/copies artifacts and reports `com.apple.quarantine` deltas.
- `QuarantineLab_net_client`: identical code to `QuarantineLab_default`, but with `com.apple.security.network.client`.
- `QuarantineLab_downloads_rw`: identical code to `QuarantineLab_default`, but with `com.apple.security.files.downloads.read-write`.
- `QuarantineLab_user_selected_executable`: identical code to `QuarantineLab_default`, but with different entitlements.
- `QuarantineLab_bookmarks_app_scope`: identical code to `QuarantineLab_default`, but with `com.apple.security.files.bookmarks.app-scope`.

Built-in probe ids (in-process):

- `probe_catalog`
- `world_shape`
- `network_tcp_connect` (`--host <ipv4> --port <1..65535>`)
- `downloads_rw` (`[--name <file-name>]`)
- `fs_op` (parameterized filesystem op; see `--op` help in `experiments/bin/witness-substrate`)
- `fs_op_wait` (fs_op with a wait trigger; see `--wait-fifo`/`--wait-exists` help in `experiments/bin/witness-substrate`)
- `net_op` (parameterized network op; see `--op` help in `experiments/bin/witness-substrate`)
- `dlopen_external` (`--path <abs>` or `EJ_DLOPEN_PATH`)
- `jit_map_jit` (`[--size <bytes>]`)
- `jit_rwx_legacy` (`[--size <bytes>]`)
- `bookmark_op` (filesystem op gated by an input bookmark token)
- `bookmark_make` (best-effort bookmark generator; security-scoped bookmark creation requires ScopedBookmarksAgent IPC, which is denied unless the target has bookmarks or user-selected read-only/read-write entitlements)
- `bookmark_roundtrip` (make + resolve + run a bookmark-scoped fs op in one call)
- `capabilities_snapshot` (observer: entitlements + resolved standard directories)
- `userdefaults_op` (UserDefaults read/write/remove + inferred prefs path)
- `fs_xattr` (get/list/set/remove xattrs; xattr writes are refused outside harness paths unless explicitly allowed)
- `fs_coordinated_op` (NSFileCoordinator mediated read/write; best-effort and environment-dependent)

Notes:

- `probe_catalog` outputs a JSON catalog in `result.stdout`; use `<probe-id> --help` for per-probe usage (help text is returned in JSON `result.stdout`).
- `probe_catalog` includes `trace_symbols`, mapping probe ids to stable `ej_*` marker symbols for external tooling.
- `dlopen_external` executes dylib initializers; treat it as code execution.
- `run-xpc` supports pre-run waits for attach workflows (`--wait-fifo`/`--wait-exists` or `--attach <seconds>`); wait metadata is recorded in `data.details` (`wait_*` keys).
- When a wait is configured, the client emits a `wait-ready` line to stderr with the resolved wait path.
- `--wait-create` tells the service to create the FIFO path before waiting (only valid with `--wait-fifo`).

## Trace markers (`ej_*`)

Key probes call stable, C-callable marker functions such as `ej_probe_fs_op` and `ej_probe_dlopen_external`. These symbols are present in the XPC service Mach‑O and are invoked at the start of probe execution, making them easy targets for `dtrace`, `frida`, and `otool`.

Use `probe_catalog` to discover the symbol name for a given probe id (`trace_symbols`).

## Inspection-friendly builds

Inspection-friendly builds are the default (symbols + frame pointers + reduced Swift optimization). Set `EJ_INSPECTION=0` to build an optimized release. This does not change entitlements or runtime behavior, only build flags.

## Safe probe resolution (no traversal, no container staging)

XPC services that act as entitlement research targets must not accept arbitrary filesystem paths for execution.

The reference policy in `ProbeService_*/main.swift` is:

- The caller passes a `probe_id` that is treated as an *identifier*, not a path.
- The service rejects empty ids and any id containing `/` or `\\` patterns.
- The service dispatches to a built-in, in-process probe implementation (no external exec).

This is deliberate: it prevents path traversal and avoids reintroducing “stage into container then exec by path” patterns that are commonly blocked (and are easy to misattribute as “sandbox denied” without evidence).

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
- `QuarantineLab_net_client`: App Sandbox + `com.apple.security.network.client`.
- `QuarantineLab_downloads_rw`: App Sandbox + `com.apple.security.files.downloads.read-write`.
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
