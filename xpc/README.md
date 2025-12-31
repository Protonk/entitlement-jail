# `xpc/` (Swift XPC subsystem: build + targets)

This is developer documentation for the Swift code under `xpc/`: the shared XPC wire types, the embedded XPC client helpers, and the XPC services that act as the repo’s “entitlements as a variable” targets.

This document is intentionally build/implementation-focused and avoids duplicating CLI flag documentation.

For usage/behavior contracts, see:

- User guide: [PolicyWitness.md](../PolicyWitness.md)
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
  - Stable `pw_*` trace marker symbols used by external tooling
- `client/main.swift` → builds the embedded `xpc-probe-client`
- `quarantine-client/main.swift` → builds the embedded `xpc-quarantine-client`
- `QuarantineLabServiceHost.swift`
  - Shared Quarantine Lab service implementation (identical behavior across `QuarantineLab_*`)
- `services/<ServiceName>/…`
  - One directory per XPC service target: `Info.plist`, `Entitlements.plist`, `main.swift`
- `entitlements_overlays/injectable.plist`
  - Canonical entitlement overlay for generating injectable twins at build time

## How it builds into `PolicyWitness.app`

`xpc/` is built and embedded by [build.sh](../build.sh) when `BUILD_XPC=1` (default).

The build script finds `swiftc` via `xcrun` (Xcode Command Line Tools are required).

Note: `xcrun dyld_info` (not `dyldinfo`) is the tool for dyld cache inspection on this host.

### Outputs (bundle layout contract)

The build script produces:

- `PolicyWitness.app/Contents/MacOS/xpc-probe-client`
- `PolicyWitness.app/Contents/MacOS/xpc-quarantine-client`
- `PolicyWitness.app/Contents/MacOS/pw-inherit-child`
- `PolicyWitness.app/Contents/MacOS/pw-inherit-child-bad`
- `PolicyWitness.app/Contents/XPCServices/<ServiceName>.xpc`
  - `…/<ServiceName>.xpc/Contents/MacOS/<ServiceName>` (the service executable)
  - `…/ProbeService_*/Contents/MacOS/pw-inherit-child` (embedded child helper for `inherit_child`)
  - `…/ProbeService_*/Contents/MacOS/pw-inherit-child-bad` (embedded bad helper for `inherit_bad_entitlements`)

The client helpers must live under `Contents/MacOS` so `Bundle.main` resolves to `PolicyWitness.app` (XPC lookup and path resolution depend on having the correct bundle context).

### What `build.sh` assumes about services

Service discovery/embedding is directory-driven:

- Every directory under `xpc/services/*` is treated as a service named `<ServiceName>`.
- The service bundle is written to `Contents/XPCServices/<ServiceName>.xpc`.
- The service executable is named exactly `<ServiceName>` and is placed at `…/<ServiceName>.xpc/Contents/MacOS/<ServiceName>`.
- Each service directory must contain: `Info.plist`, `Entitlements.plist`, `main.swift`.

Injectable twins are generated during the build:

- For each base service bundle, a sibling `__injectable` bundle is synthesized.
- The twin’s entitlements are the base entitlements plus the fixed overlay in `entitlements_overlays/injectable.plist`.
- Twins have distinct executables and bundle identifiers (suffix `__injectable` and `.injectable`).

If you change naming/layout here, you also need to update the build script, Evidence generation, and any docs/tests that assume the bundle layout.

Build composition is shared-source based:

- Client helpers are compiled from `ProbeAPI.swift` + their `main.swift`.
- `pw-inherit-child` is compiled from `ProbeAPI.swift` + `xpc/child/main.swift`.
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

- `PW_INSPECTION=1` (default): builds Swift with `-Onone -g` and Rust with frame pointers + debuginfo (easier to inspect).
- `SWIFT_MODULE_CACHE` (default `./.tmp/swift-module-cache`): should be writable even in sandboxed harnesses.
- `SWIFT_OPT_LEVEL`, `SWIFT_DEBUG_FLAGS`: forwarded to `swiftc`.

## Runtime wiring (who talks to whom)

- `PolicyWitness.app/Contents/MacOS/policy-witness` (Rust launcher) does not speak NSXPC directly.
- For `policy-witness xpc {run,session}` / `quarantine-lab`, it invokes the embedded Swift client helpers:
  - `xpc-probe-client` opens an `NSXPCConnection(serviceName: <bundle-id>)` and calls `ProbeServiceProtocol`.
  - `xpc-quarantine-client` does the same for `QuarantineLabProtocol`.
- Services decode JSON request bytes, perform work, and reply with JSON response bytes.

CLI flag semantics and JSON envelope details are defined in [runner/README.md](../runner/README.md).

## Session mode (debug/attach)

PolicyWitness uses **sessions** as the primary XPC surface for probes, so external tooling can attach deterministically without racing service startup.

Shape:

- Control plane: client → service (`ProbeServiceProtocol` session methods in `ProbeAPI.swift`)
- Event plane: service → client (`SessionEventSinkProtocol`, emitting JSON envelopes)

Where to look:

- Wire types/protocols: `xpc/ProbeAPI.swift`
- Service implementation: `xpc/ProbeServiceSessionHost.swift` (shared session host)
- Service entrypoints: `xpc/services/*/main.swift` (tiny; listener + delegate)
- Client implementation: `xpc/client/main.swift` (`xpc-probe-client session <bundle-id>`; JSONL stdin/stdout)
- Rust wrapper command: `runner/src/main.rs` (`policy-witness xpc session ...`)

## Targets in `xpc/services/` (three buckets)

The services fall into two service families (plus one “helper” bucket that is part of the XPC subsystem but not an XPC service).

### 1) Probe services (`ProbeService_*`)

All `ProbeService_*` targets are intended to share the *same* probe behavior. They should differ only in `Entitlements.plist`.

- `ProbeService_minimal` — App Sandbox only (baseline)
- `ProbeService_net_client` — `com.apple.security.network.client`
- `ProbeService_downloads_rw` — `com.apple.security.files.downloads.read-write`
- `ProbeService_user_selected_executable` — `com.apple.security.files.user-selected.executable`
- `ProbeService_bookmarks_app_scope` — `com.apple.security.files.bookmarks.app-scope` (scoped bookmarks agent access)
- `ProbeService_temporary_exception` — `com.apple.security.temporary-exception.sbpl` for `file-issue-extension` (high concern; extension issuance)

Each base probe service gets an automatically generated injectable twin at build time (bundle suffix `__injectable`).

Important bookmark constraint (easy to misdiagnose):

- Security-scoped bookmark behavior is not “just an entitlement toggle”; it is also sensitive to code identity.
- In practice for this repo: treat bookmark tokens as scoped to the creating service identity (bundle id / team id). If you create a bookmark under one profile/service and try to resolve it under another, resolution may fail in ways that look like missing entitlements (often involving ScopedBookmarksAgent).
- `inherit_child --scenario bookmark_ferry` is designed to avoid this trap by ensuring the spawned child helper shares the service identity (see `build.sh` / `SIGNING.md` notes about signing per-service helper copies with `--identifier <service bundle id>`).

### 2) Quarantine Lab services (`QuarantineLab_*`)

These targets exist to observe quarantine/Gatekeeper-related metadata deltas without turning them into Seatbelt attribution claims. Like probe services, they should differ only in `Entitlements.plist`.

- `QuarantineLab_default` — App Sandbox only (baseline)
- `QuarantineLab_downloads_rw` — `com.apple.security.files.downloads.read-write`
- `QuarantineLab_user_selected_executable` — `com.apple.security.files.user-selected.executable`

User-facing `quarantine-lab` workflows are documented in [PolicyWitness.md](../PolicyWitness.md).

If you modify Quarantine Lab behavior, apply the same change across the whole `QuarantineLab_*` family so entitlements remain the primary variable.

### 3) Embedded client helpers (built from `xpc/`)

These are not XPC services, but they are part of the XPC subsystem and are required for the Rust launcher’s XPC commands.

- `xpc-probe-client` (from `xpc/client/main.swift`): wraps NSXPC calls, prints JSON envelopes to stdout, exits with the probe `rc` in one-shot mode.
- `xpc-quarantine-client` (from `xpc/quarantine-client/main.swift`): wraps NSXPC calls for Quarantine Lab, prints a JSON envelope, exits with the lab `rc`.
- `pw-inherit-child` (from `xpc/child/main.swift`): sandbox-inheriting child helper used by the `inherit_child` probe (paired-process harness).

## Probe execution model (what a ProbeService is allowed to do)

Probe services are *not* a generic “run arbitrary code/path” facility. The constraints are intentional and are part of the research design.

- The caller provides a `probe_id` (an identifier), not a path to execute.
- Services should reject empty ids and any id containing path separators.
- Probes run **in-process** inside the XPC service (no staging into containers, no `exec by path`).
- Filesystem probes are safe-by-default: potentially destructive direct-path operations are gated to harness paths unless explicitly overridden.
- Durable sessions (`xpc session`) keep the service alive so multi-phase transcripts remain in the same process context; otherwise “liveness” and maintenance semantics degrade into fresh-start behavior.

The reference dispatch and safety gates live in `InProcessProbeCore.swift`.

## Sandbox extension probe (dev note)

The `sandbox_extension` probe’s consume/release path is intentionally defensive:

- When `--call-symbol` is not set, it auto-tries the common symbols (`sandbox_extension_consume`, `sandbox_consume_extension`, `sandbox_consume_fs_extension`, and `sandbox_release_fs_extension` when present) using conservative signature variants.
- The chosen symbol/variant and each attempt’s rc/errno are recorded in `details` (`call_symbol_selected`, `call_variant_selected`, `attempt_*`) so debugging tools can reproduce the exact path.
- dyld disassembly on this host indicates `sandbox_extension_release_file` and `sandbox_release_fs_extension` take only a token argument (single-arg); path/flags are not used.
- Wrapper/maintenance sub-ops map directly to SPI symbols: `issue_extension`, `issue_fs_extension`, `issue_fs_rw_extension`, `update_file` (path + flags), and `update_file_by_fileid` (token + file id + flags; some hosts expect a fileid pointer, see `--call-variant fileid_ptr_token`, or a selector value via `--call-variant payload_ptr_selector --selector <u64>`).
- Kernel disassembly on Sonoma 14.4.1 suggests `update_file_by_fileid` uses only the low 32 bits of an 8-byte payload (field0) as an internal id, treats field1 as a small selector (compared to 2), and requires field2 to be zero. This implies a plain fileid/token string may not be sufficient to make the call succeed without an internal handle.
- `update_file_rename_delta` is a “semantics harness” op: it defines success as an **access delta** (not `rc==0`) across an inode-preserving rename. It records pre/post `open()` outcomes for `--path`/`--new-path`, enforces `rename_was_inode_preserving`, and runs a stable `update_file_by_fileid` candidate sweep (including consume-handle-derived candidates) with per-candidate `*_attempt_index` and `*_changed_access` fields.
- It also encodes “rename can silently change meaning”: issue+consume can flip `open_read` from `EPERM` to allow in the same process context, but the grant remains path-scoped (inode-preserving rename does not transfer access to the new path) until `update_file(new_path)` retargets it.
- `update_file_by_fileid` may return `rc==0` with no access delta, so the probe’s post-call `open_read` checks and `*_changed_access` fields are the evidence (not return codes).
- When `--wait-for-external-rename` is used, full stat snapshots and wait/poll observations are recorded so the host-side choreography is reproducible.
- For a clean “denied → allowed” witness, use a world-readable file that App Sandbox blocks by default (for example `/private/var/db/launchd.db/com.apple.launchd/overrides.plist`). On Sonoma, `/etc/hosts` is often already readable and won’t show a before/after change.
- `issue_file` exposes `token_fields_count` plus `token_field_8/9/10` (raw token fields) in `details`, and `update_file_by_fileid` includes `file_id_low32` and `file_id_stat_dev` when deriving ids from `--path`.
- `fs_op` supports `--no-cleanup` to keep harness artifacts (useful when testing rename/truncate + `update_file_by_fileid` flows).

If you need to pin behavior for ABI investigation, pass `--call-symbol` and `--call-variant` explicitly.

## Trace markers (`pw_*`)

Some probes call stable, C-callable marker functions such as `pw_probe_fs_op`. These symbols exist in the service Mach‑O and make it easy for external tools to locate probe boundaries.

The probe catalog includes a `trace_symbols` mapping; see [runner/README.md](../runner/README.md) / [PolicyWitness.md](../PolicyWitness.md) for how to request it.

## `inherit_child` (paired-process harness: frozen two-bus protocol)

`inherit_child` is the “capability ferry” harness: a probe that spawns a sandbox-inheriting child process and compares **acquire** vs **use** across a cooperative parent/child lineage.

Key property: it uses **two distinct transport channels**, and that split is a contract surface:

- **Event bus** — ordered JSONL events (human-readable narrative) plus parent→child byte payloads (bookmark bytes).
- **Rights bus** — a dedicated Unix-domain socket for `SCM_RIGHTS` FD passing (file/dir/socket capabilities). No FDs are ever passed over the event bus.

The single source of truth for protocol constants, framing, and witness schema is `xpc/ProbeAPI.swift`:

- `InheritChildProtocol` (protocol version + framing rules)
- `InheritChildCapabilityId` (cap id namespace)
- `InheritChildWitness` / `InheritChildEvent` / `InheritChildProtocolError` (what must be recorded)

### Transport contracts (how to reason about failures)

**Event bus framing**

- Child→parent: JSONL events plus one sentinel line:
  - Prefix: `PW_CHILD_SENTINEL`
  - Includes at least: `protocol_version=<v>` and `cap_namespace=<ns>`
- Parent→child payloads (for byte capabilities like bookmarks):
  - 1 header line: `PW_CAP_PAYLOAD proto=<v> cap_ns=<ns> cap_id=<id> cap_type=<type> len=<n>`
  - followed by exactly `<n>` raw bytes.

**Rights bus framing**

- Parent→child: one `sendmsg()` per capability with:
  - `SCM_RIGHTS` containing the FD, and
  - a 16-byte header of four `int32` values: `cap_id, meta0, meta1, meta2`
    - `meta0` is the protocol version; `meta1/meta2` are reserved (0).

Protocol mismatches and ordering violations are treated as **protocol bugs**, not “sandbox behavior”:

- The child verifies protocol version/namespace from env + framing fields.
- Unexpected `cap_id`, missing `SCM_RIGHTS`, or unexpected message ordering is emitted as a single early `child_capability_recv_failed` event and exits nonzero.
- The parent maps these to distinct normalized outcomes (`child_protocol_violation`, `child_rights_bus_io_error`, `child_event_bus_io_error`) and records a structured `protocol_error` in the witness.

### Scenario routing and the capability matrix

`inherit_child` is scenario-routed: `--scenario <name>` selects a list of capability tests rather than a bespoke monolith.

Scenario names are a contract surface (smoke + fixtures depend on them). The catalog is centralized in the probe implementation (`InProcessProbeCore.swift`) and should be updated as a single source of truth.

Outputs:

- `witness.events[]` — narrative timeline (sentinel, lifecycle phases, attempts, stop markers)
- `witness.capability_results[]` — matrix rows with explicit acquire/use rc/errno (plus capability-specific fields like bookmark resolution/startAccessing/access attempts)
- `witness.outcome_summary` — deterministic per-capability deltas (good for scanning without reading raw events)

Ordering invariants (enforced by smoke + fixtures):

- `child_ready` appears before any `child_*_attempt` event.
- For each capability, the child emits an acquire attempt before a use attempt (no “use before acquire” races).

### Witness invariants (don’t regress debuggability)

For every `inherit_child` run — including early failures and child non-emission cases — the witness is expected to be present and to include at least:

- Protocol: `schema_version`, `protocol_version`, `capability_namespace`
- Identity: `run_id`, `scenario`, `service_bundle_id`, `process_name`
- Child: `child_pid`, `child_exit_status`, `child_path`, `child_bundle_id`, `child_team_id`
- Inheritance contract: `child_entitlements`, `inherit_contract_ok`
- Transports: `child_event_fd`, `child_rights_fd` (should match the child sentinel line)
- Logs: `sandbox_log_capture_status` (`not_requested|requested_unavailable|captured`) and `sandbox_log_capture` (string map)

When the failure is a protocol-level bug, the witness also carries `protocol_error` (structured) so it can’t be misdiagnosed as sandbox behavior.
When there are no child-emitted events, treat it as “child died before writing” (diagnostic), not as a sandbox deny.

### Stop markers (inspection-first)

`inherit_child` supports “stop points that matter”:

- `--stop-on-entry` — child raises `SIGSTOP` ultra-early (deterministic attach point).
- `--stop-on-deny` — on `EPERM`/`EACCES` shaped failures, emit the denying op + `callsite_id` + best-effort backtrace, then stop.

Backtraces are best-effort and must never be fatal; failures are recorded as `backtrace_error` rather than aborting the run.

### Signing/entitlements invariants (child helpers)

The child helpers are part of the “inheritance contract” surface:

- `pw-inherit-child` (good) must have **only**:
  - `com.apple.security.app-sandbox=true`
  - `com.apple.security.inherit=true`
- `pw-inherit-child-bad` (canary) intentionally violates the contract by including an additional App Sandbox entitlement (for example `com.apple.security.files.user-selected.read-only=true`) so the OS predictably aborts it. This is used by the `inherit_bad_entitlements` scenario as a regression tripwire for signing/twinning changes.

Correctness constraints enforced by the build + tests:

- The build signs the per-service embedded helper copies with the service bundle identifier (`codesign --identifier <service bundle id> ...`) so security-scoped bookmark behavior is stable and attributable to the correct identity.
- `tests/build-evidence.py` verifies child helper entitlements (good/bad) for the app-level copy and the per-service embedded copies (including injectable twins).

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

##  `allow-jit` vs `allow-unsigned-executable-memory` on Apple Silicon

On Apple Silicon, `com.apple.security.cs.allow-unsigned-executable-memory` offers a superset of the privileges of `com.apple.security.cs.allow-jit`, so carrying both is usually redundant: [apple-developer-forums](https://developer.apple.com/forums/thread/776290)
