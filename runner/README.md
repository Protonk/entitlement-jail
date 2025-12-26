# `runner/` (Rust CLI launcher: behavior + contracts)

This is developer documentation for the Rust code in `runner/`. It builds the command-line launcher that ships as:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail`

This document exists so people working on the CLI can debug breakage without spelunking a user guide. It complements (and links to) the user-facing docs, but it still treats behavior as a contract: if you change the CLI, update this doc.

Related docs:

- User guide / workflows: [EntitlementJail.md](../EntitlementJail.md)
- XPC build + service layout: [xpc/README.md](../xpc/README.md)
- Signing/build procedure: [SIGNING.md](../SIGNING.md)
- Contributing/build tour: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Tri-run experiment harness: [experiments/README.md](../experiments/README.md)

## What lives in `runner/`

Core files:

- [src/main.rs](src/main.rs) — subcommand parsing, policy boundaries, risk gating, evidence/profiles commands
- [src/json_contract.rs](src/json_contract.rs) — JSON envelope + lexicographic key ordering (output stability)
- [src/evidence.rs](src/evidence.rs) — Evidence manifest loading + hash verification helpers
- [src/profiles.rs](src/profiles.rs) — profile manifest loading + lookup helpers
- [src/debug_entitlements_probe.rs](src/debug_entitlements_probe.rs) — debug-only startup `dlopen` probe (opt-in via env var)

CLI tests:

- [tests/cli_integration.rs](tests/cli_integration.rs) — integration tests against a built `EntitlementJail.app` (or `EJ_BIN_PATH`)

This crate also builds standalone helper CLIs:

- [src/bin/quarantine-observer.rs](src/bin/quarantine-observer.rs) → `quarantine-observer` (outside the sandbox boundary)
- [src/bin/sandbox-log-observer.rs](src/bin/sandbox-log-observer.rs) → `sandbox-log-observer` (also embedded into the `.app`)
- [src/bin/ej-inspector.rs](src/bin/ej-inspector.rs) → `ej-inspector` (debugger-side only)

## How it builds into `EntitlementJail.app`

The build is centralized in [build-macos.sh](../build-macos.sh) (invoked by `make build`).

Key wiring:

- `cargo build --manifest-path runner/Cargo.toml --release --bin runner` produces `runner/target/release/runner`.
- The build script copies that binary to `EntitlementJail.app/Contents/MacOS/entitlement-jail`.
- The build script also embeds `runner/target/release/sandbox-log-observer` as `EntitlementJail.app/Contents/MacOS/sandbox-log-observer`.
- Evidence manifests are generated during the build by [`tests/build-evidence.py`](../tests/build-evidence.py) and embedded under `EntitlementJail.app/Contents/Resources/Evidence/`.

If you change bundle paths, add embedded executables, or change how services are enumerated/signed, expect to touch both [build-macos.sh](../build-macos.sh) and [`tests/build-evidence.py`](../tests/build-evidence.py), plus the docs that describe the resulting bundle layout.

## Design invariants (don’t casually break these)

### No arbitrary path execution

The launcher intentionally does **not** provide a “run arbitrary staged Mach‑O by path” feature.

On stock macOS, sandboxed apps commonly hit `process-exec*` denials when trying to execute from writable/container locations. If this repo quietly allowed arbitrary exec-by-path, many failures would become uninterpretable (and easy to misattribute).

Instead, the supported execution surfaces are:

- `run-system` — execute **in-place platform binaries** from allowlisted prefixes
- `run-embedded` — execute **bundle-embedded** helper tools (inheritance demo surface)
- `run-xpc` — delegate to **launchd-managed XPC services** (preferred; entitlements are the variable)
- `quarantine-lab` — write/open artifacts and report quarantine metadata deltas (**no execution**)

### XPC commands are wrappers + gates

The Rust launcher does not speak NSXPC directly.

- `run-xpc` delegates to the embedded Swift client `xpc-probe-client` and primarily acts as:
  - an argument router (finds the service id / profile id position),
  - a risk gate (`--ack-risk` enforcement),
  - a wrapper that preserves stdout/stderr and exits like the child process.
- `quarantine-lab` delegates to the embedded Swift client `xpc-quarantine-client` with the same “wrapper” behavior.

Architecture details live in [xpc/README.md](../xpc/README.md).

### JSON output envelopes are stable and sorted

All JSON emitters in this repo (Rust and Swift) share a uniform top-level envelope and keep keys lexicographically sorted for stability.

If you add fields or change shapes, treat it as a contract change: update docs and any downstream tools/tests that consume the outputs.

### Risk tiers are derived (and enforced)

Risk tiers/warnings are not hand-curated in the Rust code.

- The build generates `Evidence/profiles.json` by extracting **signed** entitlements via `codesign` ([`tests/build-evidence.py`](../tests/build-evidence.py)).
- The launcher uses the `risk_tier` and `risk_reasons` fields in that manifest to:
  - warn on tier 1 profiles,
  - require explicit acknowledgement on tier 2 profiles (`--ack-risk`).

If you add a “high concern” entitlement, update the risk classifier so the tier stays honest.

## Finding and invoking the CLI

Shipped location:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail`

For user-friendly invocation patterns and workflows, see [EntitlementJail.md](../EntitlementJail.md). For CLI development, it’s still useful to keep the raw subcommand surface area in view:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-system <absolute-platform-binary> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-embedded <tool-name> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc [--ack-risk <id|bundle-id>] [--log-stream <path|auto|stdout>|--log-path-class <class> --log-name <name>] [--log-predicate <predicate>] [--observe] [--observer-duration <seconds>] [--observer-format <json|jsonl>] [--observer-output <path|auto>] [--observer-follow] [--attach-report <path|auto|stdout|stderr>] [--preload-dylib <abs>] [--preload-dylib-stage] [--json-out <path>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>] [--wait-fifo <path>|--wait-exists <path>|--wait-path-class <class> --wait-name <name>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create] [--attach <seconds>] [--hold-open <seconds>] [--xpc-timeout-ms <n>] (--profile <id> | <xpc-service-bundle-id>) <probe-id> [probe-args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail verify-evidence
./EntitlementJail.app/Contents/MacOS/entitlement-jail inspect-macho <service-id|main|path>
./EntitlementJail.app/Contents/MacOS/entitlement-jail list-profiles
./EntitlementJail.app/Contents/MacOS/entitlement-jail list-services
./EntitlementJail.app/Contents/MacOS/entitlement-jail show-profile <id>
./EntitlementJail.app/Contents/MacOS/entitlement-jail describe-service <id>
./EntitlementJail.app/Contents/MacOS/entitlement-jail health-check [--profile <id>]
./EntitlementJail.app/Contents/MacOS/entitlement-jail bundle-evidence [--out <dir>] [--include-health-check] [--ack-risk <id|bundle-id>]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-matrix --group <name> [--out <dir>] [--ack-risk <id|bundle-id>] <probe-id> [probe-args...]
```

## JSON output contract (envelope + kinds)

All JSON emitters in this repo (CLI outputs, XPC client outputs, and helper tools) share a uniform envelope:

```json
{
  "schema_version": 1,
  "kind": "probe_response",
  "generated_at_unix_ms": 1700000000000,
  "result": {
    "ok": true,
    "rc": 0,
    "exit_code": null,
    "normalized_outcome": "ok",
    "errno": null,
    "error": null,
    "stderr": "",
    "stdout": ""
  },
  "data": {}
}
```

Rules:

- Keys are lexicographically sorted for stability (see [src/json_contract.rs](src/json_contract.rs)).
- `result.rc` is used by probes/quarantine; `result.exit_code` is used by CLI/tools. Unused fields are `null`.
- All command-specific fields live under `data` (no extra top-level keys).

Envelope `kind` values used by the launcher and helpers:

- `probe_response`
- `quarantine_response`
- `verify_evidence_report`
- `inspect_macho_report`
- `profiles_report`
- `services_report`
- `profile_report`
- `describe_service_report`
- `health_check_report`
- `bundle_evidence_report`
- `run_matrix_report`
- `inspector_report`
- `quarantine_observer_report`
- `sandbox_log_observer_report`
- `sandbox_log_stream_report`

### Who emits JSON (and who doesn’t)

Not every subcommand prints JSON:

- **Pass-through exec (no JSON)**: `run-system`, `run-embedded` (exit like the child process)
- **Swift-emitted JSON**: `run-xpc`, `quarantine-lab` (wrapper to embedded Swift clients; exit like the client process)
- **Rust-emitted JSON**: `verify-evidence`, `inspect-macho`, `list-profiles`, `list-services`, `show-profile`, `describe-service`, `health-check`, `bundle-evidence`, `run-matrix`

## `run-system`: in-place platform binaries

`run-system` only executes **absolute** paths under these prefixes:

- `/bin`
- `/usr/bin`
- `/sbin`
- `/usr/sbin`
- `/usr/libexec`
- `/System/Library`

Rationale:

- These locations are “platform/in-place” and typically non-writable, which avoids the common sandbox failure mode of attempting to execute staged content from writable/container paths.
- The allowlist is a policy boundary: if a path is not obviously platform/in-place, use `run-embedded` or `run-xpc` instead of widening the definition ad hoc.

Behavior:

- Refuses non-absolute paths.
- Refuses absolute paths outside the allowlist.
- Verifies the target exists and has executable bits before spawning.
- Spawns the process and exits with the child’s exit status (stdout/stderr are not captured or rewrapped).

## `run-embedded`: bundle-embedded helpers

`run-embedded` runs an executable that is shipped *inside the app bundle*, by a simple tool name (a single path component).

Resolution rules:

- `tool-name` must be a single path component (no `/`, no `..`, no traversal).
- Search paths are relative to the `.app` bundle that contains `entitlement-jail`:
  - `EntitlementJail.app/Contents/Helpers/<tool-name>`
  - `EntitlementJail.app/Contents/Helpers/Probes/<tool-name>`

Signing note:

- In the default build, the launcher is plain-signed (unsandboxed host-side) and embedded helpers are signed plainly as well.
- If you produce a sandboxed-launcher build, embedded helpers must be signed for sandbox inheritance; follow [SIGNING.md](../SIGNING.md).

Behavior:

- Verifies the resolved target exists and is executable.
- Spawns it as a child process and exits with the child’s exit status.

Treat `run-embedded` as an inheritance demo surface only; use XPC services for entitlements-as-a-variable experiments.

## `run-xpc`: launchd-managed XPC services (preferred)

`run-xpc` is the main “entitlements vary cleanly” surface. It runs probes **in-process** inside launchd-managed XPC services, and it can optionally attach best-effort sandbox-deny evidence capture.

### Wiring (who does what)

- The Rust launcher delegates to the embedded Swift helper `xpc-probe-client` (under `Contents/MacOS`), which speaks NSXPC.
- The launcher performs risk gating (`--ack-risk`) based on `Evidence/profiles.json` before it executes the helper.
- The helper connects to an XPC service by bundle id and sends a JSON request `{probe_id, argv, ...}`.
- The XPC service executes the probe in-process and replies with JSON.

XPC architecture details (and why `xpc-probe-client` must live under `Contents/MacOS`) are documented in [xpc/README.md](../xpc/README.md).

### Service selection (`--profile` vs bundle id)

You can select the target service by:

- `--profile <id>` (preferred ergonomics; resolves via `Evidence/profiles.json`), or
- passing the explicit `<xpc-service-bundle-id>`.

If you use `--profile`, omit the explicit service bundle id.

### Risk gating (`--ack-risk`)

Tier model:

- Tier 0: baseline/access entitlements only (not gated)
- Tier 1: warn-only (some concern)
- Tier 2: requires explicit acknowledgement: `--ack-risk <profile-id|bundle-id>`

Tier assignment comes from `Evidence/profiles.json` (derived from signed entitlements during build).

### Built-in probe ids (in-process)

These probes are implemented in Swift (see [xpc/InProcessProbeCore.swift](../xpc/InProcessProbeCore.swift)) and run inside the XPC service process:

- Discovery/identity:
  - `probe_catalog`
  - `capabilities_snapshot`
  - `world_shape`
- Networking:
  - `net_op` (`--op <getaddrinfo|tcp_connect|udp_send> ...`)
  - `network_tcp_connect` (`--host <ipv4> --port <1..65535>`)
- Filesystem (safe-by-default; destructive direct-path ops are gated):
  - `downloads_rw`
  - `fs_op`
  - `fs_op_wait`
  - `fs_xattr`
  - `fs_coordinated_op`
  - `bookmark_op`, `bookmark_make`, `bookmark_roundtrip`
- User defaults:
  - `userdefaults_op`
- Instrumentation / intentional code execution:
  - `dlopen_external` (loads a dylib and executes initializers; supply `--path <abs>` or `EJ_DLOPEN_PATH`)
  - `sandbox_check` (calls `sandbox_check()` via `dlsym`, intended as a `libsystem_sandbox` hook/trace calibration point)
  - `jit_map_jit`
  - `jit_rwx_legacy`

Notes:

- `probe_catalog` returns a JSON catalog in `result.stdout`; use `<probe-id> --help` for probe-specific usage.
- The catalog includes a `trace_symbols` map, which ties probe ids to stable `ej_*` marker symbols.

### Log capture + deny evidence (`--log-stream` / `--observe`)

`run-xpc` supports best-effort capture of sandbox denial lines from unified logging. This is *evidence attachment*, not proof of causality.

Two mechanisms exist:

- `--log-stream ...` (live capture during the probe; uses `/usr/bin/log stream`)
- `--observe ...` (runs the unsandboxed observer tool; uses `log show` by default, or `log stream` when configured)

Important behavioral constraints:

- The observer is designed to run **outside** the sandbox boundary. If the launcher is sandboxed, log capture may fail.
- Absence of deny lines is not a denial claim: `deny_evidence=not_found` means “capture ran; no matching deny lines were observed.”
- Log capture output is a separate JSON report:
  - `sandbox_log_stream_report` for `--log-stream`
  - `sandbox_log_observer_report` for `--observe`

Output path controls:

- `--log-stream <path|auto|stdout>` controls where the stream report goes.
  - `stdout` requires `--json-out` for the probe JSON.
- `--log-path-class <class> --log-name <name>` chooses a container-safe output path for the stream report (useful when repo paths are blocked).
- Observer output goes to `--observer-output <path|auto>` and can be `json` or `jsonl` (`--observer-format`).

Response fields:

- `deny_evidence`: `not_captured`, `captured`, `not_found`, `log_error`
- `data.log_capture_*` and `data.log_observer_*` fields record status, predicates, and observed deny lines, plus an embedded observer report.

For user-oriented recipes and troubleshooting patterns, see the “Logging & Evidence” section in [EntitlementJail.md](../EntitlementJail.md).

### Pre-run waits and attach workflows (`--wait-*`, `--attach`, `--hold-open`)

`run-xpc` supports pre-run waits to make “attach a debugger/tracer before the probe runs” deterministic:

- `--wait-fifo <path>` / `--wait-exists <path>` block **before** probe execution.
- `--wait-path-class <class> --wait-name <name>` lets the service resolve a container path safely.
- `--wait-create` asks the service to create the FIFO before waiting (only valid with `--wait-fifo`).
- `--attach <seconds>` is a convenience mode: it selects a FIFO in the service container `tmp` and pairs it with a default hold-open.
- `--hold-open <seconds>` keeps the XPC connection alive after the response to make post-probe attachment easier.

When a wait is configured, the client prints a `wait-ready` line to stderr with the resolved wait path.

When attach/wait workflows are in use, the client also prints a `pid-ready` line. For automation, `--attach-report <path|auto|stdout|stderr>` emits machine-readable JSONL attach events (`wait_ready`, `pid_ready`) without parsing stderr.

For “load my own interposer” workflows, `--preload-dylib <abs>` asks the service to `dlopen()` a dylib before the probe runs, and `--preload-dylib-stage` stages the dylib into the service container `tmp` first (to avoid file-open sandbox denials).

### Output and ordering constraints

- `run-xpc` prints a `kind: probe_response` envelope to stdout and exits with `result.rc`.
- Log/observer/attach/instrumentation flags (`--log-*`, `--observe`, `--observer-*`, `--attach-report`, `--preload-dylib*`, `--json-out`) must appear **before** `<xpc-service-bundle-id>`.
- `--xpc-timeout-ms` sets a client-side timeout; on timeout, the client emits `normalized_outcome: xpc_error`.

## Profiles, services, and health checks

Profiles are short ids mapping to XPC services in the “process zoo”.

The authoritative inventory is `EntitlementJail.app/Contents/Resources/Evidence/profiles.json`, generated during build by [`tests/build-evidence.py`](../tests/build-evidence.py).

Commands:

- `list-profiles` (`kind: profiles_report`)
- `list-services` (`kind: services_report`)
- `show-profile <id>` (`kind: profile_report`)
- `describe-service <id>` (`kind: describe_service_report`; static entitlements-derived view)

`health-check` runs a small set of safe probes (currently `capabilities_snapshot`, `world_shape`, `fs_op --op stat --path-class tmp`) and emits `kind: health_check_report`.

## `run-matrix`: compare a probe across a service group

`run-matrix` runs the same probe across a predefined group and emits a compare table plus a JSON bundle.

Current groups:

- `baseline`: `minimal`
- `debug`: `minimal`, `get-task-allow`
- `inject`: `minimal`, `fully_injectable`

Default output path (overwritten each run):

```
~/Library/Application Support/entitlement-jail/matrix/<group>/latest
```

Notes:

- Tier 2 profiles in the group are skipped unless you pass `--ack-risk <id|bundle-id>`.
- If you run a sandboxed-launcher build, default output paths resolve under the container home; choose `--out` accordingly.

## `quarantine-lab`: write/open artifacts and report `com.apple.quarantine` (no execution)

`quarantine-lab` delegates to the embedded Swift helper `xpc-quarantine-client` plus an XPC service (for example `com.yourteam.entitlement-jail.QuarantineLab_default`).

Key contract:

- This mode **does not execute** specimens. It writes/opens/reads and reports quarantine metadata deltas.

High-level knobs:

- Payload classes: `shell_script`, `command_file`, `text`, `webarchive_like`
- Operations: `create_new` (default), `open_only`, `open_existing_save`
- Output dir: `tmp` or `app_support`
- Options: `--existing-path`, `--name`, `--exec/--no-exec`, `--selection` (annotation), `--test-case-id` (annotation)

For user workflows and interpretation guidance, see [EntitlementJail.md](../EntitlementJail.md).

## Unsandboxed observer: `quarantine-observer`

`quarantine-observer` is intended to be a clean witness that does not inherit the App Sandbox.

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release --bin quarantine-observer
```

Run:

```sh
runner/target/release/quarantine-observer <path> --assess
```

It:

- reads `com.apple.quarantine` (if present),
- records Gatekeeper status and (optionally) an assessment signal (observer-only; does not execute the file).

Do not run it from a sandboxed parent process.

## Unsandboxed observer: `sandbox-log-observer`

`sandbox-log-observer` is the standalone observer used by `run-xpc --observe`.

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release --bin sandbox-log-observer
```

Run:

```sh
runner/target/release/sandbox-log-observer --pid <pid> --process-name <name> --last 5s
runner/target/release/sandbox-log-observer --pid <pid> --process-name <name> --duration 5 --format jsonl --output /tmp/ej-observer.jsonl
```

It:

- runs `log show` by default (or `log stream` with `--duration`/`--follow`),
- emits a JSON envelope (`kind: sandbox_log_observer_report`),
- uses `data.observer_schema_version` for the observer report schema version (separate from the envelope schema).

In the distributed bundle it is embedded at:

- `EntitlementJail.app/Contents/MacOS/sandbox-log-observer`

Do not run it from a sandboxed parent process.

## Evidence (embedded manifests) + inspection commands

The app embeds evidence files under:

- `EntitlementJail.app/Contents/Resources/Evidence/manifest.json`
- `EntitlementJail.app/Contents/Resources/Evidence/symbols.json`
- `EntitlementJail.app/Contents/Resources/Evidence/profiles.json`

What they’re for:

- `manifest.json`: hashes/LC_UUIDs/entitlements for embedded helpers and XPC services (the manifest itself is covered by the app bundle signature; it intentionally omits the main binary hash to avoid self-referencing).
- `symbols.json`: exported `ej_*` probe markers per binary.
- `profiles.json`: profile ids, service bundle ids, entitlements, tags, and risk tier metadata.

Commands:

- `verify-evidence` (`kind: verify_evidence_report`)
- `inspect-macho <service-id|main|path>` (`kind: inspect_macho_report`)

`inspect-macho` selectors are intentionally flexible for debugging:

- A service bundle id (example: `com.yourteam.entitlement-jail.ProbeService_minimal`)
- `main` (the launcher binary entry)
- `evidence.symbols` / `evidence.profiles` (well-known evidence entries)
- A bundle-relative path under `EntitlementJail.app` (example: `Contents/XPCServices/ProbeService_minimal.xpc/Contents/MacOS/ProbeService_minimal`)

`verify-evidence` exits `0` when `result.ok=true`, otherwise `3`.

## `bundle-evidence`: one-shot evidence bundle

`bundle-evidence` collects evidence files and selected JSON reports into a single output directory for archiving/sharing.

Default output path (overwritten each run):

```
~/Library/Application Support/entitlement-jail/evidence/latest
```

By default, tier 2 profiles are **skipped** unless you pass `--ack-risk <id|bundle-id>`. This command does not execute probes unless you request the optional health check (`--include-health-check`).

Bundle contents:

- `Evidence/manifest.json`
- `Evidence/symbols.json`
- `Evidence/profiles.json`
- `verify-evidence.json`
- `list-profiles.json`
- `profiles/<profile-id>.json`
- `bundle_meta.json`
- `health-check.json` (only with `--include-health-check`)

## Optional debugger-side tool: `ej-inspector`

`ej-inspector` is a standalone CLI that checks a target’s signature identity (Team ID + bundle id/prefix) before attempting `task_for_pid`.

If allowed, it immediately deallocates the task port and exits; it does not attach or manipulate state.

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release --bin ej-inspector
```

Usage:

```sh
runner/target/release/ej-inspector <pid> --team-id <TEAMID> --bundle-id-prefix com.yourteam.entitlement-jail.
```

Debugger-side signing/entitlement requirements are documented in [SIGNING.md](../SIGNING.md).

## Debug-only startup probe

If you set `EJ_DEBUG_DLOPEN=1` and `TEST_DYLIB_PATH=<abs>`, the main `entitlement-jail` binary will attempt a `dlopen` at startup and print the result to stderr.

This is disabled by default so help/inspection commands remain side-effect free.

## Layer attribution model (developer view)

This repo treats “what happened” and “why it happened” as separate questions.

For CLI development, the key rule is: don’t silently strengthen claims when plumbing errors through layers.

- Seatbelt/App Sandbox:
  - `run-system` / `run-embedded` may fail for many reasons; “spawn failed” is not automatically “sandbox denied”.
  - `run-xpc` attaches deny evidence only when a deny-shaped unified log line is actually observed.
- Quarantine/Gatekeeper:
  - `quarantine-lab` measures `com.apple.quarantine` deltas and reports `process_exec_not_attempted`.
  - `quarantine-observer` records Gatekeeper status and optional assessment signals (observer-only).
- Other:
  - signature validity, timestamps, missing files, path policy, filesystem permissions, and launchd/XPC issues should remain distinct from “Seatbelt denied”.
