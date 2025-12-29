# `runner/` (Rust launcher: CLI shape + contracts)

This is developer documentation for the Rust code in `runner/`. It builds the command-line launcher that ships as:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail`

This document exists so people working on the CLI can debug breakage without spelunking a user guide. It complements the user-facing docs, but it still treats behavior as a contract: if you change the CLI, update this doc.

Related docs:

- User guide / workflows (shipped with the app): [EntitlementJail.md](../EntitlementJail.md)
- XPC subsystem (Swift; build + services): [xpc/README.md](../xpc/README.md)
- Contributing/build tour: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Signing/build procedure: [SIGNING.md](../SIGNING.md)
- Tri-run experiment harness: [experiments/README.md](../experiments/README.md)

## What lives in `runner/`

Core files:

- `runner/src/main.rs` — CLI parsing, policy boundaries, risk gating, evidence/profiles commands
- `runner/src/json_contract.rs` — JSON envelope + lexicographic key ordering (output stability)
- `runner/src/evidence.rs` — Evidence manifest loading + hash verification helpers
- `runner/src/profiles.rs` — profile manifest loading + lookup helpers
- `runner/src/debug_entitlements_probe.rs` — debug-only startup `dlopen` probe (opt-in via env var)

CLI tests:

- `runner/tests/cli_integration.rs` — integration tests against a built `EntitlementJail.app` (or `EJ_BIN_PATH`)

This crate also builds standalone helper CLIs:

- `runner/src/bin/quarantine-observer.rs` → `quarantine-observer` (outside the sandbox boundary)
- `runner/src/bin/sandbox-log-observer.rs` → `sandbox-log-observer` (outside the sandbox boundary; embedded into the `.app`)
- `runner/src/bin/ej-inspector.rs` → `ej-inspector` (debugger-side helper; not part of the in-sandbox surface)

## How it builds into `EntitlementJail.app`

The build is centralized in `build.sh` (invoked by `make build`).

Key wiring:

- `cargo build --manifest-path runner/Cargo.toml --release --bin runner` produces `runner/target/release/runner`.
- The build script copies that binary to `EntitlementJail.app/Contents/MacOS/entitlement-jail`.
- The build script also embeds `runner/target/release/sandbox-log-observer` as `EntitlementJail.app/Contents/MacOS/sandbox-log-observer`.
- Evidence manifests are generated during the build by `tests/build-evidence.py` and embedded under `EntitlementJail.app/Contents/Resources/Evidence/`.

If you change bundle paths, add embedded executables, or change how services are enumerated/signed, expect to touch both `build.sh` and `tests/build-evidence.py`, plus the docs that describe the resulting bundle layout.

## Design invariants (don’t casually break these)

### No arbitrary path execution

The launcher intentionally does **not** provide a “run arbitrary staged Mach‑O by path” feature.

On stock macOS, sandboxed apps commonly hit `process-exec*` denials when trying to execute from writable/container locations. If this repo quietly allowed arbitrary exec-by-path, many failures would become uninterpretable (and easy to misattribute).

Instead, the supported execution surfaces are:

- `run-system` — execute **in-place platform binaries** from allowlisted prefixes
- `run-embedded` — execute **bundle-embedded** helper tools (inheritance demo surface)
- `xpc run` / `xpc session` — run probes **in-process** inside launchd-managed XPC services (preferred; entitlements are the variable)
- `quarantine-lab` — write/open artifacts and report quarantine metadata deltas (**no execution**)

### XPC commands delegate (Rust does not speak NSXPC)

The Rust launcher does not speak NSXPC directly.

- `entitlement-jail xpc run` and `entitlement-jail xpc session` delegate to the embedded Swift helper `xpc-probe-client`.
- `entitlement-jail quarantine-lab` delegates to the embedded Swift helper `xpc-quarantine-client`.

The launcher primarily acts as:

- an argument router (profile id / bundle id selection),
- a risk reporter (warnings derived from `profiles.json`), and
- a wrapper that preserves stdout/stderr and exits like the child process.

### JSON output envelopes are stable and sorted

All JSON emitters in this repo (Rust and Swift) share a uniform top-level envelope and keep keys lexicographically sorted for stability.

If you add fields or change shapes, treat it as a contract change: update docs and any downstream tools/tests that consume the outputs.

### Risk signals are derived (and warned)

Risk signals/warnings are not hand-curated in the Rust code.

- The build generates `Evidence/profiles.json` by extracting **signed** entitlements via `codesign` (`tests/build-evidence.py`).
- The launcher uses per-variant risk metadata from that manifest to emit warnings.
- There is no acknowledgement flag; selecting the injectable variant is treated as explicit intent.

If you add a “high concern” entitlement, update the risk classifier so the risk signal stays honest.

## Finding and invoking the CLI

Shipped location:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail`

For CLI development, it’s useful to keep the raw subcommand surface area in view:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-system <absolute-platform-binary> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-embedded <tool-name> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail xpc run (--profile <id[@variant]> [--variant <base|injectable>] | --service <bundle-id>) [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] <probe-id> [probe-args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail xpc session (--profile <id[@variant]> [--variant <base|injectable>] | --service <bundle-id>) [--plan-id <id>] [--correlation-id <id>] [--wait <fifo:auto|fifo:/abs|exists:/abs>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--xpc-timeout-ms <n>]
./EntitlementJail.app/Contents/MacOS/entitlement-jail quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail verify-evidence
./EntitlementJail.app/Contents/MacOS/entitlement-jail inspect-macho <service-id|main|path>
./EntitlementJail.app/Contents/MacOS/entitlement-jail list-profiles
./EntitlementJail.app/Contents/MacOS/entitlement-jail list-services
./EntitlementJail.app/Contents/MacOS/entitlement-jail show-profile <id[@variant]> [--variant <base|injectable>]
./EntitlementJail.app/Contents/MacOS/entitlement-jail describe-service <id[@variant]> [--variant <base|injectable>]
./EntitlementJail.app/Contents/MacOS/entitlement-jail health-check [--profile <id[@variant]>] [--variant <base|injectable>]
./EntitlementJail.app/Contents/MacOS/entitlement-jail bundle-evidence [--out <dir>] [--include-health-check]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-matrix --group <name> [--variant <base|injectable>] [--out <dir>] <probe-id> [probe-args...]
```

## JSON output contract (envelope + kinds)

All JSON emitters in this repo (CLI outputs, XPC client outputs, and helper tools) share a uniform envelope:

```json
{
  "schema_version": 4,
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

- Keys are lexicographically sorted for stability (see `runner/src/json_contract.rs`).
- `result.rc` is used by probes/quarantine; `result.exit_code` is used by CLI/tools. Unused fields are `null`.
- All command-specific fields live under `data` (no extra top-level keys).

Note: Rust-emitted envelopes currently use `schema_version: 4`. XPC probe/quarantine responses emitted by the embedded Swift clients still use `schema_version: 2`.

Envelope `kind` values used by the launcher and helpers:

- `probe_response`
- `xpc_session_event`
- `xpc_session_error`
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

### Who emits JSON (and who doesn’t)

Not every subcommand prints JSON:

- **Pass-through exec (no JSON)**: `run-system`, `run-embedded` (exit like the child process)
- **Swift-emitted JSON**: `xpc run`, `xpc session`, `quarantine-lab` (wrapper to embedded Swift clients; exit like the client process)
- **Rust-emitted JSON**: `verify-evidence`, `inspect-macho`, `list-profiles`, `list-services`, `show-profile`, `describe-service`, `health-check`, `bundle-evidence`, `run-matrix`

## `run-system`: in-place platform binaries

`run-system` only executes **absolute** paths under these prefixes:

- `/bin`
- `/usr/bin`
- `/sbin`
- `/usr/sbin`
- `/usr/libexec`
- `/System/Library`

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

Behavior:

- Verifies the resolved target exists and is executable.
- Spawns it as a child process and exits with the child’s exit status.

Treat `run-embedded` as an inheritance demo surface only; use XPC services for entitlements-as-a-variable experiments.

## `xpc run`: one-shot probes in launchd-managed services

`xpc run` is the main “entitlements vary cleanly” surface. It runs probes **in-process** inside launchd-managed XPC services.

Wiring (who does what):

- The Rust launcher delegates to the embedded Swift helper `xpc-probe-client` (under `Contents/MacOS`), which speaks NSXPC.
- The launcher emits risk warnings based on `Evidence/profiles.json` before it executes the helper.
- `xpc-probe-client` opens a session, runs one probe, prints a `probe_response` envelope, and closes the session.

Service selection:

- `--profile <id>` resolves a base profile via `Evidence/profiles.json` and selects a variant.
- `--variant <base|injectable>` selects the variant (default: `base`); `profile@injectable` is accepted as sugar.
- `--service <bundle-id>` targets an explicit XPC service bundle id (base or injectable).

Exit behavior:

- Stdout: a single `kind: probe_response` JSON envelope.
- Process exit code: `result.rc` (clamped to 0–255) so probe failures are script-visible.

## `xpc session`: durable service sessions (debug/attach)

`xpc session` is a session-based control plane intended for deterministic debugger/tracer attachment (lldb/dtrace/Frida) without racing service startup. It keeps the service alive across multiple probes unless explicitly closed.

I/O contract:

- Stdout is JSONL: one JSON envelope per line.
  - Lifecycle lines: `kind: xpc_session_event` / `kind: xpc_session_error`
  - Probe lines: `kind: probe_response` (one per `run_probe` command)
- Stdin is JSONL commands (one object per line):
  - `{"command":"run_probe","probe_id":"...","argv":[...]}`
  - `{"command":"keepalive"}`
  - `{"command":"close_session"}`

Critical semantic: if a wait is configured (via `--wait ...`), `run_probe` is refused until the service emits `data.event: trigger_received`. This is the stable “attach-before-probe” barrier.

For the authoritative on-the-wire shapes, see `xpc/ProbeAPI.swift` and `xpc/ProbeServiceSessionHost.swift`.

## Profiles, services, and health checks

Profiles are short base ids that map to XPC service families in the “process zoo”.

The authoritative inventory is `EntitlementJail.app/Contents/Resources/Evidence/profiles.json`, generated during build by `tests/build-evidence.py`.

Each profile entry contains a `variants` array with at least:

- `variant: base` (canonical entitlements)
- `variant: injectable` (auto-generated twin with the fixed overlay)

Commands:

- `list-profiles` (`kind: profiles_report`)
- `list-services` (`kind: services_report`; base + injectable variants)
- `show-profile <id>` (`kind: profile_report`; includes variants)
- `describe-service <id>` (`kind: describe_service_report`; static entitlements-derived view)

`health-check` runs a small set of safe probes and emits `kind: health_check_report`.

## `run-matrix`: compare a probe across a service group

`run-matrix` runs the same probe across a predefined group and emits a compare table plus a JSON bundle.

Default output path (overwritten each run):

```
~/Library/Application Support/entitlement-jail/matrix/<group>/<variant>/latest
```

Notes:

- High-concern variants are included without extra flags.
- If you run a sandboxed-launcher build, default output paths resolve under the container home; choose `--out` accordingly.

## `quarantine-lab`: write/open artifacts and report quarantine metadata (no execution)

`quarantine-lab` delegates to the embedded Swift helper `xpc-quarantine-client` plus an XPC service (for example `com.yourteam.entitlement-jail.QuarantineLab_default`).

Key contract:

- This mode **does not execute** specimens. It writes/opens/reads and reports quarantine metadata deltas.

## Unsandboxed observer: `sandbox-log-observer`

`sandbox-log-observer` is intended to be a clean witness that does not inherit the App Sandbox.

The launcher does not automatically run it; callers should treat it as an explicit, separate evidence attachment step.

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release --bin sandbox-log-observer
```
