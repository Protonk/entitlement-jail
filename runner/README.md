# `runner/` (Rust launcher: CLI shape + contracts)

This is developer documentation for the Rust code in `runner/`. It builds the command-line launcher that ships as:

- `PolicyWitness.app/Contents/MacOS/policy-witness`

This document exists so people working on the CLI can debug breakage without spelunking a user guide. It complements the user-facing docs and treats behavior as a contract: if you change the CLI, update this doc.

Related docs:

- User guide / workflows (shipped with the app): [PolicyWitness.md](../PolicyWitness.md)
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

- `runner/tests/cli_integration.rs` — integration tests against a built `PolicyWitness.app` (or `PW_BIN_PATH`)
- `tests/suites/smoke/update_file_rename_delta_fixtures.sh` — regression fixtures for the `sandbox_extension update_file_rename_delta` semantics harness (rename retargeting + per-candidate access-delta checks)

This crate also builds standalone helper CLIs:

- `runner/src/bin/quarantine-observer.rs` → `quarantine-observer` (outside the sandbox boundary)
- `runner/src/bin/sandbox-log-observer.rs` → `sandbox-log-observer` (outside the sandbox boundary; embedded into the `.app`)
- `runner/src/bin/pw-inspector.rs` → `pw-inspector` (debugger-side helper; not part of the in-sandbox surface)

## How it builds into `PolicyWitness.app`

The build is centralized in `build.sh` (invoked by `make build`).

Key wiring:

- `cargo build --manifest-path runner/Cargo.toml --release --bin policy-witness` produces `runner/target/release/policy-witness`.
- The build script copies that binary to `PolicyWitness.app/Contents/MacOS/policy-witness`.
- The build script also embeds `runner/target/release/sandbox-log-observer` as `PolicyWitness.app/Contents/MacOS/sandbox-log-observer`.
- The build script builds `pw-inherit-child` and embeds it at `PolicyWitness.app/Contents/MacOS/pw-inherit-child`, then copies it into each `ProbeService_*` bundle (see `xpc/README.md`).
- Evidence manifests are generated during the build by `tests/build-evidence.py` and embedded under `PolicyWitness.app/Contents/Resources/Evidence/`.

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

- `policy-witness xpc run` and `policy-witness xpc session` delegate to the embedded Swift helper `xpc-probe-client`.
- `policy-witness quarantine-lab` delegates to the embedded Swift helper `xpc-quarantine-client`.

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

- `PolicyWitness.app/Contents/MacOS/policy-witness`

For CLI development, it’s useful to keep the raw subcommand surface area in view:

```sh
./PolicyWitness.app/Contents/MacOS/policy-witness run-system <absolute-platform-binary> [args...]
./PolicyWitness.app/Contents/MacOS/policy-witness run-embedded <tool-name> [args...]
./PolicyWitness.app/Contents/MacOS/policy-witness xpc run (--profile <id[@variant]> [--variant <base|injectable>] | --service <bundle-id>) [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--capture-sandbox-logs] <probe-id> [probe-args...]
./PolicyWitness.app/Contents/MacOS/policy-witness xpc session (--profile <id[@variant]> [--variant <base|injectable>] | --service <bundle-id>) [--plan-id <id>] [--correlation-id <id>] [--wait <fifo:auto|fifo:/abs|exists:/abs>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--xpc-timeout-ms <n>]
./PolicyWitness.app/Contents/MacOS/policy-witness quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
./PolicyWitness.app/Contents/MacOS/policy-witness verify-evidence
./PolicyWitness.app/Contents/MacOS/policy-witness inspect-macho <service-id|main|path>
./PolicyWitness.app/Contents/MacOS/policy-witness list-profiles
./PolicyWitness.app/Contents/MacOS/policy-witness list-services
./PolicyWitness.app/Contents/MacOS/policy-witness show-profile <id[@variant]> [--variant <base|injectable>]
./PolicyWitness.app/Contents/MacOS/policy-witness describe-service <id[@variant]> [--variant <base|injectable>]
./PolicyWitness.app/Contents/MacOS/policy-witness health-check [--profile <id[@variant]>] [--variant <base|injectable>]
./PolicyWitness.app/Contents/MacOS/policy-witness bundle-evidence [--out <dir>] [--include-health-check]
./PolicyWitness.app/Contents/MacOS/policy-witness run-matrix --group <name> [--variant <base|injectable>] [--out <dir>] <probe-id> [probe-args...]
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

- Keys are lexicographically sorted for stability (see `runner/src/json_contract.rs`).
- `result.rc` is used by probes/quarantine; `result.exit_code` is used by CLI/tools. Unused fields are `null`.
- All command-specific fields live under `data` (no extra top-level keys).

Note: Rust-emitted envelopes use `schema_version: 1`. XPC probe/quarantine responses emitted by the embedded Swift clients use `schema_version: 1`.

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
- Search paths are relative to the `.app` bundle that contains `policy-witness`:
  - `PolicyWitness.app/Contents/Helpers/<tool-name>`
  - `PolicyWitness.app/Contents/Helpers/Probes/<tool-name>`

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

Note: the `inherit_child` probe emits a structured witness under `data.witness` (frozen two-bus protocol + strict invariants + scenario/matrix results) and uses `kind: probe_response`.
Stop mechanics are observable without a debugger: `inherit_child` uses start-suspended spawn plus stop markers, and the witness/event stream makes stop-on-entry/deny behavior testable.

Sandbox log capture:

- `--capture-sandbox-logs` runs the embedded `sandbox-log-observer` in lookback mode after the probe returns.
- The capture is always attached under `data.host_sandbox_log_capture` (predicate + time bounds + excerpt or error).
- For `inherit_child`, the launcher also attaches tri-state status to `data.witness` as `sandbox_log_capture_status` (`not_requested|requested_unavailable|captured`) and `sandbox_log_capture` (string map).

## `xpc session`: durable service sessions (debug/attach)

`xpc session` is a session-based control plane intended for deterministic debugger/tracer attachment (lldb/dtrace/Frida) without racing service startup. It keeps the service alive across multiple probes unless explicitly closed.
Durable sessions matter for extension liveness claims: “before/after” checks are only meaningful when they occur in the same process context (not a fresh-start service each time).

I/O contract:

- Stdout is JSONL: one JSON envelope per line.
  - Lifecycle lines: `kind: xpc_session_event` / `kind: xpc_session_error`
  - Probe lines: `kind: probe_response` (one per `run_probe` command)
- Stdin is JSONL commands (one object per line):
  - `{"command":"run_probe","probe_id":"...","argv":[...]}`
  - `{"command":"keepalive"}`
  - `{"command":"close_session"}`

Critical semantic: if a wait is configured (via `--wait ...`), `run_probe` is refused until the service emits `data.event: trigger_received`. This is the stable “attach-before-probe” barrier.

Session events can include `data.child_pid` + `data.run_id` for probes that spawn a child (for example `inherit_child`), along with `data.event: child_spawned|child_stopped|child_exited`.

For the authoritative on-the-wire shapes, see `xpc/ProbeAPI.swift` and `xpc/ProbeServiceSessionHost.swift`.

## Profiles, services, and health checks

Profiles are short base ids that map to XPC service families in the “process zoo”.

The authoritative inventory is `PolicyWitness.app/Contents/Resources/Evidence/profiles.json`, generated during build by `tests/build-evidence.py`.

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
~/Library/Application Support/policy-witness/matrix/<group>/<variant>/latest
```

Notes:

- High-concern variants are included without extra flags.
- If you run a sandboxed-launcher build, default output paths resolve under the container home; choose `--out` accordingly.

## `quarantine-lab`: write/open artifacts and report quarantine metadata (no execution)

`quarantine-lab` delegates to the embedded Swift helper `xpc-quarantine-client` plus an XPC service (for example `com.yourteam.policy-witness.QuarantineLab_default`).

Key contract:

- This mode **does not execute** specimens. It writes/opens/reads and reports quarantine metadata deltas.

## Unsandboxed observer: `sandbox-log-observer`

`sandbox-log-observer` is intended to be a clean witness that does not inherit the App Sandbox.

The launcher does not automatically run it; callers should treat it as an explicit, separate evidence attachment step.

Stream mode supports `--until-pid-exit` to stop capture when the target process exits.

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release --bin sandbox-log-observer
```
