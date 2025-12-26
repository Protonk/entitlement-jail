# `entitlement-jail` (CLI + behavior manual)

This document is the authoritative reference for the command-line behavior and what is (and is not) being claimed/measured.

## Core rule: arbitrary path exec is rejected by design

On stock macOS, sandboxed apps commonly hit `process-exec*` denials when attempting to execute binaries staged into writable/container locations. This repo intentionally does **not** support “exec arbitrary staged Mach-O by path”.

Supported execution surfaces:

- `run-system`: execute in-place platform binaries from an allowlisted set of system prefixes
- `run-embedded`: execute bundle-embedded helper tools (sandbox inheritance; strict signing requirements)
- `run-xpc`: delegate to launchd-managed XPC services (preferred when entitlements are the research variable)
- `quarantine-lab`: write/open artifacts via an XPC service and report `com.apple.quarantine` deltas (no execution)

## Invoking the tool

The launcher lives at:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail`

Usage:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-system <absolute-platform-binary> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-embedded <tool-name> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc [--profile <id>] [--ack-risk <id|bundle-id>] [--log-stream <path|auto|stdout>|--log-path-class <class> --log-name <name>] [--log-predicate <predicate>] [--observe] [--observer-duration <seconds>] [--observer-format <json|jsonl>] [--observer-output <path|auto>] [--observer-follow] [--json-out <path>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>] [--wait-fifo <path>|--wait-exists <path>] [--wait-path-class <class>] [--wait-name <name>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create] [--attach <seconds>] [--hold-open <seconds>] [--xpc-timeout-ms <n>] <xpc-service-bundle-id> <probe-id> [probe-args...]
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

## JSON output contract

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

- Keys are lexicographically sorted for stability.
- `result.rc` is used by probes/quarantine; `result.exit_code` is used by CLI/tools. Unused fields are `null`.
- All command-specific fields live under `data` (no extra top‑level keys).

Kinds:

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
- If you produce a sandboxed launcher build, embedded helpers must be signed for sandbox inheritance; follow [SIGNING.md](../SIGNING.md).

Behavior:

- Verifies the resolved target exists and is executable.
- Spawns it as a child process and exits with the child’s exit status.

Note: treat `run-embedded` as an inheritance demo surface only; use XPC services for entitlements-as-a-variable experiments.

## `run-xpc`: launchd-managed XPC services (preferred)

`run-xpc` delegates to an embedded Swift helper (`xpc-probe-client`) that speaks NSXPC. The main `entitlement-jail` binary does not talk XPC directly.

Helper location (important):

- `xpc-probe-client` is embedded as `EntitlementJail.app/Contents/MacOS/xpc-probe-client` (not `Contents/Helpers`), so `Bundle.main` resolves to `EntitlementJail.app`.
- This bundle context is required for `NSXPCConnection(serviceName:)` to locate the app’s embedded `.xpc` bundles by bundle id.

Invocation:

- `run-xpc [--log-stream <path|auto|stdout>|--log-path-class <class> --log-name <name>] [--log-predicate <predicate>] [--observe] [--observer-duration <seconds>] [--observer-format <json|jsonl>] [--observer-output <path|auto>] [--observer-follow] [--json-out <path>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>] [--wait-fifo <path>|--wait-exists <path>] [--wait-path-class <class>] [--wait-name <name>] [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create] [--attach <seconds>] [--hold-open <seconds>] [--xpc-timeout-ms <n>] <xpc-service-bundle-id> <probe-id> [probe-args...]`
- Example service bundle id: `com.yourteam.entitlement-jail.ProbeService_minimal`

Built-in probe ids (in-process):

- `probe_catalog`
- `world_shape`
- `network_tcp_connect` (`--host <ipv4> --port <1..65535>`)
- `downloads_rw` (`[--name <file-name>]`)
- `fs_op` (`--op <...> (--path <abs> | --path-class <...>) [--allow-unsafe-path]`)
- `fs_op_wait` (`fs_op` + `--wait-fifo <path>` or `--wait-exists <path>`; optional `--wait-timeout-ms`, `--wait-interval-ms`)
- `net_op` (`--op <getaddrinfo|tcp_connect|udp_send> --host <host> [--port <1..65535>] [--numeric]`)
- `dlopen_external` (`--path <abs>` or `EJ_DLOPEN_PATH`)
- `jit_map_jit` (`[--size <bytes>]`)
- `jit_rwx_legacy` (`[--size <bytes>]`)
- `bookmark_op` (`--bookmark-b64 <base64> | --bookmark-path <path> [--relative <rel>] [--op <fs-op>] [--allow-unsafe-path]`)
- `bookmark_make` (`--path <abs> [--no-security-scope] [--read-only] [--allow-missing]`)
- `bookmark_roundtrip` (`--path <abs> [--op <fs-op>] [--relative <rel>] [--no-security-scope] [--read-only] [--allow-missing] [--allow-unsafe-path]`)
- `capabilities_snapshot`
- `userdefaults_op` (`--op <read|write|remove|sync> [--key <k>] [--value <v>] [--suite <suite>]`)
- `fs_xattr` (`--op <get|list|set|remove> --path <abs> [--name <xattr>] [--value <v>] [--allow-write] [--allow-unsafe-path]`)
- `fs_coordinated_op` (`--op <read|write> (--path <abs> | --path-class <...>) [--allow-unsafe-path]`)

Notes:

- `--profile <id>` lets you select a service by profile id (see `list-profiles`), instead of passing the full bundle id.
- When you use `--profile`, omit the explicit service bundle id.
- Tier 2 profiles require `--ack-risk <id|bundle-id>` to run; Tier 1 prints a warning; Tier 0 runs silently.
- `probe_catalog` outputs JSON in `result.stdout`; use `<probe-id> --help` for per-probe usage (help text is returned in `result.stdout`).
- `probe_catalog` includes `trace_symbols`, mapping probe ids to stable `ej_*` marker symbols for external tooling.
- Filesystem probes are safe-by-default: destructive direct-path operations are refused unless you target a harness path (for `fs_op`/`fs_coordinated_op` via `--path-class`/`--target`, or for `fs_xattr` via an explicit path under `*/entitlement-jail-harness/*`) or pass `--allow-unsafe-path` (or `--allow-write` for `fs_xattr`).
- `dlopen_external` loads and executes dylib initializers by design; use a signed test dylib.
- `--log-stream` writes a best-effort live unified log excerpt for sandbox denial lines (uses `log stream` during the probe) and emits a PID-scoped JSON report at the requested path (`kind: sandbox_log_stream_report`, excerpt in `data.log_stdout`); absence of deny lines is not a denial claim. Use `--log-stream auto` for an app-managed path; `--log-stream stdout` writes the stream report to stdout and requires `--json-out`.
- `--observe` runs the unsandboxed observer even without `--log-stream`; `--log-stream` also triggers the observer automatically.
- `--observer-duration`/`--observer-follow` run the observer in live mode (`log stream`); default observer mode uses `log show` and probe start/end timestamps.
- `--observer-format jsonl` and `--observer-output <path|auto>` control observer persistence (`jsonl` emits per-line events plus a final report line).
- `--log-path-class`/`--log-name` chooses a container-safe output path for the log stream report (useful when repo paths are blocked); the observer report lives alongside it unless overridden.
- In-sandbox post-run log access is intentionally unsupported; the observer runs outside the sandbox boundary.
- Responses include `log_capture_status`, `log_capture_predicate`, `log_capture_observed_*`, plus `log_observer_status`, `log_observer_path`, `log_observer_observed_*`, `log_observer_deny_lines`, and the embedded `log_observer_report`; `deny_evidence` is `not_captured` when log capture is not requested, `captured` when a denial line is observed (stream or observer), `not_found` when capture ran but no denial lines matched, and `log_error` when both stream and observer failed.
- If the service omits PID/process name in `data.details`, the client injects fallbacks and records `pid_source` / `process_name_source`.
- All JSON responses use the envelope described above (including top-level `schema_version`).
- `--log-stream` uses `/usr/bin/log`; when the launcher is sandboxed, `log` may refuse to run and deny evidence will not be captured. The default build keeps the launcher unsandboxed so log capture works.
- `--hold-open` keeps the XPC connection open after the response to make debugger/trace attachment easier.
- `--json-out` writes the probe JSON response to a file (stdout stays available for log stream output).
- Log/observer flags (`--log-*`, `--observe`, `--observer-*`, `--json-out`) must appear before `<xpc-service-bundle-id>`.
- `--log-predicate` overrides the default PID-scoped predicate for both stream and observer (pass a full predicate string).
- `--attach <seconds>` is a convenience for attach workflows: it sets a pre-run wait using a FIFO under the service’s container `tmp` plus a matching `--hold-open` (unless you set `--hold-open` explicitly).
- `--xpc-timeout-ms <n>` sets a client-side timeout; if no response arrives, the client emits a structured `probe_response` with `normalized_outcome: xpc_error`.
- `--wait-fifo`/`--wait-exists` block **before** probe execution; the wait outcome is recorded in `data.details` (`wait_*` keys).
- `--wait-create` tells the service to create the FIFO path before waiting (only valid with `--wait-fifo`).
- When a wait is configured, the client prints a `wait-ready` line to stderr with the resolved wait path (use that FIFO or file path to trigger). When attach waits are in use, it also prints a `pid-ready` line once the service PID is known.

### Attach cheat-sheet

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc --attach 60 --profile fully_injectable fs_op --op stat --path-class tmp
```

Copy the FIFO path from stderr, then trigger:

```sh
printf go > /path/from/wait-ready.fifo
```

If you want the process to stay alive longer after the probe runs, add `--hold-open <seconds>`.

High-level flow:

1. `entitlement-jail` runs the embedded helper `xpc-probe-client`.
2. The helper connects to the XPC service by bundle id and sends a JSON request `{probe_id, argv, ...}`.
3. The XPC service runs the probe **in-process** (no child-process exec) and returns a JSON response.
4. The helper prints the JSON response and exits with `rc`.

Why XPC:

- Each `.xpc` is a separate signed target with its own entitlements, and is launchd-managed.
- This makes entitlements a first-class experimental variable without relying on child-process inheritance quirks.

Example (dlopen_external):

```sh
EJ_DLOPEN_PATH="$PWD/tests/fixtures/TestDylib/out/testdylib.dylib" \
  ./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc --ack-risk fully_injectable com.yourteam.entitlement-jail.ProbeService_fully_injectable dlopen_external
```

## Profiles and health checks

Profiles are short ids that map to XPC services in the process zoo.

List and inspect:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail list-profiles
./EntitlementJail.app/Contents/MacOS/entitlement-jail list-services
./EntitlementJail.app/Contents/MacOS/entitlement-jail show-profile minimal
./EntitlementJail.app/Contents/MacOS/entitlement-jail describe-service minimal
```

Use a profile id with `run-xpc`:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc --profile minimal capabilities_snapshot
```

Tier model:

- Tier 0: baseline/access entitlements only (not gated)
- Tier 1: `get-task-allow` and/or `disable-library-validation` (warn-only)
- Tier 2: `allow-dyld-environment-variables`, `allow-jit`, or `allow-unsigned-executable-memory` (requires `--ack-risk`)

Example (tier 2 ack):

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc --profile fully_injectable --ack-risk fully_injectable probe_catalog
```

Health check (safe probes only):

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail health-check --profile minimal
```

This runs `capabilities_snapshot`, `world_shape`, and `fs_op --op stat --path-class tmp`.

`describe-service` is a **static** view derived from entitlements and container path conventions; it does not run any probes.

## `run-matrix`: compare a probe across a service group

Run the same probe across a predefined group and emit a compare table plus JSON bundle.

Groups:

- `baseline`: `minimal`
- `debug`: `minimal`, `get-task-allow`
- `inject`: `minimal`, `fully_injectable`

Example:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-matrix --group inject fs_op --op stat --path-class tmp
```

Output (default, overwritten each run):

```
~/Library/Application Support/entitlement-jail/matrix/<group>/latest
```

When running inside a sandboxed-launcher build, `HOME` resolves to the container home, so the default path lives under `~/Library/Containers/<bundle-id>/Data/...`.
If you pass `--out` in that configuration, choose a container-writable path; repo paths are typically blocked from inside the sandbox.

Files:

- `run-matrix.json`
- `run-matrix.table.txt`

Tier 2 profiles in the group are skipped unless you pass `--ack-risk <id|bundle-id>`.

## `quarantine-lab`: write/open artifacts and report `com.apple.quarantine`

`quarantine-lab` delegates to an embedded Swift helper (`xpc-quarantine-client`) and an XPC service (for example `com.yourteam.entitlement-jail.QuarantineLab_default`).

Helper location (important):

- `xpc-quarantine-client` is embedded as `EntitlementJail.app/Contents/MacOS/xpc-quarantine-client` for the same bundle-context reason as `run-xpc`.

Important: this mode **does not execute artifacts**. It writes/opens/reads and reports metadata deltas.

Payload classes:

- `shell_script`: writes a small `#!/bin/sh` script (`.sh`) and defaults to executable
- `command_file`: writes a small `#!/bin/sh` script (`.command`) and defaults to executable
- `text`: writes a `.txt` file and defaults to non-executable
- `webarchive_like`: writes a minimal plist-ish `.webarchive`-shaped payload (not a correctness-focused WebArchive)

Operations (`--operation`):

- `create_new` (default): write a new artifact into an output directory
- `open_only`: open/read an existing path (or the derived output path) and report any xattr delta
- `open_existing_save`: read an existing path and save a copy into the output directory

Path selection (`--dir`):

- `tmp` (default): `TMPDIR/.../entitlement-jail-quarantine-lab`
- `app_support`: `~/Library/Application Support/entitlement-jail-quarantine-lab`

Other options:

- `--existing-path <path>`: the input specimen for `open_existing_save`, and the target for `open_only` if provided
- `--name <file-name>`: output file name (single path component; an extension is enforced based on payload class)
- `--exec` / `--no-exec`: force/clear `+x` on the output (otherwise defaults are derived from payload type or source)
- `--selection <string>`: annotation only; does not grant access or change authorization
- `--test-case-id <id>`: annotation included in output

Outputs:

- The helper prints a JSON object describing what was written/opened and `com.apple.quarantine` before/after (raw + parsed fields).

## Unsandboxed observer: `quarantine-observer`

`quarantine-observer` is intentionally *not* run from inside `EntitlementJail.app`. Its job is to be a clean witness that does not inherit the App Sandbox.

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release
```

Run:

```sh
runner/target/release/quarantine-observer <path> --assess
```

Behavior:

- Reads the `com.apple.quarantine` xattr (if present).
- Records Gatekeeper status and (optionally) an assessment signal (observer-only; does not execute the file).

Do not run the observer from a sandboxed parent process; the default build’s host-side launcher is unsandboxed, which preserves the “outside the sandbox” boundary.

## Unsandboxed observer: `sandbox-log-observer`

`sandbox-log-observer` runs `log show` by default (or `log stream` with `--duration`/`--follow`) and emits a versioned JSON envelope with a sandbox-deny excerpt.

In the distributed bundle it is embedded at:

- `EntitlementJail.app/Contents/MacOS/sandbox-log-observer`

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release --bin sandbox-log-observer
```

Run:

```sh
runner/target/release/sandbox-log-observer --pid <pid> --process-name <name> --last 5s
runner/target/release/sandbox-log-observer --pid <pid> --process-name <name> --duration 5 --format jsonl --output /tmp/ej-observer.jsonl
```

Notes:

- `--predicate` overrides the default `Sandbox: <name>(<pid>)` predicate.
- Prefer `--start`/`--end` when you have probe timing; `--last` is a fallback. Use `--duration`/`--follow` for live observation.
- `--format jsonl` emits per-line `sandbox_log_observer_event` lines plus a final `sandbox_log_observer_report` summary line.
- `--output` writes a file (appends for jsonl, overwrites for json).
- `--plan-id`/`--row-id`/`--correlation-id` annotate the JSON output for easier stitching.
- `data.mode` is `show` or `stream`; `data.duration_ms` is set when `--duration` is used.
- `data.observer_schema_version` is the observer report schema version (stable unless explicitly bumped).
- `data.deny_lines` is a structured list of deny-shaped log lines (case-insensitive match on `deny`).
- Use it outside the sandbox boundary; do not run it from a sandboxed parent process.

## Evidence manifest (signed BOM)

The app embeds a small evidence manifest at:

- `EntitlementJail.app/Contents/Resources/Evidence/manifest.json`

It records hashes, LC_UUIDs, and entitlements for embedded helpers and XPC services. The manifest is signed as part of the app bundle (it deliberately omits the main binary hash to avoid self‑referencing).

The Evidence directory also includes:

- `EntitlementJail.app/Contents/Resources/Evidence/symbols.json`

This lists exported `ej_*` probe markers per binary (useful for `otool`, `dtrace`, `frida`, or Ghidra correlation).

- `EntitlementJail.app/Contents/Resources/Evidence/profiles.json`

This lists profile ids, service bundle ids, tags, and entitlements for the process zoo.

Each profile includes `risk_tier` and `risk_reasons` fields used by the CLI risk gate.

Commands:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail verify-evidence
./EntitlementJail.app/Contents/MacOS/entitlement-jail inspect-macho com.yourteam.entitlement-jail.ProbeService_minimal
./EntitlementJail.app/Contents/MacOS/entitlement-jail inspect-macho main
./EntitlementJail.app/Contents/MacOS/entitlement-jail inspect-macho evidence.symbols
./EntitlementJail.app/Contents/MacOS/entitlement-jail inspect-macho evidence.profiles
./EntitlementJail.app/Contents/MacOS/entitlement-jail inspect-macho Contents/XPCServices/ProbeService_minimal.xpc/Contents/MacOS/ProbeService_minimal
```

`verify-evidence` checks the on‑disk binaries against the manifest. `inspect-macho` prints the manifest entry (and absolute path) for a service id, `main`, or a bundle‑relative path.

`verify-evidence` returns a JSON envelope. Use `result.ok` for the overall outcome and `data` for `checked`, `mismatches`, `manifest_path`, `schema_version` (manifest schema), and optional `notes`.

## `bundle-evidence`: one-shot evidence bundle

`bundle-evidence` collects the Evidence files and JSON reports into a single output directory for archiving or sharing.

Default output path (overwritten on each run):

```
~/Library/Application Support/entitlement-jail/evidence/latest
```

When running inside a sandboxed-launcher build, `HOME` resolves to the container home, so the default path lives under `~/Library/Containers/<bundle-id>/Data/...`.

Outputs:

- `Evidence/manifest.json`
- `Evidence/symbols.json`
- `Evidence/profiles.json`
- `verify-evidence.json`
- `list-profiles.json`
- `profiles/<profile-id>.json`
- `bundle_meta.json`
- `health-check.json` (only with `--include-health-check`)

By default, Tier 2 profiles are **skipped** in `profiles/` unless you pass `--ack-risk <id|bundle-id>`. This does not execute probes unless you request the optional health check.

Example:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail bundle-evidence --out /tmp/ej-evidence
```

## Optional debugger-side tool: `ej-inspector`

`ej-inspector` is a standalone CLI that checks a target’s signature identity (Team ID + bundle id/prefix) before attempting `task_for_pid`. If allowed, it immediately deallocates the task port and exits; it does not attach or manipulate state.

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release --bin ej-inspector
```

Signing and entitlement requirements for debugger-side tooling are documented in `SIGNING.md`.

Usage:

```sh
runner/target/release/ej-inspector <pid> --team-id <TEAMID> --bundle-id-prefix com.yourteam.entitlement-jail.
```

Notes:

- The target must also carry `com.apple.security.get-task-allow` for debugger attach to succeed.
- If you omit `--bundle-id-prefix`/`--bundle-id`, the tool defaults to `com.yourteam.entitlement-jail.`.
- Use this tool outside the sandbox boundary; do not run it from inside `EntitlementJail.app`.

## Debug-only startup probe

If you set `EJ_DEBUG_DLOPEN=1` and `TEST_DYLIB_PATH=<abs>`, the main `entitlement-jail` binary will attempt a `dlopen` at startup and print the result to stderr. This is for debugging entitlements and is disabled by default to keep help/inspection commands side-effect free.

## Layer attribution model

This repo treats “what happened” and “why it happened” as separate questions.

- Seatbelt/App Sandbox layer:
  - `run-system` / `run-embedded` may fail due to `process-exec*` policy (but failure to launch is not automatically a sandbox denial).
  - `quarantine-lab` reports `seatbelt: process_exec_not_attempted` because it does not execute specimens.
- Quarantine/Gatekeeper layer:
  - `quarantine-lab` measures `com.apple.quarantine` before/after writing/opening/copying.
  - `quarantine-observer` can record Gatekeeper status and optional assessment signals for the written specimen.
- “Other”:
  - Signature validity issues, missing secure timestamps, path validation, file permissions, missing files, and launchd/XPC issues are not Seatbelt signals and must be reported distinctly.

## JSON outputs (high level)

XPC-backed commands print JSON to stdout (the Rust launcher does not reformat it):

- `run-xpc` prints a `kind: probe_response` envelope and exits with `result.rc`.
- `quarantine-lab` prints a `kind: quarantine_response` envelope and exits with `result.rc`.

For wire-format details and exact fields, see the JSON output contract above and [xpc/README.md](../xpc/README.md).
