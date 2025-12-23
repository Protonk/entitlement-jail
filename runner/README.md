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

The sandboxed launcher lives at:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail`

Usage:

```sh
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-system <absolute-platform-binary> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-embedded <tool-name> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc [--log-sandbox <path>|--log-stream <path>] [--log-predicate <predicate>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>] [--hold-open <seconds>] <xpc-service-bundle-id> <probe-id> [probe-args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
```

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

## `run-embedded`: bundle-embedded helpers (inheritance)

`run-embedded` runs an executable that is shipped *inside the app bundle*, by a simple tool name (a single path component).

Resolution rules:

- `tool-name` must be a single path component (no `/`, no `..`, no traversal).
- Search paths are relative to the `.app` bundle that contains `entitlement-jail`:
  - `EntitlementJail.app/Contents/Helpers/<tool-name>`
  - `EntitlementJail.app/Contents/Helpers/Probes/<tool-name>`

Signing rules:

- Embedded helpers are expected to be signed correctly for sandbox inheritance (see [SIGNING.md](../SIGNING.md)).
- If the helper is not signed as required, inheritance may fail or behave as a different “identity” than you expected.

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

- `run-xpc [--log-sandbox <path>|--log-stream <path>] [--log-predicate <predicate>] [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>] [--hold-open <seconds>] <xpc-service-bundle-id> <probe-id> [probe-args...]`
- Example service bundle id: `com.yourteam.entitlement-jail.ProbeService_minimal`

Built-in probe ids (in-process):

- `probe_catalog`
- `world_shape`
- `network_tcp_connect` (`--host <ipv4> --port <1..65535>`)
- `downloads_rw` (`[--name <file-name>]`)
- `fs_op` (`--op <...> (--path <abs> | --path-class <...>) [--allow-unsafe-path]`)
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

- `probe_catalog` outputs JSON in `stdout`; use `<probe-id> --help` for per-probe usage (help text is returned in JSON `stdout`).
- Filesystem probes are safe-by-default: destructive direct-path operations are refused unless you target a harness path (for `fs_op`/`fs_coordinated_op` via `--path-class`/`--target`, or for `fs_xattr` via an explicit path under `*/entitlement-jail-harness/*`) or pass `--allow-unsafe-path` (or `--allow-write` for `fs_xattr`).
- `dlopen_external` loads and executes dylib initializers by design; use a signed test dylib.
- `--log-sandbox`/`--log-stream` writes a best-effort unified log excerpt filtered to `Sandbox:` lines for the probe PID (uses `log show`; absence of deny lines is not a denial claim).
- When `run-xpc` runs inside `EntitlementJail.app`, `/usr/bin/log` may be blocked by the app sandbox; log capture will report an error instead of a denial signal.
- `--hold-open` keeps the XPC connection open after the response to make debugger/trace attachment easier.
- `--log-sandbox`/`--log-predicate` must appear before `<xpc-service-bundle-id>`.
- `--log-predicate` overrides the default `log show` predicate (pass a full predicate string).

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
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' Tests/TestDylib/build.sh
EJ_DLOPEN_PATH="$PWD/Tests/TestDylib/out/testdylib.dylib" \
  ./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc com.yourteam.entitlement-jail.ProbeService_plugin_host_relaxed dlopen_external
```

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
- Always captures `spctl --status`.
- Optionally runs `spctl --assess --type execute` (assessment only; does not execute the file).

Do not run the observer from inside `EntitlementJail.app` (or any sandboxed parent), or you lose the “outside the sandbox” boundary and mix attribution.

## Optional debugger-side tool: `ej-inspector`

`ej-inspector` is a standalone CLI that checks a target’s codesign identity (Team ID + bundle id/prefix) before attempting `task_for_pid`. If allowed, it immediately deallocates the task port and exits; it does not attach or manipulate state.

Build:

```sh
cargo build --manifest-path runner/Cargo.toml --release --bin ej-inspector
```

Sign (optional but required for `task_for_pid` in most cases):

```sh
codesign --force --options runtime --timestamp --entitlements Inspector.entitlements -s "$ID" runner/target/release/ej-inspector
```

Usage:

```sh
runner/target/release/ej-inspector <pid> --team-id <TEAMID> --bundle-id-prefix com.yourteam.entitlement-jail.
```

Notes:

- The target must also carry `com.apple.security.get-task-allow` for debugger attach to succeed.
- If you omit `--bundle-id-prefix`/`--bundle-id`, the tool defaults to `com.yourteam.entitlement-jail.`.
- Use this tool outside the sandbox boundary; do not run it from inside `EntitlementJail.app`.

## Layer attribution model

This repo treats “what happened” and “why it happened” as separate questions.

- Seatbelt/App Sandbox layer:
  - `run-system` / `run-embedded` may fail due to `process-exec*` policy (but failure to launch is not automatically a sandbox denial).
  - `quarantine-lab` reports `seatbelt: process_exec_not_attempted` because it does not execute specimens.
- Quarantine/Gatekeeper layer:
  - `quarantine-lab` measures `com.apple.quarantine` before/after writing/opening/copying.
  - `quarantine-observer` can record `spctl` status and optional assessment results for the written specimen.
- “Other”:
  - Code signing validity, missing timestamps, path validation, file permissions, missing files, and launchd/XPC issues are not Seatbelt signals and must be reported distinctly.

## JSON outputs (high level)

XPC-backed commands print JSON to stdout (the sandboxed Rust launcher does not reformat it):

- `run-xpc` prints a `RunProbeResponse`-shaped JSON object and exits with `rc`.
- `quarantine-lab` prints a `QuarantineWriteResponse`-shaped JSON object and exits with `rc`.

For wire-format details and exact fields, see [xpc/README.md](../xpc/README.md).
