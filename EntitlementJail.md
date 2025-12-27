# EntitlementJail.app (User Guide)

EntitlementJail is a macOS research/teaching tool for exploring **App Sandbox + entitlements** while keeping “what happened” separate from “why it happened”.

It ships as an app bundle containing:

- a host-side CLI launcher (plain-signed; not sandboxed), and
- a process zoo of separately signed sandboxed XPC services (each with its own entitlement profile).

This guide assumes you have only `EntitlementJail.app` and this file (`EntitlementJail.md`).

## Contents

- Router (start here)
- Quick start
- Concepts
- Workflows
- Output format (JSON)
- Safety notes

## Router (start here)

- Sanity check: `health-check`
- Discovery: `list-profiles`, `list-services`, `show-profile`, `describe-service`
- Run one probe (one-shot): `xpc run --profile <id> <probe-id> [probe-args...]`
- Deterministic debugger attach + multiple probes: `xpc session --profile fully_injectable ...`
- Compare across profiles: `run-matrix --group <...> <probe-id> [probe-args...]`
- Evidence bundle: `bundle-evidence` (plus `verify-evidence`, `inspect-macho`)
- Quarantine/Gatekeeper deltas (no execution): `quarantine-lab`
- Deny evidence (outside the sandbox boundary): `EntitlementJail.app/Contents/MacOS/sandbox-log-observer`

## Quick start

Set a convenience variable:

```sh
EJ="$PWD/EntitlementJail.app/Contents/MacOS/entitlement-jail"
```

Discover what’s inside:

```sh
$EJ list-profiles
$EJ list-services
$EJ show-profile minimal
```

Run a probe in the baseline sandbox profile:

```sh
$EJ xpc run --profile minimal capabilities_snapshot
```

Compare the same probe across a curated group:

```sh
$EJ run-matrix --group debug capabilities_snapshot
```

Create a harness file and set an xattr (extract `data.details.file_path` without `jq`):

```sh
$EJ xpc run --profile minimal fs_op --op create --path-class tmp --target specimen_file --name ej_xattr.txt > /tmp/ej_fs_op.json
FILE_PATH=$(plutil -extract data.details.file_path raw -o - /tmp/ej_fs_op.json)
$EJ xpc run --profile minimal fs_xattr --op set --path "$FILE_PATH" --name user.ej --value test
```

## Concepts

### Process zoo

- A **profile** is a short id (like `minimal` or `fully_injectable`) that maps to one XPC service bundle id.
- Each XPC service is a separate **signed Mach‑O** with its own entitlements.
- Probes run **in-process** inside the service. This avoids the common “exec from a writable/container path” failure mode that dominates many sandbox demos.

### Witness records (and attribution)

EntitlementJail records *what happened* (return codes, errno, resolved paths, timing) and may attach attribution hints, but it avoids overclaiming:

- A permission-shaped failure (often `EPERM`/`EACCES`) is **not automatically** a sandbox denial.
- “Seatbelt/App Sandbox denial” is an attribution claim that requires evidence (for example, a matching unified-log denial line for the service PID).
- Quarantine/Gatekeeper behavior is measured separately (Quarantine Lab does not execute anything).

### Two XPC modes: one-shot vs session

- `xpc run` is one-shot (open session → run one probe → close session).
- `xpc session` keeps the service alive across multiple probes and emits explicit lifecycle events so attach/debug tooling can coordinate deterministically.

## Workflows

All workflows use the CLI at `EntitlementJail.app/Contents/MacOS/entitlement-jail` (the quick start sets `EJ` to this path). Run `$EJ --help` to see the command list and the canonical invocation shapes.

### Discover profiles and services

Profiles are the ergonomic interface for the process zoo.

List them:

```sh
$EJ list-profiles
```

Inspect a profile (entitlements, risk tier, tags):

```sh
$EJ show-profile fully_injectable
```

Inspect a service “statically” (what the profile says it should have):

```sh
$EJ describe-service fully_injectable
```

**Risk tiers**

- Tier 0: runs silently
- Tier 1: runs with a warning
- Tier 2: requires explicit acknowledgement: `--ack-risk <profile-id|bundle-id>`

This is about guardrails, not morality: Tier 2 profiles intentionally carry entitlements that widen instrumentation/injection surface.

**Profiles you’ll likely see**

Use `list-profiles` as the source of truth. Some common ids include: `minimal`, `net_client`, `downloads_rw`, `bookmarks_app_scope`, `get-task-allow`, and `fully_injectable`.

For debugging/injection, the two profiles to know are:

- `get-task-allow`: App Sandbox + `com.apple.security.get-task-allow` + `com.apple.security.cs.disable-library-validation` (Tier 1).
- `fully_injectable`: `get-task-allow` + `disable-library-validation` + `allow-dyld-environment-variables` + `allow-jit` + `allow-unsigned-executable-memory` (Tier 2).

There are also Quarantine Lab profiles (kind `quarantine`) such as `quarantine_default`, `quarantine_net_client`, `quarantine_downloads_rw`, `quarantine_user_selected_executable`, and `quarantine_bookmarks_app_scope`.

### Run probes in a service (`xpc run`)

Pick a profile/service, run one probe, and get a JSON witness record.

Usage:

```sh
$EJ xpc run (--profile <id> | --service <bundle-id>)
            [--ack-risk <id|bundle-id>]
            [--plan-id <id>] [--row-id <id>] [--correlation-id <id>]
            <probe-id> [probe-args...]
```

Notes:

- Prefer `--profile <id>` and omit the explicit bundle id.
- Tier 2 profiles require `--ack-risk` (you can pass either the profile id or the full bundle id).
- `xpc run` is intentionally one-shot. For deterministic attach and multi-probe workflows, use `xpc session`.

Common probes:

```sh
$EJ xpc run --profile minimal probe_catalog
$EJ xpc run --profile minimal capabilities_snapshot
$EJ xpc run --profile minimal fs_op --op stat --path-class tmp
$EJ xpc run --profile net_client net_op --op tcp_connect --host 127.0.0.1 --port 9
$EJ xpc run --profile fully_injectable --ack-risk fully_injectable sandbox_check --operation file-read-data --path /etc/hosts
```

### Deterministic debugger attach (`xpc session`)

`xpc session` is a session-based XPC control plane intended for tooling like lldb/dtrace/Frida. It provides explicit lifecycle events and keeps the service alive across multiple probes so you can attach once and then iterate.

Usage:

```sh
$EJ xpc session (--profile <id> | --service <bundle-id>)
                [--ack-risk <id|bundle-id>]
                [--plan-id <id>] [--correlation-id <id>]
                [--wait <fifo:auto|fifo:/abs|exists:/abs>]
                [--wait-timeout-ms <n>] [--wait-interval-ms <n>]
                [--xpc-timeout-ms <n>]
```

I/O contract:

- Stdout is JSONL (one JSON envelope per line):
  - Lifecycle: `kind: xpc_session_event` / `kind: xpc_session_error`
  - Probes: `kind: probe_response` (one per `run_probe` command)
- Stdin is JSONL commands (one object per line):
  - `{"command":"run_probe","probe_id":"...","argv":[...]}`
  - `{"command":"keepalive"}`
  - `{"command":"close_session"}`

Lifecycle events you’ll commonly see:

- `session_ready` — session opened; includes `data.pid` and an opaque `data.session_token`
- `wait_ready` — wait barrier configured; includes `data.wait_path`
- `trigger_received` — wait barrier satisfied; safe point to start probes
- `probe_starting` / `probe_done` — per-probe execution bracketing
- `session_closed` — explicit close

If a wait is configured, probes are refused until the trigger is received (you’ll get a normal `probe_response` with `normalized_outcome: session_not_triggered`).

Attach workflow (high level):

1. Start a session with `--wait fifo:auto`.
2. Watch stdout for `data.event == "wait_ready"` and capture `data.pid` + `data.wait_path`.
3. Attach your tooling to `data.pid` and install hooks (before any probe runs).
4. Trigger the wait by writing to the FIFO at `data.wait_path` (for example `printf go > "$WAIT_PATH"`).
5. Send `run_probe` commands over stdin JSONL.

### Deny evidence (`sandbox-log-observer`)

Some probes return permission-shaped failures. If you want deny evidence, run the embedded observer tool outside the sandbox boundary and treat its output as an *evidence attachment*.

The observer requires a PID and process name. You can get them from:

- a `probe_response` (`data.details.pid` + `data.details.process_name`), or
- an `xpc_session_event` (`data.pid` + `data.service_name`).

One-shot pairing example:

```sh
$EJ xpc run --profile minimal fs_op --op stat --path-class tmp > /tmp/ej_probe.json
PID=$(plutil -extract data.details.pid raw -o - /tmp/ej_probe.json)
NAME=$(plutil -extract data.details.process_name raw -o - /tmp/ej_probe.json)
EntitlementJail.app/Contents/MacOS/sandbox-log-observer --pid "$PID" --process-name "$NAME" --last 10s
```

Observer usage (summary):

- Windowed (`log show`, default): `--last 5s` or explicit `--start`/`--end`
- Live (`log stream`): `--duration <seconds>` or `--follow`
- Output: `--format json` (default) or `--format jsonl` (events + final report); optional copy via `--output <path>`

### Compare a probe across a group (`run-matrix`)

`run-matrix` runs one probe across a named group of profiles and writes:

- a compare table (`run-matrix.table.txt`)
- a full JSON report (`run-matrix.json`)

Usage:

```sh
$EJ run-matrix --group <baseline|debug|inject> [--out <dir>] [--ack-risk <id|bundle-id>] <probe-id> [probe-args...]
```

Examples:

```sh
$EJ run-matrix --group baseline capabilities_snapshot
$EJ run-matrix --group debug capabilities_snapshot
```

Tier 2 profiles are skipped unless you pass `--ack-risk`.

Groups (current build; use `list-profiles` as the source of truth):

- `baseline`: `minimal`
- `debug`: `minimal`, `get-task-allow`
- `inject`: `minimal`, `fully_injectable` (Tier 2 requires `--ack-risk`)

Default output directory (per group, overwritten each run; see `data.output_dir`):

```
~/Library/Application Support/entitlement-jail/matrix/<group>/latest
```

### Evidence and inspection

EntitlementJail ships “static evidence” inside the app bundle:

- `Contents/Resources/Evidence/manifest.json` (hashes + entitlements for key Mach‑Os)
- `Contents/Resources/Evidence/symbols.json` (stable `ej_*` marker symbols for tooling)
- `Contents/Resources/Evidence/profiles.json` (the process zoo profiles and entitlements)

Commands:

```sh
$EJ verify-evidence
$EJ inspect-macho main
$EJ inspect-macho evidence.symbols
$EJ inspect-macho evidence.profiles
$EJ bundle-evidence
```

Default evidence bundle output directory (overwritten each run; see `data.output_dir`):

```
~/Library/Application Support/entitlement-jail/evidence/latest
```

### Quarantine Lab (`quarantine-lab`)

Quarantine Lab writes/opens/copies payloads and reports `com.apple.quarantine` deltas.

Hard rule: it does **not** *run* payloads (no `execve`, no `posix_spawn`). Note that the `--exec` flag (shown in `xpc-quarantine-client --help`) means “mark the written file executable” (`chmod +x`), not “execute it”.

Usage:

```sh
$EJ quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
```

Choosing a service id:

- Run `$EJ list-profiles` and look for Quarantine Lab profiles (often `quarantine_*`).
- Run `$EJ show-profile <id>` and copy `data.profile.bundle_id` into the `quarantine-lab` invocation.

Example:

```sh
$EJ show-profile quarantine_default
$EJ quarantine-lab <bundle_id_from_show_profile> shell_script --dir tmp
```

Payload classes:

- `shell_script` | `command_file` | `text` | `webarchive_like`

For the full option list, run:

```sh
EntitlementJail.app/Contents/MacOS/xpc-quarantine-client --help
```

## Output format (JSON)

All commands that emit JSON use the same top-level envelope:

```json
{
  "schema_version": 2,
  "kind": "probe_response",
  "generated_at_unix_ms": 1700000000000,
  "result": {
    "ok": true,
    "normalized_outcome": "ok",
    "rc": 0
  },
  "data": {}
}
```

Rules:

- Keys are lexicographically sorted for stability.
- `xpc run` and `quarantine-lab` use `result.rc`; report-style commands use `result.exit_code`.
- Some `result` fields are omitted when empty/not-applicable (for example `errno`, `stderr`, `stdout`), and some reports include them as `null`.
- Command-specific fields live under `data` (no extra top-level keys).
- `xpc session` emits one envelope per line (JSONL): lifecycle events (`xpc_session_event` / `xpc_session_error`) plus `probe_response` lines for each probe you run in the session.

What to read first:

- Outcome: `result.ok`, `result.normalized_outcome`, plus `result.errno`/`result.error` if not ok.
- Service identity: `data.service_bundle_id`, `data.service_name` (for probe responses), and `data.pid` (for session events).
- “What path did it use?”: `data.details.file_path` (common for filesystem probes like `fs_op`/`fs_xattr`).

Quick extraction without `jq` (macOS ships `plutil`):

```sh
plutil -extract result.normalized_outcome raw -o - report.json
plutil -extract data.details.pid raw -o - report.json
plutil -extract data.details.process_name raw -o - report.json
```

## Safety notes

- `run-system` runs **platform binaries only** (allowlisted to standard system prefixes). It exists for specific demonstrations; most work should use XPC services (`xpc run` / `xpc session`).
- `run-embedded` runs signed helper tools embedded in the app bundle. It does not run arbitrary on-disk tools by path.
- `dlopen_external` executes dylib initializers by design. Treat it as code execution and use it intentionally.
- If you did not capture deny evidence, do not claim “sandbox denied”; keep attribution explicit.
