# EntitlementJail.app (User Guide)

EntitlementJail is a macOS research/teaching tool for exploring **App Sandbox + entitlements** without collapsing “couldn’t do X” into “the sandbox denied X”.

It is built around a **process zoo**: many embedded XPC services, each signed with a different entitlement profile. You run the *same probe* inside different services and compare the witness records.

This document assumes you have **only**:

- `EntitlementJail.app`
- this file (`EntitlementJail.md`)

No development workflows are required.

## Quick start

Set a convenience variable:

```sh
EJ="$PWD/EntitlementJail.app/Contents/MacOS/entitlement-jail"
```

Discover what’s inside:

```sh
$EJ list-profiles
$EJ list-services
$EJ describe-service minimal
```

Run an “observer” probe in the baseline service:

```sh
$EJ run-xpc --profile minimal capabilities_snapshot
```

Compare the same probe across a curated group:

```sh
$EJ run-matrix --group debug capabilities_snapshot
```

Make a service easier to attach to (lldb / dtrace / Frida) by holding it open:

```sh
$EJ run-xpc --attach 60 --profile debuggable probe_catalog
```

## The mental model (what you’re measuring)

### Process zoo

- A **profile** is a short id (like `minimal` or `fully_injectable`) that maps to one XPC service bundle id.
- Each XPC service is a separate **signed Mach‑O** with its own entitlements.
- Probes run **in-process** inside the service. This avoids the common “child exec from writable path” failure mode that dominates sandbox demos.

### Witness records (and attribution)

EntitlementJail records *what happened* (return codes, errno, paths, timing) and attaches “best-effort attribution hints”, but it avoids overclaiming:

- A permission-shaped failure (often `EPERM`/`EACCES`) is **not automatically** a sandbox denial.
- “Seatbelt/App Sandbox denial” is only attributed when there is **deny evidence** (for example, a matching `Sandbox:` unified log line for the service PID).
- Quarantine/Gatekeeper behavior is measured separately (Quarantine Lab does not execute anything).

## CLI overview

The CLI is a sandboxed executable embedded in the app:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail`

Top-level commands:

- `list-profiles` / `show-profile <id>`: profile discovery (including risk tier + entitlements)
- `list-services` / `describe-service <id>`: service discovery (static capabilities; no live probe)
- `run-xpc`: run a probe in a selected XPC service (primary workflow)
- `run-matrix`: run the same probe across a named group and emit a table + JSON bundle
- `health-check`: quick “does the process zoo respond” check
- `verify-evidence` / `inspect-macho` / `bundle-evidence`: evidence and inspection artifacts
- `quarantine-lab`: write/open/copy payloads and report quarantine deltas (no execution)
- `run-system` / `run-embedded`: legacy/demo surfaces (see safety notes)

Run `--help` on any command to see the exact argument syntax.

## Profiles (what services exist)

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

### Risk tiers

Profiles are grouped into three risk tiers:

- Tier 0: runs silently
- Tier 1: runs with a warning
- Tier 2: requires explicit acknowledgement: `--ack-risk <profile-id|bundle-id>`

This is about **guardrails**, not morality: Tier 2 profiles intentionally carry entitlements that widen instrumentation/injection surface.

### Shipped probe profiles (current build)

Use `list-profiles` as the source of truth. For convenience, the current build includes:

| Profile id | Focus | Tier |
| --- | --- | --- |
| `minimal` | baseline sandbox | 0 |
| `net_client` | network client | 0 |
| `downloads_rw` | Downloads read/write | 0 |
| `user_selected_executable` | user-selected executable | 0 |
| `bookmarks_app_scope` | bookmarks app-scope | 0 |
| `debuggable` | debug attach surface | 1 |
| `plugin_host_relaxed` | relaxed library validation | 1 |
| `dyld_env_enabled` | DYLD env variables allowed | 2 |
| `jit_map_jit` | `MAP_JIT` | 2 |
| `jit_rwx_legacy` | RWX executable memory | 2 |
| `fully_injectable` | “max” attach/inject | 2 |

There are also Quarantine Lab profiles (kind `quarantine`) such as `quarantine_default`, `quarantine_net_client`, and `quarantine_downloads_rw`.

## `run-xpc` (run probes in a service)

This is the primary workflow: pick a profile/service, run a probe, and get a JSON witness record.

Usage:

```sh
$EJ run-xpc [--profile <id>] [--ack-risk <id|bundle-id>]
            [--log-sandbox <path>|--log-stream <path>] [--log-predicate <predicate>]
            [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>]
            [--wait-fifo <path>|--wait-exists <path>] [--wait-path-class <class>] [--wait-name <name>]
            [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create]
            [--attach <seconds>] [--hold-open <seconds>]
            <xpc-service-bundle-id> <probe-id> [probe-args...]
```

Notes:

- Prefer `--profile <id>` and omit the explicit bundle id.
- Tier 2 profiles require `--ack-risk` (you can pass either the profile id or the full bundle id).
- `--log-sandbox` / `--log-stream` are best-effort unified log capture for `Sandbox:` lines. Absence of deny lines is not a denial claim.
- `--hold-open` keeps the service process alive after printing the JSON response.

Common probes (discoverable via `probe_catalog`):

```sh
$EJ run-xpc --profile minimal probe_catalog
$EJ run-xpc --profile minimal capabilities_snapshot
$EJ run-xpc --profile minimal fs_op --op stat --path-class tmp
$EJ run-xpc --profile net_client net_op --op tcp_connect --host 127.0.0.1 --port 9
```

### Attach-friendly waits (`--attach`, `--wait-*`)

Many XPC services start and exit quickly. For external tooling (lldb/dtrace/Frida), you usually want:

1. a deterministic “wait here” point before the interesting operation, and
2. a post-run hold so the process stays alive while you inspect it.

`--attach <seconds>` is the ergonomic path:

```sh
$EJ run-xpc --attach 60 --profile debuggable probe_catalog
```

The client prints a line like:

```
[client] wait-ready mode=fifo wait_path=/.../wait-ready.fifo
```

Trigger the probe by writing to the FIFO:

```sh
printf go > /path/from/wait-ready.fifo
```

If you prefer controlling the wait path explicitly:

- `--wait-fifo <path>` blocks until a writer connects
- `--wait-exists <path>` polls until a file exists
- `--wait-path-class`/`--wait-name` let the service choose a path under its own container directories

Wait metadata is recorded in `data.details` (`wait_*` fields).

### Sandbox log capture (deny evidence)

Some probes return a permission-shaped failure (often `EPERM`/`EACCES`). That is *compatible with* a sandbox denial, but it is not proof of one.

If you want deny evidence for a specific run, request log capture:

```sh
$EJ run-xpc --log-sandbox /tmp/ej-sandbox.log --profile minimal fs_op --op stat --path-class tmp
```

Interpretation rules:

- If log capture was requested, check `data.log_capture_status` and `data.log_capture_error`.
- If log capture was not requested, `data.deny_evidence` is set to `not_captured`.
- Log capture may fail from inside the sandbox boundary (for example, if `/usr/bin/log` is blocked); treat that as “no deny evidence captured”, not as a Seatbelt signal.

## `run-matrix` (compare a probe across a group)

`run-matrix` runs one probe across a named group of profiles and writes:

- a compare table (`run-matrix.table.txt`)
- a full JSON report (`run-matrix.json`)

Usage:

```sh
$EJ run-matrix --group <baseline|debug|inject|jit> [--out <dir>] [--ack-risk <id|bundle-id>] <probe-id> [probe-args...]
```

Examples:

```sh
$EJ run-matrix --group baseline capabilities_snapshot
$EJ run-matrix --group debug capabilities_snapshot
```

Tier 2 profiles are skipped unless you pass `--ack-risk`.

Default output directory (overwritten each run):

```
~/Library/Application Support/entitlement-jail/matrix/latest
```

## Evidence and inspection

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

Tip: to inspect a specific service binary by bundle id:

```sh
$EJ show-profile minimal
$EJ inspect-macho <bundle_id_from_show_profile_output>
```

`bundle-evidence` collects these files plus JSON reports into one directory (overwritten each run):

```
~/Library/Application Support/entitlement-jail/evidence/latest
```

### Verifying sandboxing and signatures (optional)

The “ground truth” for sandbox/entitlements is the signature metadata on each Mach‑O:

- Main CLI: `EntitlementJail.app/Contents/MacOS/entitlement-jail`
- XPC services: `EntitlementJail.app/Contents/XPCServices/*.xpc/Contents/MacOS/*`

Useful commands:

```sh
codesign -d --entitlements :- EntitlementJail.app
codesign -d --entitlements :- EntitlementJail.app/Contents/XPCServices/ProbeService_debuggable.xpc/Contents/MacOS/ProbeService_debuggable
codesign --verify --deep --strict --verbose=2 EntitlementJail.app
spctl -a -vv EntitlementJail.app
```

You can also inspect entitlements via the CLI profiles:

```sh
$EJ show-profile debuggable
$EJ describe-service debuggable
```

## Quarantine Lab (`quarantine-lab`)

Quarantine Lab writes/opens/copies payloads and reports `com.apple.quarantine` deltas.

Hard rule: it does **not** execute payloads.

Usage:

```sh
$EJ quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
```

Payload classes:

- `shell_script` | `command_file` | `text` | `webarchive_like`

Selected options:

- `--operation <create_new|open_only|open_existing_save>`
- `--existing-path <path>`
- `--dir <tmp|app_support>`
- `--name <file-name>`
- `--exec | --no-exec` (sets/unsets the executable bit on the written file)

For the full option list, run:

```sh
EntitlementJail.app/Contents/MacOS/xpc-quarantine-client --help
```

## Output format (uniform JSON envelope)

All commands that emit JSON use the same envelope:

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
- `run-xpc` and `quarantine-lab` use `result.rc`; other commands use `result.exit_code`.
- Command-specific fields live under `data` (no extra top-level keys).

For `run-xpc`, the most useful attachment keys are:

- `data.service_bundle_id`
- `data.service_name`
- `data.details.service_pid` (or `data.details.probe_pid`)

## Safety notes

- `run-system` runs **platform binaries only** (allowlisted to standard system prefixes). It exists for specific demonstrations; most work should use `run-xpc`.
- `run-embedded` runs signed helper tools embedded in the app bundle (sandbox inheritance demonstrations). It does not run arbitrary on-disk tools by path.
- `dlopen_external` executes dylib initializers by design. Treat it as code execution and use it intentionally.
- If you did not capture deny evidence, do not claim “sandbox denied”; keep attribution explicit.
