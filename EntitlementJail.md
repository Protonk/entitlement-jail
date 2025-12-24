# EntitlementJail.app (User Guide)

EntitlementJail is a macOS research/teaching tool for exploring **App Sandbox + entitlements** without collapsing “couldn’t do X” into “the sandbox denied X”.
It ships as an app bundle containing a sandboxed CLI launcher plus a process zoo of XPC services (each separately signed with different entitlements).

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
- Run one probe: `run-xpc --profile <id> <probe-id> [probe-args...]`
- Compare across profiles: `run-matrix --group <...> <probe-id> [probe-args...]`
- Evidence bundle: `bundle-evidence` (plus `verify-evidence`, `inspect-macho`)
- Quarantine/Gatekeeper deltas (no execution): `quarantine-lab`
- Output locations: defaults live under the app container (prefix like `~/Library/Containers/com.yourteam.entitlement-jail/Data/...`). Trust `data.output_dir` in JSON reports.
- Deny evidence: `--log-*` capture may fail (“Cannot run while sandboxed”); use `sandbox-log-observer` outside the sandbox boundary if you have the source repo.

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

Create a harness file and set an xattr (extract `data.details.file_path` without `jq`):

```sh
$EJ run-xpc --profile minimal fs_op --op create --path-class tmp --target specimen_file --name ej_xattr.txt > /tmp/ej_fs_op.json
FILE_PATH=$(plutil -extract data.details.file_path raw -o - /tmp/ej_fs_op.json)
$EJ run-xpc --profile minimal fs_xattr --op set --path "$FILE_PATH" --name user.ej --value test
```

Make a service easier to attach to (lldb / dtrace / Frida) by holding it open:

```sh
$EJ run-xpc --attach 60 --profile debuggable probe_catalog
```

## Concepts

**Process zoo**

- A **profile** is a short id (like `minimal` or `fully_injectable`) that maps to one XPC service bundle id.
- Each XPC service is a separate **signed Mach‑O** with its own entitlements.
- Probes run **in-process** inside the service. This avoids the common “child exec from writable path” failure mode that dominates sandbox demos.

**Witness records (and attribution)**

EntitlementJail records *what happened* (return codes, errno, paths, timing) and attaches “best-effort attribution hints”, but it avoids overclaiming:

- A permission-shaped failure (often `EPERM`/`EACCES`) is **not automatically** a sandbox denial.
- “Seatbelt/App Sandbox denial” is only attributed when there is **deny evidence** (for example, a matching `Sandbox:` unified log line for the service PID).
- Quarantine/Gatekeeper behavior is measured separately (Quarantine Lab does not execute anything).

## Workflows
All workflows use the sandboxed CLI at `EntitlementJail.app/Contents/MacOS/entitlement-jail` (the quick start sets `EJ` to this path). Run `--help` on any command to see the exact argument syntax.

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

This is about **guardrails**, not morality: Tier 2 profiles intentionally carry entitlements that widen instrumentation/injection surface.

**Profiles you’ll likely see**

Use `list-profiles` as the source of truth. Some common ids include: `minimal`, `net_client`, `downloads_rw`, `bookmarks_app_scope`, `debuggable`, and `fully_injectable`.

There are also Quarantine Lab profiles (kind `quarantine`) such as `quarantine_default`, `quarantine_net_client`, and `quarantine_downloads_rw`.

### Run probes in a service (`run-xpc`)

This is the primary workflow: pick a profile/service, run a probe, and get a JSON witness record.

Usage:

```sh
$EJ run-xpc [--ack-risk <id|bundle-id>]
            [--log-sandbox <path>|--log-stream <path>|--log-path-class <class> --log-name <name>] [--log-predicate <predicate>]
            [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>]
            [--wait-fifo <path>|--wait-exists <path>|--wait-path-class <class> --wait-name <name>]
            [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create]
            [--attach <seconds>] [--hold-open <seconds>]
            (--profile <id> | <xpc-service-bundle-id>) <probe-id> [probe-args...]
```

Notes:

- Prefer `--profile <id>` and omit the explicit bundle id.
- Tier 2 profiles require `--ack-risk` (you can pass either the profile id or the full bundle id).
- `--log-sandbox` / `--log-stream` / `--log-path-class` are best-effort unified log capture for `Sandbox:` lines. Absence of deny lines is not a denial claim.
- `--log-path-class` + `--log-name` writes the capture file under the service container (useful when repo paths are blocked).
- `--hold-open` keeps the service process alive after printing the JSON response.
- `--attach <seconds>` sets up a FIFO wait and, by default, also sets `--hold-open <seconds>` (so wall time can approach `2*seconds` if you trigger near the timeout). For automation/harnesses, consider `--hold-open 0`.

Common probes (discoverable via `probe_catalog`):

```sh
$EJ run-xpc --profile minimal probe_catalog
$EJ run-xpc --profile minimal capabilities_snapshot
$EJ run-xpc --profile minimal fs_op --op stat --path-class tmp
$EJ run-xpc --profile net_client net_op --op tcp_connect --host 127.0.0.1 --port 9
```

**Attach-friendly waits (`--attach`, `--wait-*`)**

Many XPC services start and exit quickly. For external tooling (lldb/dtrace/Frida), you usually want:

1. a deterministic “wait here” point before the interesting operation, and
2. a post-run hold so the process stays alive while you inspect it.

`--attach <seconds>` is the ergonomic path:

```sh
$EJ run-xpc --attach 60 --profile debuggable probe_catalog
$EJ run-xpc --attach 5 --hold-open 0 --profile debuggable probe_catalog
```

The client prints a line like:

```
[client] wait-ready mode=fifo wait_path=/.../wait-ready.fifo
```

Trigger the probe by writing to the FIFO:

```sh
printf go > /path/from/wait-ready.fifo
```

FIFO waits are one-shot: after the wait is released, the FIFO may have no reader. A second **nonblocking** writer open can fail with `ENXIO` (“Device not configured”).

If you prefer controlling the wait path explicitly:

- `--wait-fifo <path>` blocks until a writer connects
- `--wait-exists <path>` polls until a file exists
- `--wait-path-class`/`--wait-name` let the service choose a path under its own container directories
- If you use `--wait-path-class`/`--wait-name`, it implies a FIFO wait and will create the FIFO.
- If you use `--wait-fifo`, pass `--wait-create` (or create the FIFO yourself) so the wait path exists.

Wait metadata is recorded in `data.details` (`wait_*` fields).

**Sandbox log capture (deny evidence)**

Some probes return a permission-shaped failure (often `EPERM`/`EACCES`). That is *compatible with* a sandbox denial, but it is not proof of one.

If you want deny evidence for a specific run, request log capture:

```sh
$EJ run-xpc --log-sandbox /tmp/ej-sandbox.log --profile minimal fs_op --op stat --path-class tmp
$EJ run-xpc --log-path-class tmp --log-name ej-sandbox.log --profile minimal fs_op --op stat --path-class tmp
```

Interpretation rules:

- If log capture was requested, check `data.log_capture_status` and `data.log_capture_error`.
- If log capture was not requested, `data.deny_evidence` is set to `not_captured`.
- Log capture may fail from inside the sandbox boundary (for example, if `/usr/bin/log` is blocked); treat that as "no deny evidence captured", not as a Seatbelt signal. In that case the capture file may exist but be empty.
- If you have the source repo, use `sandbox-log-observer` outside the sandbox boundary to capture a `Sandbox:` excerpt by PID.
- Use `data.details.service_pid` (or `data.details.probe_pid`) plus `data.details.process_name` as inputs.

**Filesystem probes (fs_op, fs_xattr, fs_coordinated_op)**

Some probes expect a **file** path, not a directory. In particular:

- `fs_op --target run_dir` and `fs_op --target harness_dir` resolve to directories.
- `fs_op --target specimen_file` resolves to a file path under `*/entitlement-jail-harness/*`, but the file is only created by ops like `create` or `open_write` (not by `stat`).
- `fs_xattr` write/remove operations are refused outside harness paths unless you pass `--allow-write` or `--allow-unsafe-path`.

A reliable pattern for `fs_xattr` is:

```sh
$EJ run-xpc --profile minimal fs_op --op create --path-class tmp --target specimen_file --name ej_xattr.txt > /tmp/ej_fs_op.json
FILE_PATH=$(plutil -extract data.details.file_path raw -o - /tmp/ej_fs_op.json)
$EJ run-xpc --profile minimal fs_xattr --op set --path "$FILE_PATH" --name user.ej --value test
```

**Bookmark probes (bookmark_make, bookmark_roundtrip)**

`bookmark_make` and `bookmark_roundtrip` use security-scoped bookmarks by default. Profiles without `com.apple.security.files.bookmarks.app-scope` (for example `minimal`) will typically return a `service_refusal` with `entitlement_missing_bookmarks_app_scope`. That is an expected negative witness, not a sandbox denial. If you want a non-security-scoped run, pass `--no-security-scope`.

### Compare a probe across a group (`run-matrix`)

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

Groups (current build; use `list-profiles` as the source of truth):

- `baseline`: `minimal`
- `debug`: `minimal`, `debuggable`
- `inject`: `minimal`, `plugin_host_relaxed`, `dyld_env_enabled`, `fully_injectable` (Tier 2 requires `--ack-risk`)
- `jit`: `minimal`, `jit_map_jit`, `jit_rwx_legacy` (Tier 2 requires `--ack-risk`)

Default output directory (overwritten each run; see `data.output_dir`):

```
~/Library/Containers/com.yourteam.entitlement-jail/Data/Library/Application Support/entitlement-jail/matrix/latest
```

If you pass `--out`, choose a container-writable path; repo paths are typically blocked from inside the sandbox.

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

Tip: to inspect a specific service binary by bundle id:

```sh
$EJ show-profile minimal
$EJ inspect-macho <bundle_id_from_show_profile_output>
```

`bundle-evidence` collects these files plus JSON reports into one directory (overwritten each run):

```
~/Library/Containers/com.yourteam.entitlement-jail/Data/Library/Application Support/entitlement-jail/evidence/latest
```

If you pass `--out`, choose a container-writable path; repo paths are typically blocked from inside the sandbox.

Optional: if you need to audit entitlements/signing, treat `show-profile`/`describe-service` as convenience views and `codesign -d --entitlements :- <mach-o>` as the ground truth. (This is inspection only; it does not execute anything.)

### Quarantine Lab (`quarantine-lab`)

Quarantine Lab writes/opens/copies payloads and reports `com.apple.quarantine` deltas.

Hard rule: it does **not** execute payloads.

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

## Output format (JSON)

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

What to read first:

- Outcome: `result.ok`, `result.normalized_outcome`, plus `result.errno`/`result.error` if not ok.
- Service identity: `data.service_bundle_id`, `data.service_name`.
- “Where did it write?”: `data.output_dir` (for commands like `run-matrix` and `bundle-evidence`).
- “What path did it use?”: `data.details.file_path` (common for filesystem probes like `fs_op`/`fs_xattr`).
- Log capture: `data.log_capture_status`, `data.log_capture_error`, and `data.deny_evidence`.
- Observer inputs: `data.details.service_pid` (or `data.details.probe_pid`) and `data.details.process_name`.

Quick extraction without `jq` (macOS ships `plutil`):

```sh
plutil -extract result.normalized_outcome raw -o - report.json
plutil -extract data.output_dir raw -o - report.json
plutil -extract data.details.file_path raw -o - report.json
```

## Safety notes

- `run-system` runs **platform binaries only** (allowlisted to standard system prefixes). It exists for specific demonstrations; most work should use `run-xpc`.
- `run-embedded` runs signed helper tools embedded in the app bundle (sandbox inheritance demonstrations). It does not run arbitrary on-disk tools by path.
- `dlopen_external` executes dylib initializers by design. Treat it as code execution and use it intentionally.
- If you did not capture deny evidence, do not claim “sandbox denied”; keep attribution explicit.
