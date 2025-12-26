# EntitlementJail.app (User Guide)

EntitlementJail is a macOS research/teaching tool for exploring **App Sandbox + entitlements** without collapsing “couldn’t do X” into “the sandbox denied X”.
It ships as an app bundle containing a host-side CLI launcher (plain-signed; not sandboxed) plus a process zoo of sandboxed XPC services (each separately signed with different entitlements).

This guide assumes you have only `EntitlementJail.app` and this file (`EntitlementJail.md`).

## Contents

- Router (start here)
- Quick start
- Concepts
- Logging & Evidence (quick reference)
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
- Output locations: defaults live under `~/Library/Application Support/entitlement-jail/...`. If you run a sandboxed build, the same relative paths will be under `~/Library/Containers/<bundle-id>/Data/...`. Trust `data.output_dir` in JSON reports.
- Deny evidence: prefer `--observe` (observer-first); `--log-stream` also runs the observer automatically, or run the embedded observer `EntitlementJail.app/Contents/MacOS/sandbox-log-observer` from Terminal.

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

Request deny evidence capture for a run (observer-first; stream optional):

```sh
$EJ run-xpc --observe --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9
$EJ run-xpc --log-stream /tmp/ej-sandbox.log --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9
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
$EJ run-xpc --attach 60 --profile get-task-allow probe_catalog
```

## Concepts

**Process zoo**

- A **profile** is a short id (like `minimal` or `fully_injectable`) that maps to one XPC service bundle id.
- Each XPC service is a separate **signed Mach‑O** with its own entitlements.
- Probes run **in-process** inside the service. This avoids the common “child exec from writable path” failure mode that dominates sandbox demos.

**Witness records (and attribution)**

EntitlementJail records *what happened* (return codes, errno, paths, timing) and attaches “best-effort attribution hints”, but it avoids overclaiming:

- A permission-shaped failure (often `EPERM`/`EACCES`) is **not automatically** a sandbox denial.
- “Seatbelt/App Sandbox denial” is only attributed when there is **deny evidence** (for example, a matching unified log denial line for the service PID, often containing `deny` / `Sandbox:`).
- Quarantine/Gatekeeper behavior is measured separately (Quarantine Lab does not execute anything).

## Logging & Evidence (quick reference)

This section is the short version of log capture and deny evidence. For full context, see the "Sandbox log capture (deny evidence)" subsection under Workflows.

**Best-practice command patterns**

Observer-only (windowed log show, default):

```sh
$EJ run-xpc --observe --profile minimal fs_op --op stat --path-class tmp
```

Observer live stream with JSONL output (auto path):

```sh
$EJ run-xpc --observe --observer-duration 2 --observer-format jsonl --observer-output auto --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9
```

If the PID is not available in time, the observer falls back to windowed `log show`; check `data.log_observer_report.data.mode`.

Stream capture to file (observer runs automatically):

```sh
$EJ run-xpc --log-stream auto --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9
```

Stream report to stdout (probe JSON goes to file):

```sh
$EJ run-xpc --log-stream stdout --json-out /tmp/ej_probe.json --profile minimal net_op --op tcp_connect --host 127.0.0.1 --port 9
```

Standalone observer (outside the sandbox boundary):

```sh
EntitlementJail.app/Contents/MacOS/sandbox-log-observer --pid <pid> --process-name <name> --last 5s
```

**Report types**

| Report kind | Produced by | Where to find it |
| --- | --- | --- |
| `sandbox_log_stream_report` | `run-xpc --log-stream` | file at `data.log_capture_path` (or stdout when `--log-stream stdout`) |
| `sandbox_log_observer_report` | `run-xpc --observe` or `sandbox-log-observer` | file at `data.log_observer_path`, and embedded in `data.log_observer_report` |

**Status fields and values**

- `deny_evidence`: `not_captured`, `captured`, `not_found`, `log_error`
  - `captured` means the stream or observer matched a deny line for the PID/process.
  - `not_found` means capture ran but no deny line matched.
- `log_capture_status`: `not_requested`, `requested_written`, `requested_failed`
- `log_observer_status`: `not_requested`, `requested_written`, `requested_failed`

**Output locations and extensions**

- `data.log_capture_path` points to a JSON file containing a single `sandbox_log_stream_report` envelope (or `stdout`/`-` when `--log-stream stdout` is used).
- `data.log_observer_path` points to a JSON or JSONL file depending on `--observer-format`:
  - `json` -> `.json` (single report envelope)
  - `jsonl` -> `.jsonl` (one `sandbox_log_observer_event` per line plus a final `sandbox_log_observer_report`)

**Stdout vs file output**

- With `--log-stream stdout`, the stream report is written to stdout and the probe JSON must go to `--json-out`.
- Observer output always goes to a file path (`--observer-output` or auto).

**Troubleshooting quick hits**

- `permission_error` with `deny_evidence=not_found` means no deny line was captured. Treat attribution as unknown: check `data.log_capture_error` / `data.log_observer_error`, verify the path exists, and rerun with `--observe --observer-duration <seconds>` or a standalone observer if needed.
- `deny_evidence=captured` but you cannot find a Sandbox line: check `data.log_observer_deny_lines` and the `sandbox_log_stream_report`. The deny line may not include the literal `Sandbox:` prefix, or it may appear only in one of the two reports.

Follow‑up recipe for downloads path class (“permission_error with no deny evidence”):
1) Re-run the same probe under `downloads_rw` or a `user_selected_*` profile (see `list-profiles`) to see if the outcome flips (entitlement-sensitive signal).
2) Widen the observer window (`--observer-duration 5` or `--observer-follow`) to reduce missed denies.
3) Inspect the resolved target path (`data.details.base_dir`, `data.details.file_path`, `data.details.path_class`) to verify what the probe actually touched.

## Workflows
All workflows use the CLI at `EntitlementJail.app/Contents/MacOS/entitlement-jail` (the quick start sets `EJ` to this path). Run `--help` on any command to see the exact argument syntax.

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

Use `list-profiles` as the source of truth. Some common ids include: `minimal`, `net_client`, `downloads_rw`, `bookmarks_app_scope`, `get-task-allow`, and `fully_injectable`.

For debugging/injection, the two profiles to know are:

- `get-task-allow`: App Sandbox + `com.apple.security.get-task-allow` + `com.apple.security.cs.disable-library-validation` (Tier 1).
- `fully_injectable`: `get-task-allow` + `disable-library-validation` + `allow-dyld-environment-variables` + `allow-jit` + `allow-unsigned-executable-memory` (Tier 2).

There are also Quarantine Lab profiles (kind `quarantine`) such as `quarantine_default`, `quarantine_net_client`, `quarantine_downloads_rw`, `quarantine_user_selected_executable`, and `quarantine_bookmarks_app_scope`.

### Run probes in a service (`run-xpc`)

This is the primary workflow: pick a profile/service, run a probe, and get a JSON witness record.

Usage:

```sh
$EJ run-xpc [--ack-risk <id|bundle-id>]
            [--log-stream <path|auto|stdout>|--log-path-class <class> --log-name <name>] [--log-predicate <predicate>]
            [--observe] [--observer-duration <seconds>] [--observer-format <json|jsonl>] [--observer-output <path|auto>] [--observer-follow]
            [--json-out <path>]
            [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>]
            [--wait-fifo <path>|--wait-exists <path>|--wait-path-class <class> --wait-name <name>]
            [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create]
            [--attach <seconds>] [--hold-open <seconds>] [--xpc-timeout-ms <n>]
            (--profile <id> | <xpc-service-bundle-id>) <probe-id> [probe-args...]
```

Notes:

- Prefer `--profile <id>` and omit the explicit bundle id.
- Tier 2 profiles require `--ack-risk` (you can pass either the profile id or the full bundle id).
- `--log-stream` is a best-effort **live** capture for sandbox denial lines; it writes a PID/process-filtered JSON report (`kind: sandbox_log_stream_report`) to the path you provide and sets `data.log_capture_*` in the probe response.
- `--log-stream auto` writes to an app-managed path under `~/Library/Application Support/entitlement-jail/logs/`; `--log-stream stdout` writes the stream report to stdout and requires `--json-out` so the probe JSON goes to a file (observer output still goes to a file path).
- `--log-stream` implies observer capture (same as `--observe`).
- `--observe` runs the embedded `sandbox-log-observer` even without `--log-stream`.
- `--observer-duration <seconds>` (or `--observer-follow`) makes the observer run in live mode (`log stream`) when possible; if the PID is not available in time, the observer falls back to windowed `log show` (check `data.log_observer_report.data.mode`).
- `--observer-follow` cannot be combined with `--observer-duration`.
- `--observer-format jsonl` and `--observer-output <path|auto>` control observer persistence; `jsonl` emits per-line events plus a final report line.
- `--log-path-class` + `--log-name` chooses a container-safe output path for the log stream report (still host-side capture). Allowed classes: `home`, `tmp`, `downloads`, `desktop`, `documents`, `app_support`, `caches`.
- `--log-path-class`/`--log-name` must be provided together and cannot be combined with an explicit `--log-stream <path>`.
- `--log-predicate` overrides the default PID-scoped predicate for both stream and observer (advanced; use with care).
- `--json-out` writes the probe JSON response to a file (stdout stays available for log stream output).
- `--attach-report <path|auto|stdout|stderr>` emits machine-readable attach events (`wait_ready`, `pid_ready`) as JSONL. If you choose `stdout`, you must also set `--json-out` so the probe JSON doesn't mix with the attach report.
- `--hold-open` keeps the service process alive after printing the JSON response.
- `--attach <seconds>` sets up a FIFO wait and, by default, also sets `--hold-open <seconds>` (so wall time can approach `2*seconds` if you trigger near the timeout). For automation/harnesses, consider `--hold-open 0`.
- `--preload-dylib <abs>` asks the service to `dlopen()` a dylib before running the probe. This is intended for instrumentation and executes dylib initializers by design; use it intentionally and prefer an injection-friendly profile (for example `fully_injectable`). In sandboxed services, you will usually also want `--preload-dylib-stage` so the dylib is copied into the service container before loading (otherwise the sandbox may block the file open).
- `--preload-dylib-stage` copies the dylib into the service container `tmp` and loads that staged copy (use this when the service sandbox would block reading from your source path).
- `--xpc-timeout-ms <n>` sets a client-side timeout; if no response arrives, the client emits a structured `probe_response` with `normalized_outcome: xpc_error`.

Common probes (discoverable via `probe_catalog`):

```sh
$EJ run-xpc --profile minimal probe_catalog
$EJ run-xpc --profile minimal capabilities_snapshot
$EJ run-xpc --profile minimal fs_op --op stat --path-class tmp
$EJ run-xpc --profile net_client net_op --op tcp_connect --host 127.0.0.1 --port 9
$EJ run-xpc --profile fully_injectable --ack-risk fully_injectable sandbox_check --operation file-read-data --path /etc/hosts
```

**Attach-friendly waits (`--attach`, `--wait-*`)**

Many XPC services start and exit quickly. For external tooling (lldb/dtrace/Frida), you usually want:

1. a deterministic “wait here” point before the interesting operation, and
2. a post-run hold so the process stays alive while you inspect it.

`--attach <seconds>` is the ergonomic path:

```sh
$EJ run-xpc --attach 60 --profile get-task-allow probe_catalog
$EJ run-xpc --attach 5 --hold-open 0 --profile get-task-allow probe_catalog
```

The client prints a line like:

```
[client] wait-ready mode=fifo wait_path=/.../wait-ready.fifo
```

When attach waits are in use, it also prints:

```
[client] pid-ready pid=<pid> process_name=<name> [correlation_id=<id>]
```

These status lines go to stderr so JSON stdout stays clean for parsing.

If you’re scripting around attach, `--attach-report` avoids parsing free-form status lines. It emits JSONL events (one per line), for example:

```json
{"kind":"attach_event","event":"wait_ready",...}
{"kind":"attach_event","event":"pid_ready",...}
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

Note on hooking `libsystem_sandbox` (`sandbox_check`)

- Many probes (notably filesystem probes like `fs_op`) perform syscalls directly and do not call `sandbox_check`. If you want `libsystem_sandbox` visibility, use the `sandbox_check` probe as a calibration point, or hook syscalls and/or rely on deny evidence capture.

**Sandbox log capture (deny evidence)**

Some probes return a permission-shaped failure (often `EPERM`/`EACCES`). That is *compatible with* a sandbox denial, but it is not proof of one. Treat the observer as the evidence source; log stream is a best-effort feed.
See "Logging & Evidence (quick reference)" for status fields, report types, and output paths.

If you want deny evidence for a specific run, prefer the observer (log stream is optional):

```sh
$EJ run-xpc --observe --profile minimal fs_op --op stat --path-class tmp
$EJ run-xpc --observe --observer-duration 3 --profile minimal fs_op --op stat --path-class tmp
$EJ run-xpc --log-stream /tmp/ej-sandbox.log --profile minimal fs_op --op stat --path-class tmp
$EJ run-xpc --log-path-class tmp --log-name ej-sandbox.log --profile minimal fs_op --op stat --path-class tmp
```

The log stream report is a JSON envelope (`kind: sandbox_log_stream_report`). `data` includes:

- `pid`, `process_name`, `predicate`
- `log_rc`, `log_rc_raw`, `log_stdout`, `log_stderr`, `log_error`
- `observed_lines`, `observed_deny`
- `layer_attribution.seatbelt` = `log_stream`

`data.log_stdout` is a filtered excerpt (deny/Sandbox lines for the PID/process), not the full `log stream` output.
The `log_rc` value is normalized to `0` when the stream is terminated intentionally; `log_rc_raw` preserves the raw exit status.

When the observer runs (via `--observe` or any `--log-stream`), the CLI writes a second report to `--observer-output` if set. Otherwise:

- If `--log-stream` points to a file path, the observer report defaults to `<log_stream_path>.observer.json` (or `.observer.jsonl` when `--observer-format jsonl` is set).
- If `--log-stream stdout` (or no log stream path is provided), the observer report defaults to an app-managed path under `~/Library/Application Support/entitlement-jail/logs/` (extension matches the observer format).

The observer report is a JSON envelope (`kind: sandbox_log_observer_report`). `data` includes:

- `observer_schema_version`, `mode` (`show`/`stream`), `duration_ms`
- `plan_id`, `row_id`, `correlation_id`
- `pid`, `process_name`, `predicate`, `start`, `end`, `last`
- `log_rc`, `log_stdout`, `log_stderr`, `log_error`, `log_truncated`
- `observed_lines`, `observed_deny`, `deny_lines`
- `layer_attribution.seatbelt` = `observer_only`

The full observer report is also embedded in `data.log_observer_report` in the `run-xpc` response.

Standalone observer examples:

```sh
EntitlementJail.app/Contents/MacOS/sandbox-log-observer --pid <pid> --process-name <name> --last 5s
EntitlementJail.app/Contents/MacOS/sandbox-log-observer --pid <pid> --process-name <name> --duration 5 --format jsonl --output /tmp/ej-observer.jsonl
```

If you omit `--predicate`, you must provide `--process-name`; the observer will build a PID-scoped sandbox predicate. `--output` writes a copy of the JSON/JSONL stream to disk in addition to stdout (JSONL appends).

Without `--duration`/`--follow`, the observer uses `log show` and defaults to `--last 5s` unless you pass `--start`/`--end` or `--last`.

If you use `--format jsonl`, the output stream includes `sandbox_log_observer_event` envelopes for each observed line plus a final `sandbox_log_observer_report` line.

Interpretation rules:

- If log capture was requested, check `data.log_capture_status`, `data.log_capture_error`, `data.log_capture_path`, `data.log_capture_predicate`, `data.log_capture_observed_lines`, and `data.log_capture_observed_deny`.
- For observer output, check `data.log_observer_status`, `data.log_observer_error`, `data.log_observer_path`, `data.log_observer_predicate`, `data.log_observer_start`, `data.log_observer_end`, `data.log_observer_last`, `data.log_observer_observed_lines`, `data.log_observer_observed_deny`, `data.log_observer_deny_lines`, and `data.log_observer_report`.
- `data.log_capture_status` is `not_requested`, `requested_written`, or `requested_failed`; `data.log_observer_status` is `requested_written` or `requested_failed`.
- `data.log_observer_path` points to the observer report file.
- `data.log_capture_path` is the stream report path (or `stdout`/`-` when `--log-stream stdout` is used).
- The log prelude line (“Filtering the log data using …”) is ignored for `observed_*` and `deny_lines`.
- Permission-shaped failures can still yield `deny_evidence=not_found`; treat that as “no deny evidence captured”, not as a denial attribution.
- If log capture was not requested, `data.deny_evidence` is set to `not_captured`.
- If stream and observer both fail, `data.deny_evidence` is set to `log_error`.
- Log capture is best-effort; if `/usr/bin/log` fails, treat that as "no deny evidence captured", not as a Seatbelt signal. Log capture is host-side only; in-sandbox log capture is not viable.
- Use the embedded observer `EntitlementJail.app/Contents/MacOS/sandbox-log-observer` when you want an explicit “outside the sandbox boundary” witness or to re-run with a custom predicate.
- Use `data.details.service_pid` (or `data.details.probe_pid`) plus `data.details.process_name` as inputs.
- If those fields are missing, the CLI injects fallbacks and annotates `data.details.pid_source` / `data.details.process_name_source`.

**Filesystem probes (fs_op, fs_xattr, fs_coordinated_op)**

Some probes expect a **file** path, not a directory. In particular:

- `fs_op --target run_dir` and `fs_op --target harness_dir` resolve to directories.
- `fs_op --target specimen_file` resolves to a file path under `*/entitlement-jail-harness/*`, but the file is only created by ops like `create` or `open_write` (not by `stat`).
- `fs_xattr` write/remove operations are refused outside harness paths unless you pass `--allow-write` or `--allow-unsafe-path`.

Note on `--path-class downloads`: the resolved path is the **service container** Downloads directory (for example `~/Library/Containers/<bundle-id>/Data/Downloads`). A `permission_error` here can be entitlement-sensitive (compare with `downloads_rw`) even if no deny line is captured; keep attribution explicit.

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

If you pass `--out`, it can be any writable directory (including a path inside this repo). If you are running a sandboxed build, repo paths may be blocked; use a home/tmp path instead.

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
~/Library/Application Support/entitlement-jail/evidence/latest
```

If you pass `--out`, it can be any writable directory (including a path inside this repo). If you are running a sandboxed build, repo paths may be blocked; use a home/tmp path instead.

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
- Log capture: `data.log_capture_status`, `data.log_capture_error`, `data.log_capture_path`, `data.log_capture_predicate`, `data.log_capture_observed_lines`, `data.log_capture_observed_deny`, and `data.deny_evidence` (`not_captured`, `captured`, `not_found`, or `log_error`).
- Observer summary: `data.log_observer_status`, `data.log_observer_error`, `data.log_observer_path`, `data.log_observer_predicate`, `data.log_observer_start`, `data.log_observer_end`, `data.log_observer_last`, `data.log_observer_observed_lines`, `data.log_observer_observed_deny`, `data.log_observer_deny_lines`, plus the embedded `data.log_observer_report`.
- Observer inputs: `data.details.service_pid` (or `data.details.probe_pid`) and `data.details.process_name`.

Quick extraction without `jq` (macOS ships `plutil`):

```sh
plutil -extract result.normalized_outcome raw -o - report.json
plutil -extract data.output_dir raw -o - report.json
plutil -extract data.details.file_path raw -o - report.json
```

## Safety notes

- `run-system` runs **platform binaries only** (allowlisted to standard system prefixes). It exists for specific demonstrations; most work should use `run-xpc`.
- `run-embedded` runs signed helper tools embedded in the app bundle. It does not run arbitrary on-disk tools by path.
- `dlopen_external` executes dylib initializers by design. Treat it as code execution and use it intentionally.
- `--preload-dylib` also executes dylib initializers by design; treat it as code execution and use it intentionally.
- If you did not capture deny evidence, do not claim “sandbox denied”; keep attribution explicit.
