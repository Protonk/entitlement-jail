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
- Run one probe (one-shot): `xpc run --profile <id[@variant]> <probe-id> [probe-args...]`
- Deterministic debugger attach + multiple probes: `xpc session --profile minimal@injectable ...`
- Compare across profiles: `run-matrix --group <...> [--variant <base|injectable>] <probe-id> [probe-args...]`
- Sandbox extension flow: `sandbox_extension` (issue/consume/release)
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
$EJ run-matrix --group baseline capabilities_snapshot
```

Create a harness file and set an xattr (extract `data.details.file_path` without `jq`):

```sh
$EJ xpc run --profile minimal fs_op --op create --path-class tmp --target specimen_file --name ej_xattr.txt > /tmp/ej_fs_op.json
FILE_PATH=$(plutil -extract data.details.file_path raw -o - /tmp/ej_fs_op.json)
$EJ xpc run --profile minimal fs_xattr --op set --path "$FILE_PATH" --name user.ej --value test
```

## Concepts

### Process zoo

- A **profile** is a short base id (like `minimal` or `temporary_exception`) that maps to one XPC service family.
- Each profile has two **variants**: `base` (the canonical entitlements) and `injectable` (an auto-generated twin with a fixed instrumentation overlay).
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
$EJ list-services
```

`list-profiles` shows base profile ids; `list-services` shows both base and injectable service variants.

Inspect a profile (entitlements, risk signals, tags):

```sh
$EJ show-profile minimal
$EJ show-profile minimal@injectable
```

Inspect a service “statically” (what the profile says it should have):

```sh
$EJ describe-service minimal@injectable
```

**Risk signals**

Some profiles carry higher-concern entitlements. The CLI emits warnings and proceeds (choosing `injectable` is treated as explicit intent).

This is about guardrails, not morality: some profiles intentionally carry entitlements that widen instrumentation/injection surface.

Profile ids can include `@variant` (for example `minimal@injectable`).

**Profiles you’ll likely see**

Use `list-profiles` as the source of truth. Some common base ids include: `minimal`, `net_client`, `downloads_rw`, `bookmarks_app_scope`, `user_selected_executable`, and `temporary_exception`.

**Variants (base vs injectable)**

Each base profile has two variants:

- `base` (default): the canonical entitlements for that service.
- `injectable`: an auto-generated twin that adds the fixed instrumentation overlay (`get-task-allow`, `disable-library-validation`, `allow-dyld-environment-variables`, `allow-unsigned-executable-memory`). This is high concern.

Select a variant with `--variant injectable` or `profile@injectable`.

For sandbox extension issuance, use:

- `temporary_exception`: App Sandbox + `com.apple.security.temporary-exception.sbpl` for `file-issue-extension` (high concern).

There are also Quarantine Lab profiles (kind `quarantine`) such as `quarantine_default`, `quarantine_net_client`, `quarantine_downloads_rw`, `quarantine_user_selected_executable`, and `quarantine_bookmarks_app_scope`.

### Run probes in a service (`xpc run`)

Pick a profile/service, run one probe, and get a JSON witness record.

Usage:

```sh
$EJ xpc run (--profile <id[@variant]> [--variant <base|injectable>] | --service <bundle-id>)
            [--plan-id <id>] [--row-id <id>] [--correlation-id <id>]
            <probe-id> [probe-args...]
```

Notes:

- Prefer `--profile <id[@variant]>` and omit the explicit bundle id.
- High-concern variants emit a warning but do not require an extra flag.
- `xpc run` is intentionally one-shot. For deterministic attach and multi-probe workflows, use `xpc session`.

Common probes:

```sh
$EJ xpc run --profile minimal probe_catalog
$EJ xpc run --profile minimal capabilities_snapshot
$EJ xpc run --profile minimal fs_op --op stat --path-class tmp
$EJ xpc run --profile net_client net_op --op tcp_connect --host 127.0.0.1 --port 9
$EJ xpc run --profile minimal --variant injectable sandbox_check --operation file-read-data --path /etc/hosts
$EJ xpc run --profile temporary_exception sandbox_extension --op issue_file --class com.apple.app-sandbox.read --path /etc/hosts --allow-unsafe-path
```

Use `probe_catalog` as the source of truth for per-probe usage; the current build also exposes `fs_op_wait`, `bookmark_make`, `bookmark_op`, `bookmark_roundtrip`, `userdefaults_op`, `fs_coordinated_op`, and `network_tcp_connect`.

### Sandbox extension flow (issue -> consume -> release)

`sandbox_extension` uses the private sandbox extension SPI to issue/consume/release file extensions. Issuance requires a profile that allows `file-issue-extension` (see `temporary_exception`), and the issued token is returned in `data.stdout`.

Example: issue a read extension for a harness file, consume it in `minimal`, then re-run the read:

```sh
$EJ xpc run --profile temporary_exception sandbox_extension \
  --op issue_file --class com.apple.app-sandbox.read \
  --path-class tmp --target specimen_file --name ej_extension.txt --create > /tmp/ej_issue_token.json
FILE_PATH=$(plutil -extract data.details.file_path raw -o - /tmp/ej_issue_token.json)
TOKEN=$(plutil -extract data.details.token raw -o - /tmp/ej_issue_token.json)

$EJ xpc run --profile minimal fs_op --op open_read --path "$FILE_PATH"
$EJ xpc run --profile minimal sandbox_extension --op consume --token "$TOKEN"
$EJ xpc run --profile minimal fs_op --op open_read --path "$FILE_PATH"
$EJ xpc run --profile minimal sandbox_extension --op release --token "$TOKEN"
```

Notes:

- If you want to issue extensions for a non-harness path, pass `--allow-unsafe-path` to `sandbox_extension --op issue_file`.
- Tokens are returned in `data.details.token` and also in `data.stdout`.
- If consume/release fails with invalid-token style errors, try `--token-format prefix` (default: `full`).
- For read/write testing, issue `com.apple.app-sandbox.read-write` and use a write op (for example `fs_op --op open_write`) after consuming the token.
- For a clear “denied → allowed” witness, use a world-readable file that App Sandbox blocks by default (for example `/private/var/db/launchd.db/com.apple.launchd/overrides.plist`). On Sonoma, `/etc/hosts` is often already readable, so it won’t show a before/after change.
- If you need to keep a harness file across rename/truncate during `update_file_by_fileid` experiments, add `fs_op --no-cleanup` so the harness path isn’t removed.
- To issue directly to a target process, use `sandbox_extension --op issue_file_to_pid --pid <pid|self>`; the service pid is included as `data.details.service_pid` on every probe response.
- Consume/release auto-try wrapper symbols when available; use `--call-symbol`/`--call-variant` to pin a specific ABI path for debugging.
- Use `--introspect` to emit symbol presence and image paths in `data.details` for extension calls.
- On Sonoma 14.4.1, `release`/`release_file` did not revoke access inside the same process; access cleared after the process exited. Treat release as best-effort cleanup and verify on your target OS.
- Advanced: `issue_extension`/`issue_fs_extension`/`issue_fs_rw_extension` are wrapper issue calls. `update_file` (path + flags) and `update_file_by_fileid` (token + file id + flags; some hosts expect a fileid pointer, try `--call-variant fileid_ptr_token`, or a selector via `--call-variant payload_ptr_selector --selector <u64>`) are experimental maintenance calls that may not affect access in-process. On Sonoma 14.4.1, kernel disassembly suggests `update_file_by_fileid` expects an internal id (low 32 bits of an 8-byte payload) and requires field2 = 0, so success may require a handle not exposed via the public token string.

### Deterministic debugger attach (`xpc session`)

`xpc session` is a session-based XPC control plane intended for tooling like lldb/dtrace/Frida. It provides explicit lifecycle events and keeps the service alive across multiple probes so you can attach once and then iterate.

Usage:

```sh
$EJ xpc session (--profile <id[@variant]> [--variant <base|injectable>] | --service <bundle-id>)
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

- a `probe_response` (`data.details.service_pid` + `data.details.process_name`, or `data.details.pid` on older outputs), or
- an `xpc_session_event` (`data.pid` + `data.service_name`).

One-shot pairing example:

```sh
$EJ xpc run --profile minimal fs_op --op stat --path-class tmp > /tmp/ej_probe.json
PID=$(plutil -extract data.details.service_pid raw -o - /tmp/ej_probe.json)
NAME=$(plutil -extract data.details.process_name raw -o - /tmp/ej_probe.json)
EntitlementJail.app/Contents/MacOS/sandbox-log-observer --pid "$PID" --process-name "$NAME" --last 10s
```

Observer usage (summary):

- Windowed (`log show`, default): `--last 5s` or explicit `--start`/`--end`
- Live (`log stream`): `--duration <seconds>` or `--follow`
- Output: `--format json` (default) or `--format jsonl` (events + final report); optional copy via `--output <path>`
- Optional override: `--predicate <predicate>` to customize the log filter

### Compare a probe across a group (`run-matrix`)

`run-matrix` runs one probe across a named group of profiles and writes:

- a compare table (`run-matrix.table.txt`)
- a full JSON report (`run-matrix.json`)

Usage:

```sh
$EJ run-matrix --group <baseline|probe> [--variant <base|injectable>] [--out <dir>] <probe-id> [probe-args...]
```

Examples:

```sh
$EJ run-matrix --group baseline capabilities_snapshot
$EJ run-matrix --group probe --variant injectable capabilities_snapshot
```

High-concern variants are included without extra flags.

Groups (current build; use `list-profiles` as the source of truth):

- `baseline`: `minimal`
- `probe`: `minimal`, `net_client`, `downloads_rw`, `user_selected_executable`, `bookmarks_app_scope`, `temporary_exception`

Default output directory (per group, overwritten each run; see `data.output_dir`):

```
~/Library/Application Support/entitlement-jail/matrix/<group>/<variant>/latest
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
- Run `$EJ show-profile <id>` and copy `data.variant.bundle_id` into the `quarantine-lab` invocation.

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
  "schema_version": 4,
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

Note: Rust-emitted CLI reports use `schema_version: 4`. XPC probe/quarantine responses emitted by the embedded Swift clients still use `schema_version: 2`.

Rules:

- Keys are lexicographically sorted for stability.
- `xpc run` and `quarantine-lab` use `result.rc`; report-style commands use `result.exit_code`.
- Some `result` fields are omitted when empty/not-applicable (for example `errno`, `stderr`, `stdout`), and some reports include them as `null`.
- Command-specific fields live under `data` (no extra top-level keys).
- `xpc session` emits one envelope per line (JSONL): lifecycle events (`xpc_session_event` / `xpc_session_error`) plus `probe_response` lines for each probe you run in the session.

What to read first:

- Outcome: `result.ok`, `result.normalized_outcome`, plus `result.errno`/`result.error` if not ok.
- Service identity: `data.service_bundle_id`, `data.service_name`, `data.service_version`, `data.service_build` (probe responses), `data.details.service_pid`/`data.details.process_name`, and `data.pid` (session events).
- “What path did it use?”: `data.details.file_path` (common for filesystem probes like `fs_op`/`fs_xattr`).

Quick extraction without `jq` (macOS ships `plutil`):

```sh
plutil -extract result.normalized_outcome raw -o - report.json
plutil -extract data.details.service_pid raw -o - report.json
plutil -extract data.details.process_name raw -o - report.json
```

## Safety notes

- `run-system` runs **platform binaries only** (allowlisted to standard system prefixes). It exists for specific demonstrations; most work should use XPC services (`xpc run` / `xpc session`).
- `run-embedded` runs signed helper tools embedded in the app bundle. It does not run arbitrary on-disk tools by path.
- `dlopen_external` executes dylib initializers by design. Treat it as code execution and use it intentionally.
- If you did not capture deny evidence, do not claim “sandbox denied”; keep attribution explicit.
