# EntitlementJail.app

EntitlementJail is a macOS research and teaching tool that lets you observe how App Sandbox and entitlements shape runtime behavior. It is designed to produce *witness records* (what happened, where, and with which entitlement profile) rather than make blanket security claims.

You interact with it through a sandboxed CLI bundled inside the app. This document is a self‑contained reference for end users.

## Quick start

Define a convenience variable for the CLI:

```sh
EJ="$PWD/EntitlementJail.app/Contents/MacOS/entitlement-jail"
```

List available probes:

```sh
$EJ run-xpc com.yourteam.entitlement-jail.ProbeService_minimal probe_catalog
```

See entitlements + environment for a specific service:

```sh
$EJ run-xpc com.yourteam.entitlement-jail.ProbeService_minimal capabilities_snapshot
```

Run the same probe across different services to compare entitlement effects:

```sh
$EJ run-xpc com.yourteam.entitlement-jail.ProbeService_minimal net_op --op tcp_connect --host 1.1.1.1 --port 443
$EJ run-xpc com.yourteam.entitlement-jail.ProbeService_net_client net_op --op tcp_connect --host 1.1.1.1 --port 443
```

## The "process zoo" mental model

EntitlementJail uses a **process zoo**: a set of XPC services where each service is a separate signed executable with a different entitlement profile.

Key points:

- Each XPC service is its own process with its own entitlements.
- The *code path* is the same across services; the *entitlement profile* changes.
- Use the **same probe** on different services to isolate the effect of entitlements.
- The JSON output includes the service bundle id and PID so you can attach external tools to the correct process.

This design lets you answer questions like:

- "Does `get-task-allow` change attachability for this process?"
- "Does `allow-jit` change `MAP_JIT` behavior?"
- "Does `disable-library-validation` change `dlopen` outcomes?"

## CLI reference

The CLI lives at:

```
EntitlementJail.app/Contents/MacOS/entitlement-jail
```

### `run-xpc` (primary workflow)

Run a probe inside a specific XPC service (the core "entitlements as the variable" mode).

```sh
$EJ run-xpc [--log-sandbox <path>|--log-stream <path>] [--log-predicate <predicate>]
            [--plan-id <id>] [--row-id <id>] [--correlation-id <id>] [--expected-outcome <label>]
            [--wait-fifo <path>|--wait-exists <path>] [--wait-path-class <class>] [--wait-name <name>]
            [--wait-timeout-ms <n>] [--wait-interval-ms <n>] [--wait-create]
            [--attach <seconds>] [--hold-open <seconds>]
            <xpc-service-bundle-id> <probe-id> [probe-args...]
```

Examples:

```sh
# Basic probe
$EJ run-xpc com.yourteam.entitlement-jail.ProbeService_minimal capabilities_snapshot

# Filesystem probe (safe by default)
$EJ run-xpc com.yourteam.entitlement-jail.ProbeService_minimal fs_op --op stat --path-class tmp

# Capture a best-effort Sandbox log excerpt for the probe PID
$EJ run-xpc --log-sandbox /tmp/ej-sandbox.log \
  com.yourteam.entitlement-jail.ProbeService_minimal fs_op --op stat --path-class downloads
```

Notes:

- `--log-sandbox` uses `/usr/bin/log show` and is best-effort. Absence of a deny line is not proof that no denial occurred.
- `--log-predicate` overrides the default log predicate. It must appear *before* the service bundle id.
- `fs_op` is safe-by-default: destructive direct-path operations are refused unless you use a harness path (`--path-class`) or set `--allow-unsafe-path`.

### Attach-friendly waits

You can pause **before** a probe runs so external tools (Frida, DTrace, lldb) can attach to the service.

Convenience:

```sh
$EJ run-xpc --attach 60 com.yourteam.entitlement-jail.ProbeService_fully_injectable fs_op --op stat --path-class tmp
# Copy the wait_path from stderr and trigger:
echo go > /path/from/wait-ready.fifo
```

Details:

- `--attach <seconds>` sets a pre-run FIFO wait under the service container `tmp` and also sets `--hold-open` to the same duration (unless you explicitly set `--hold-open`).
- `--wait-fifo` / `--wait-exists` block **before** probe execution; wait metadata is recorded in the JSON `details` (`wait_*` keys).
- When a wait is configured, the client prints a `wait-ready` line to stderr with the resolved wait path.
- `--wait-path-class` is resolved by the *service* using its own standard directories (so it maps to that service's container).
- `--wait-create` tells the service to create the FIFO path before waiting (only valid with `--wait-fifo`).

### `run-system` (platform binaries only)

Run a platform binary in place. This refuses paths outside the system allowlist.

```sh
$EJ run-system /usr/bin/id
```

### `run-embedded` (bundle helpers)

Run a helper shipped inside the app bundle.

```sh
$EJ run-embedded <tool-name> [args...]
```

### `quarantine-lab` (quarantine metadata only)

Write/open/copy artifacts and report `com.apple.quarantine` metadata changes. This does **not** execute artifacts.

```sh
$EJ quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
```

Example:

```sh
$EJ quarantine-lab com.yourteam.entitlement-jail.QuarantineLab_default \
  shell_script --dir tmp --operation create_new --name demo
```

## Process zoo: XPC service map

Each service is identical code with a different entitlement profile.

Probe services:

| Service bundle id | Focus | Key entitlements |
| --- | --- | --- |
| `com.yourteam.entitlement-jail.ProbeService_minimal` | Baseline | App Sandbox only |
| `com.yourteam.entitlement-jail.ProbeService_net_client` | Network client | `com.apple.security.network.client` |
| `com.yourteam.entitlement-jail.ProbeService_downloads_rw` | Downloads access | `com.apple.security.files.downloads.read-write` |
| `com.yourteam.entitlement-jail.ProbeService_user_selected_executable` | User-selected executable | `com.apple.security.files.user-selected.executable` |
| `com.yourteam.entitlement-jail.ProbeService_bookmarks_app_scope` | Security-scoped bookmarks | `com.apple.security.files.bookmarks.app-scope` |
| `com.yourteam.entitlement-jail.ProbeService_debuggable` | Debug attach | `com.apple.security.get-task-allow`, `com.apple.security.cs.disable-library-validation` |
| `com.yourteam.entitlement-jail.ProbeService_plugin_host_relaxed` | Plugin host | `com.apple.security.cs.disable-library-validation` |
| `com.yourteam.entitlement-jail.ProbeService_dyld_env_enabled` | DYLD env | `com.apple.security.cs.allow-dyld-environment-variables` |
| `com.yourteam.entitlement-jail.ProbeService_fully_injectable` | Max attach/inject | `get-task-allow`, `disable-library-validation`, `allow-dyld-environment-variables`, `allow-jit`, `allow-unsigned-executable-memory` |
| `com.yourteam.entitlement-jail.ProbeService_jit_map_jit` | MAP_JIT | `com.apple.security.cs.allow-jit` |
| `com.yourteam.entitlement-jail.ProbeService_jit_rwx_legacy` | RWX legacy | `com.apple.security.cs.allow-unsigned-executable-memory` |

Quarantine Lab services:

| Service bundle id | Focus | Key entitlements |
| --- | --- | --- |
| `com.yourteam.entitlement-jail.QuarantineLab_default` | Baseline | App Sandbox only |
| `com.yourteam.entitlement-jail.QuarantineLab_net_client` | Network client | `com.apple.security.network.client` |
| `com.yourteam.entitlement-jail.QuarantineLab_downloads_rw` | Downloads access | `com.apple.security.files.downloads.read-write` |
| `com.yourteam.entitlement-jail.QuarantineLab_bookmarks_app_scope` | Bookmarks | `com.apple.security.files.bookmarks.app-scope` |
| `com.yourteam.entitlement-jail.QuarantineLab_user_selected_executable` | User-selected executable | `com.apple.security.files.user-selected.executable` |

## Built-in probes (run-xpc)

Probe ids are stable identifiers (not paths). Use `probe_catalog` and `<probe-id> --help` for exact usage.

Common probes:

- `probe_catalog` - list probes and usage
- `capabilities_snapshot` - entitlements + resolved standard directories
- `world_shape` - environment shape (containerized paths, etc.)
- `fs_op` - parameterized filesystem operations (safe-by-default)
- `fs_op_wait` - `fs_op` with an explicit wait trigger (legacy; prefer `--attach` or `--wait-*`)
- `net_op` - parameterized networking (`getaddrinfo`, `tcp_connect`, `udp_send`)
- `dlopen_external` - dlopen a signed dylib by absolute path (executes initializers)
- `jit_map_jit` - attempt `mmap` with `MAP_JIT`
- `jit_rwx_legacy` - attempt RWX `mmap`
- `downloads_rw` - read/write/remove under Downloads harness
- `bookmark_make` / `bookmark_op` / `bookmark_roundtrip` - security-scoped bookmark flows
- `userdefaults_op` - UserDefaults read/write/remove/sync
- `fs_xattr` - get/list/set/remove xattrs
- `fs_coordinated_op` - NSFileCoordinator mediated read/write

## Output format (what to trust)

Each probe returns JSON with fields like:

- `rc` and `normalized_outcome` (primary result)
- `errno` and `error` (low-level failure details)
- `details` (metadata like `service_bundle_id`, `pid`, `probe_id`, `wait_*` keys)

Use `details.pid` (or `details.service_pid`) to attach external tools to the correct process.

Do **not** assume a permission error equals a sandbox denial. It could be:

- a Seatbelt/App Sandbox denial (look for a `Sandbox:` log line for that PID),
- a service/API refusal (no sandbox log),
- or "world shape" differences (containerized paths).

## Safety and scope

- `run-xpc` executes probes in-process and does not spawn arbitrary binaries. `dlopen_external` is the explicit exception and *does* execute dylib initializers.
- `quarantine-lab` records quarantine metadata and does **not** execute artifacts.
- `run-system` and `run-embedded` run executable code by design; use them intentionally.
