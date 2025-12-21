# EntitlementJail.app (distribution README)

EntitlementJail.app is a macOS **research/teaching application** for observing how **App Sandbox (Seatbelt)** and **entitlements** shape runtime behavior, with explicit separation of:

- what happened (executed vs blocked vs refused), and
- which subsystem caused it (Seatbelt/App Sandbox vs quarantine/Gatekeeper metadata vs other service/API behavior).

It is designed to be a **runtime witness**, not a “sandbox bypass” tool.

## Where the CLI lives

EntitlementJail.app is a GUI bundle that contains a sandboxed CLI entrypoint:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail`

Run it **in place** (inside the `.app`). Some commands rely on embedded XPC services that are discovered relative to the app bundle.

Convenience:

```sh
EJ="$PWD/EntitlementJail.app/Contents/MacOS/entitlement-jail"
```

## What’s inside the app bundle

Key components you may see under `EntitlementJail.app/Contents/`:

- `MacOS/entitlement-jail`: the main sandboxed launcher (this is what you run)
- `MacOS/xpc-probe-client`: helper used by `run-xpc` to talk to embedded XPC services
- `MacOS/xpc-quarantine-client`: helper used by `quarantine-lab` to talk to embedded Quarantine Lab services
- `XPCServices/*.xpc`: launchd-managed XPC service targets (each is its own signed sandbox with its own entitlements)
- `Helpers/` (optional): bundle-embedded helper executables (only used with `run-embedded`, if present)

## Core commands (how to use it)

### 1) `run-system` — run allowlisted platform binaries

Runs a platform binary **in place** (not staged) from an allowlisted set of prefixes.

```sh
$EJ run-system /usr/bin/id
```

This mode is intentionally conservative: it refuses paths outside platform locations to avoid “staged into writable path then exec” confusion.

### 2) `run-embedded` — run bundle-embedded helper executables

Runs an executable shipped inside the `.app` bundle by tool name (a single path component).

```sh
$EJ run-embedded <tool-name> [args...]
```

If your bundle does not contain any helpers under `Contents/Helpers/`, this command will not be useful.

### 3) `run-xpc` — run in-process probes inside a selected XPC target (recommended)

This is the core “entitlements as the variable” mode.

```sh
$EJ run-xpc [--log-sandbox <path>|--log-stream <path>] [--log-predicate <predicate>] <xpc-service-bundle-id> <probe-id> [probe-args...]
```

The probe executes **in-process inside the XPC service** (no child-process exec), and returns a JSON result on stdout; the CLI exits with the returned `rc`.

Example:

```sh
$EJ run-xpc com.yourteam.entitlement-jail.ProbeService_minimal capabilities_snapshot
```

Optional: capture a PID-scoped `Sandbox:` unified log excerpt (best-effort; uses `log show`):

```sh
$EJ run-xpc --log-sandbox /tmp/ej-sandbox.log com.yourteam.entitlement-jail.ProbeService_minimal fs_op --op stat --path-class downloads
```

Rule: deny attribution is only valid when produced by **host-side** log capture (outside `EntitlementJail.app`); in-app log capture is diagnostic only and may be blocked by the app sandbox.

Note: client flags (`--log-sandbox`, `--log-predicate`) must appear before `<xpc-service-bundle-id>`.

`--log-predicate` overrides the default `log show` predicate (pass a full predicate string).

### 4) `quarantine-lab` — write/open/copy files and report `com.apple.quarantine` deltas (no execution)

Quarantine Lab is for measuring **quarantine/Gatekeeper metadata** as a separate layer from Seatbelt policy.

```sh
$EJ quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
```

Example (writes a `.sh` specimen and reports quarantine before/after; does not execute it):

```sh
$EJ quarantine-lab com.yourteam.entitlement-jail.QuarantineLab_default shell_script --dir tmp --operation create_new --name demo
```

## XPC targets (the entitlement lattice)

`run-xpc` / `quarantine-lab` select a service by **bundle id**. Each service is identical code, differing only by entitlements.

Probe services:

- `com.yourteam.entitlement-jail.ProbeService_minimal` — App Sandbox only (baseline)
- `com.yourteam.entitlement-jail.ProbeService_net_client` — adds `com.apple.security.network.client`
- `com.yourteam.entitlement-jail.ProbeService_downloads_rw` — adds `com.apple.security.files.downloads.read-write`
- `com.yourteam.entitlement-jail.ProbeService_bookmarks_app_scope` — adds `com.apple.security.files.bookmarks.app-scope` (enables ScopedBookmarksAgent IPC used by security-scoped bookmarks)
- `com.yourteam.entitlement-jail.ProbeService_user_selected_executable` — adds `com.apple.security.files.user-selected.executable` (used primarily for Quarantine Lab calibration)

Quarantine Lab services:

- `com.yourteam.entitlement-jail.QuarantineLab_default` — App Sandbox only
- `com.yourteam.entitlement-jail.QuarantineLab_net_client` — adds network client
- `com.yourteam.entitlement-jail.QuarantineLab_downloads_rw` — adds Downloads read-write
- `com.yourteam.entitlement-jail.QuarantineLab_bookmarks_app_scope` — adds bookmarks app-scope
- `com.yourteam.entitlement-jail.QuarantineLab_user_selected_executable` — adds user-selected executable

## Built-in probes (for `run-xpc`)

Probe ids are stable identifiers (not paths). Each returns JSON with fields like `rc`, `normalized_outcome`, `errno`, `error`, `details`, and optional `layer_attribution`.

Common probes:

- `probe_catalog` — emits a JSON catalog; use `<probe-id> --help` for per-probe usage
- `capabilities_snapshot` — reports entitlements and resolved standard directories for the current service
- `world_shape` — reports “world shape” (for example, containerized `HOME`) as an explicit dimension
- `fs_op` — parameterized filesystem operations (`--op stat|open_read|...`); destructive direct-path ops are refused unless `--allow-unsafe-path` is provided (prefer `--path-class`)
- `net_op` — parameterized networking (`--op getaddrinfo|tcp_connect|udp_send`)
- `downloads_rw` — best-effort read/write/remove under Downloads (for the Downloads entitlement)
- `bookmark_make` / `bookmark_op` — bookmark token generation and bookmark-driven `fs_op` (security-scoped bookmarks require the bookmarks/user-selected entitlement boundary)
- `bookmark_roundtrip` — create a bookmark token and immediately resolve + run a bookmark-scoped `fs_op`
- `userdefaults_op` — read/write/remove/sync a `UserDefaults` key (useful for containerization evidence)
- `fs_xattr` — read/list/set/remove xattrs (xattr writes are refused outside harness paths unless explicitly allowed)
- `fs_coordinated_op` — NSFileCoordinator mediated read/write

## Interpreting results (don’t collapse layers)

EntitlementJail’s outputs are intended as **witness records**, not one-line conclusions.

- “Permission-shaped error” does not automatically mean “Seatbelt denied”.
  - It could be a Seatbelt denial (best supported by an observed deny-op in unified logs).
  - It could be a mediated API/service refusal (no deny-op observed).
  - It could be “world shape” (different path classes due to containerization).
  - It could be “other” (missing files, invalid signatures, Gatekeeper behavior, etc.).
- Quarantine Lab reports `com.apple.quarantine` deltas as **metadata**, and does not execute specimens.

If you need Seatbelt-level attribution, inspect unified logs for `Sandbox:` lines referencing the emitting process (for example `ProbeService_minimal`) and the specific operation (for example `mach-lookup`, `file-read-data`, `process-exec`, …).

## Safety notes

- `run-xpc` runs probes **in-process** and does not execute arbitrary binaries.
- `quarantine-lab` does **not** execute artifacts.
- `run-system` and `run-embedded` *do* execute processes by design; use them deliberately.
