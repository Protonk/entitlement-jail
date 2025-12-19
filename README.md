# entitlement-jail

>minimal macOS app whose only job is to launch code inside the **App Sandbox**.

The app itself is signed with a Developer ID and opts into the App Sandbox via the `com.apple.security.app-sandbox` entitlement. Any command it launches runs as a child process and **inherits the same sandbox restrictions**.

On stock macOS, an App Sandbox parent is *not* a general-purpose “run arbitrary staged Mach-O” wrapper: the sandbox typically denies `process-exec*` for executables living in **writable locations** (including the app container). This tool therefore focuses on launching:

- **In-place platform binaries** (from system paths like `/usr/bin`)
- **Embedded helper tools** shipped inside the `.app` bundle (not copied into `~/Library/Containers/...`)

## What it does

* Launches a single command as a child process
* Supports `run-system` (platform binaries) and `run-embedded` (bundle-shipped probes/helpers)
* Does not attempt to `exec` arbitrary staged binaries from writable locations

## What it is

* A small `.app` bundle
* Developer ID signed
* Notarized and Gatekeeper-accepted
* Uses standard process execution (`posix_spawn` / `NSTask`-style)

## Usage

```bash
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-system <absolute-platform-binary> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-embedded <tool-name> [args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc <xpc-service-bundle-id> <probe-id> [probe-args...]
./EntitlementJail.app/Contents/MacOS/entitlement-jail quarantine-lab <xpc-service-bundle-id> <payload-class> [options...]
```

Example:

```bash
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-system /bin/ls /
```

Example (XPC service):

```bash
./EntitlementJail.app/Contents/MacOS/entitlement-jail run-xpc com.yourteam.entitlement-jail.ProbeService_minimal <probe-id> [probe-args...]
```

## Embedded tools

Embedded tools live inside the `.app` bundle and are launched by bundle-relative path (not from the app container).

Default search paths:

- `EntitlementJail.app/Contents/Helpers/<tool-name>`
- `EntitlementJail.app/Contents/Helpers/Probes/<tool-name>`

For App Sandbox inheritance to work for helpers launched via `posix_spawn`/`NSTask`, the helper tool must be signed with **exactly**:

- `com.apple.security.app-sandbox`
- `com.apple.security.inherit`

This repo includes `EntitlementJail.inherit.entitlements` for that purpose.

## Entitlement exploration note (XPC)

If your goal is to treat entitlements as “knobs”, prefer **XPC services** over child processes: each `.xpc` service is its own signed target with its own entitlements/sandbox and is launched by `launchd`, avoiding `process-exec*` issues.

This repo includes a minimal XPC “probe runner” service plus a small embedded client tool:

- XPC services live under `xpc/services/<ServiceName>/` (Info.plist + Entitlements.plist + main.swift)
- The build embeds them into `EntitlementJail.app/Contents/XPCServices/<ServiceName>.xpc`
- `run-xpc` delegates to the embedded helper `xpc-probe-client` and prints a JSON response

The JSON RPC request/response shapes are:

- Request: `{plan_id, probe_id, argv, env_overrides}`
- Response: `{rc, stdout, stderr, normalized_outcome, sandbox_log_excerpt_ref}`

## Quarantine Lab (misleading entitlements)

`com.apple.security.files.user-selected.executable` is a good “SANDBOX_LORE” case study because it’s easy to misread as “Seatbelt allows exec if the user selected it”, but the actual effect is primarily about **quarantine/Gatekeeper behavior on outputs written by sandboxed apps**.

Two recurring failure modes this lab is meant to make obvious:

- **Name → mechanism mismatch**: the name sounds like “user selected executable ⇒ may execute”, but the observable delta is often `com.apple.quarantine` metadata, not Seatbelt `process-exec*` authorization.
- **Layer attribution error**: “it ran” can be a Gatekeeper/quarantine outcome, not evidence that the sandbox allowed execution of a staged binary.

This repo includes two XPC services with identical code but different entitlements so you can observe **layer attribution** directly:

- `com.yourteam.entitlement-jail.QuarantineLab_default` (App Sandbox only)
- `com.yourteam.entitlement-jail.QuarantineLab_user_selected_executable` (App Sandbox + `com.apple.security.files.user-selected.executable`)

Supported `payload-class` values: `shell_script`, `command_file`, `text`, `webarchive_like` (and you can force/clear `+x` via `--exec` / `--no-exec`).

Run the lab (writes/opens artifacts and reports `com.apple.quarantine` before/after + raw/parsed fields; it does not execute anything):

```bash
# 1) create_new (default)
./EntitlementJail.app/Contents/MacOS/entitlement-jail quarantine-lab com.yourteam.entitlement-jail.QuarantineLab_default command_file --dir tmp --selection hardcoded
./EntitlementJail.app/Contents/MacOS/entitlement-jail quarantine-lab com.yourteam.entitlement-jail.QuarantineLab_user_selected_executable command_file --dir tmp --selection hardcoded

# 2) open_only (re-open an existing path; record any xattr delta)
./EntitlementJail.app/Contents/MacOS/entitlement-jail quarantine-lab com.yourteam.entitlement-jail.QuarantineLab_default command_file --operation open_only --existing-path <path>

# 3) open_existing_save (read an existing path and save a copy; useful for “launder by saving” claims)
./EntitlementJail.app/Contents/MacOS/entitlement-jail quarantine-lab com.yourteam.entitlement-jail.QuarantineLab_user_selected_executable command_file --operation open_existing_save --existing-path <path> --name saved.command
```

Observe outside the sandbox (unsandboxed host-side witness; always captures `spctl --status` and can optionally run `spctl --assess`, not execution):

```bash
cargo build --manifest-path runner/Cargo.toml --release
runner/target/release/quarantine-observer <path-from-written_path> --assess
```

Note: run `quarantine-observer` directly (do not run it from inside `EntitlementJail.app`, otherwise it will inherit the sandbox and defeat the “outside observer” boundary).
Note: `spctl --assess` is an assessment signal; it is not a faithful simulation of Finder “double-click” prompting behavior.

## Build

The repository contains a build script that assembles and signs the app bundle:

```bash
IDENTITY="Developer ID Application: Your Name (TEAMID)" ./build-macos.sh
```

Optional embeds:

- `EMBED_PROBES_DIR=/path/to/probes` (copied into `Contents/Helpers/Probes/` and signed with inheritance entitlements)
- `EMBED_FENCERUNNER_PATH=/path/to/fencerunner` (copied into `Contents/Helpers/` and signed with inheritance entitlements)
- `BUILD_XPC=0` (skip building embedded XPC services/client)

The resulting app can be notarized and distributed as a normal macOS application.
