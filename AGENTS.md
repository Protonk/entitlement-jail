# AGENTS.md (contributor router + invariants)

EntitlementJail is a macOS research/teaching repo that builds a single distributable artifact: `EntitlementJail.app`. The “experiment variable” is **which embedded XPC service you run**, because each `.xpc` is separately signed with its own entitlements.

This file is for people and agents *working in the repo*: where to make changes, what contracts exist, what you must keep stable, and the fastest way to orient yourself when something breaks.

## Quick router (what to open first)

Pick the thing you’re changing:

- **User-facing usage / workflows** → [`EntitlementJail.md`](EntitlementJail.md) (the **only** user-facing guide)
- **CLI behavior contract** → [`runner/README.md`](runner/README.md) (authoritative; flags, refusal rules, JSON kinds)
- **XPC architecture + how to add services** → [`xpc/README.md`](xpc/README.md)
- **Tri-run harness + mismatch atlas schema** → [`experiments/README.md`](experiments/README.md)
- **Signing/build/notarization procedure** → [`SIGNING.md`](SIGNING.md) (single source of truth)

Pick the thing that’s failing:

- **Build/sign/packaging failure** → `build-macos.sh`, then `SIGNING.md`, then `tests/run.sh --suite preflight`
- **XPC service won’t launch / replies malformed** → `xpc/services/*/main.swift`, `xpc/ProbeAPI.swift`, `xpc/InProcessProbeCore.swift`
- **JSON output changed / tests flaky** → `runner/src/json_contract.rs` (envelope + key ordering), `runner/tests/cli_integration.rs`, `tests/suites/smoke/*.sh`
- **Profiles/risk tiers look wrong** → `tests/build-evidence.py` (generates `profiles.json` and risk tiers)

## Repo layout (mental model)

This repo is intentionally multi-language:

- `runner/` (Rust): builds the CLI that ships as `EntitlementJail.app/Contents/MacOS/entitlement-jail`
  - Owns: command parsing, refusal-by-design boundaries, JSON envelope, risk-gating, evidence inspection.
- `xpc/` (Swift): builds the embedded XPC client helpers and all XPC services.
  - Owns: XPC wire types (`ProbeAPI.swift`) and the in-process probe implementation (`InProcessProbeCore.swift`).
- `experiments/` (Swift + scripts): tri-run harness + policy profiles (`sandbox-exec`) + baseline substrate.
- `tests/` (bash + python): smoke tests, preflight signing checks, evidence BOM generator.
- `build-macos.sh` (bash): builds everything into `EntitlementJail.app`, generates evidence, codesigns, and zips.

The app bundle is a *layout contract*:

- `EntitlementJail.app/Contents/MacOS/entitlement-jail` (Rust CLI launcher)
- `EntitlementJail.app/Contents/MacOS/xpc-probe-client` (Swift; NSXPCConnection wrapper)
- `EntitlementJail.app/Contents/MacOS/xpc-quarantine-client` (Swift; QuarantineLab wrapper)
- `EntitlementJail.app/Contents/MacOS/sandbox-log-observer` (Rust observer helper)
- `EntitlementJail.app/Contents/XPCServices/*.xpc` (Swift services; entitlement variable)
- `EntitlementJail.app/Contents/Resources/Evidence/*` (generated manifests: hashes, profiles, symbols)

If you change names/paths here, expect downstream breakage (tests, docs, evidence verification).

## Build + signing (how this repo actually ships)

Preferred build entrypoints:

- `make build` → runs `./build-macos.sh`
- `make test` → runs `tests/run.sh --all` (preflight, Rust unit/integration, smoke scripts; these will execute the CLI)

Key build facts worth knowing before you touch anything:

- `build-macos.sh` requires `IDENTITY` to be set to a **Developer ID Application** identity present in your keychain (it validates via `security find-identity -p codesigning`).
- `build-macos.sh` compiles:
  - Rust binaries from `runner/Cargo.toml` (`runner`, `quarantine-observer`, `sandbox-log-observer`, `ej-inspector`)
  - Swift client(s) + every service under `xpc/services/*` (enumerated dynamically)
- Build knobs (mostly for debugging):
  - `EJ_INSPECTION=1` (default) builds with symbols/frame pointers; set `EJ_INSPECTION=0` for a more optimized build.
  - `BUILD_XPC=0` skips building/embedding XPC services and Swift clients (useful when iterating only on Rust).
  - `SWIFT_OPT_LEVEL`, `SWIFT_DEBUG_FLAGS`, `RUSTFLAGS` are respected by the build script.
- Evidence is generated during the build:
  - `tests/build-evidence.py` writes `Contents/Resources/Evidence/manifest.json`, `profiles.json`, `symbols.json`
  - `profiles.json` is *derived* from on-disk service entitlements (extracted via `codesign -d --entitlements`)
- Signing is “inside-out”:
  - Sign nested tools/services first, then sign the outer `.app` last (avoid using `codesign --deep` for signing).
  - All embedded code should share the same Team ID (mixing identities breaks assumptions).
- Swift module cache must be writable:
  - `build-macos.sh` defaults `SWIFT_MODULE_CACHE=.tmp/swift-module-cache` because sandboxed harnesses often block `~/.cache`.

## Invariants (treat these as contracts)

### Execution surfaces are intentionally constrained

- **No “exec arbitrary path” feature**: the CLI rejects “run this staged Mach‑O by path” patterns by design.
  - This is a core research invariant (it prevents the classic “exec from writable container” failure mode from dominating everything).
  - See `runner/README.md` (“Core rule: arbitrary path exec is rejected by design”).

### Entitlements vary via XPC services (not inheritance)

- The launcher is host-side and plain-signed by default; the **sandbox boundary** lives in the XPC services.
- The preferred “new entitlement” work item is: add a new XPC service target under `xpc/services/`.

### XPC wire format is JSON-over-Data

- `ProbeAPI.swift` defines `RunProbeRequest/RunProbeResponse` and `QuarantineWriteRequest/QuarantineWriteResponse`.
- Services and clients pass JSON bytes (`Data`) rather than rich XPC objects.
  - If you evolve these types, update both sides together, bump `schema_version` when the JSON contract changes, and delete old protocol paths (no long-lived shims).
- The Rust launcher does not speak NSXPC directly; `entitlement-jail xpc {run,session}` and `quarantine-lab` shell out to the embedded Swift clients under `Contents/MacOS/`.

### JSON envelopes are stable and key-sorted

- Rust emitters share a uniform envelope (`schema_version`, `kind`, `generated_at_unix_ms`, `result`, `data`).
- Keys are lexicographically sorted for output stability (`runner/src/json_contract.rs`).
  - If you add fields, expect snapshot-ish tests and downstream tooling to notice.

### Evidence is a first-class artifact, not a side effect

- `verify-evidence` and `inspect-macho` depend on evidence manifests written into the `.app`.
- If you add/rename embedded binaries, update whatever generates or validates evidence:
  - Usually this is just “rebuild so `tests/build-evidence.py` re-enumerates”, but sometimes it’s also “teach the tool how to describe it”.

### Service naming is build-script-sensitive

`build-macos.sh` assumes:

- Each directory under `xpc/services/<ServiceName>/` is one service.
- The service bundle is named `<ServiceName>.xpc`.
- The service executable is named exactly `<ServiceName>` and lives at `Contents/MacOS/<ServiceName>`.
- Each service directory contains `Info.plist`, `main.swift`, and `Entitlements.plist`.

If those don’t line up, the build fails or (worse) XPC lookup fails at runtime.

### Risk gating is derived; keep it honest

- Risk tiers/warnings are not hand-maintained—they’re derived from entitlements in `tests/build-evidence.py`.
- The CLI enforces `--ack-risk` for tier-2 profiles (high concern) (`runner/src/main.rs`).
- If you introduce new “high concern” entitlements, update the risk classifier so profiles land in the correct tier.

### Probes must not reintroduce path-exec or dangerous defaults

In-process probes are meant to be:

- **identifier dispatched** (caller passes `probe_id`, not a filesystem path to execute),
- **safe-by-default** for filesystem operations (writes gated to harness paths or explicit override flags),
- **explicit about intentional code execution** (e.g. `dlopen_external`).

The reference patterns live in `xpc/InProcessProbeCore.swift`.

## Common contributor tasks (where to edit)

### Add a new entitlement profile (recommended: new XPC service)

1. Copy an existing service directory under `xpc/services/` (e.g. `ProbeService_minimal/`).
2. Edit `Entitlements.plist` (this is the variable).
3. Ensure `Info.plist` has a unique `CFBundleIdentifier`.
4. Rebuild so evidence/profiles are regenerated (and signing includes the new service).
5. Update docs if the new profile should be discoverable:
   - `xpc/README.md` (service list / purpose)
   - `EntitlementJail.md` (user-visible profile/workflow) if appropriate

### Add a new probe

1. Add implementation in `xpc/InProcessProbeCore.swift` (dispatch by `probe_id`).
2. Add/update help text and ensure it returns structured `normalized_outcome` + details.
3. If you want it externally traceable, add a stable `ej_*` marker and expose it via `probe_catalog`.
4. Consider updating smoke/integration tests to cover the new probe without heavy side effects.

### Change CLI behavior or outputs

1. Implement in `runner/src/main.rs` (and friends).
2. Update the authoritative behavior docs in `runner/README.md`.
3. If the change affects end users, also update `EntitlementJail.md`.
4. If JSON output schema changes, be deliberate: keep old fields where possible, and only bump schema when necessary.

## Testing notes (what runs what)

- `tests/suites/preflight/preflight.sh` is intentionally “observer style”: it inspects signatures/entitlements and emits a JSON report under `tests/out/<run_id>/suites/preflight/...`.
  - Integration tests use it to decide what to skip via `EJ_PREFLIGHT_JSON`.
- `runner/tests/cli_integration.rs` expects a built `EntitlementJail.app` unless you set `EJ_BIN_PATH`.
- Smoke scripts (`tests/suites/smoke/*.sh`) write under `tests/out/<run_id>/suites/smoke/...` and overwrite prior runs within that run directory.

## Safety defaults (for agents)

- Treat `EntitlementJail.app` and produced zips as **specimens**: don’t execute them unless the user explicitly asks.
- Prefer read-only inspection when diagnosing signing/quarantine questions (`codesign -d`, `spctl -a`, xattr reads, etc.).
- If you do add a feature that intentionally executes code (e.g. dylib initializers), make it opt-in and label it clearly in docs and risk gating.
