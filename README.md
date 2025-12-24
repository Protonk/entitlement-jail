# entitlement-jail

`entitlement-jail` is a macOS research/teaching repo for exploring **App Sandbox + entitlement behavior** while keeping “what happened” and “which subsystem caused it” separate.

## Contents

### 1) A process zoo (`EntitlementJail.app`)

The app embeds a **sandboxed CLI** and a set of embedded XPC services:

- The CLI is `EntitlementJail.app/Contents/MacOS/entitlement-jail` (Rust; see `runner/`).
- Each XPC service is its own signed executable with its own entitlement profile (Swift; see `xpc/`).
- Probes run **in-process** inside the selected XPC service (no arbitrary exec-by-path required).

This gives a clean experimental matrix:

> same probe code path, different entitlements


### 2) A tri-run harness (mismatch atlas)

Under `experiments/` there is an experiment harness that can run the same probe as three “witnesses”:

1. **baseline witness** (unsandboxed substrate)
2. **policy witness** (`sandbox-exec -f profile.sb …`; hypothesis only, `sandbox-exec` is deprecated)
3. **entitlement witness** (`EntitlementJail.app … run-xpc …`; probes in-process inside an XPC service)

The output is an `atlas.json` mismatch map with explicit attribution rules. See `experiments/README.md`.

### 3) Signed evidence artifacts (“BOM”)

The app bundle contains evidence files under `Contents/Resources/Evidence/`:

- `manifest.json`: hashes + entitlements for embedded Mach-Os (signed as part of the app bundle)
- `profiles.json`: the process zoo profile list (risk tiers, tags, entitlements)
- `symbols.json`: stable `ej_*` marker symbol names for external tooling correlation

See `runner/README.md` and `EntitlementJail.md` for the user-facing commands (`verify-evidence`, `inspect-macho`, `bundle-evidence`).

## Repo layout

- `runner/` — Rust CLI (builds `EntitlementJail.app/Contents/MacOS/entitlement-jail`)
  - `runner/README.md` — authoritative CLI/behavior manual (dev-facing)
- `xpc/` — Swift XPC substrate + in-process probes + XPC clients
  - `xpc/README.md` — architecture notes and extension guidance
- `experiments/` — tri-run harness + unsandboxed substrate + policy profiles
- `tests/` — smoke harness + preflight gate + fixtures
  - `tests/preflight.sh` — codesign/entitlement preflight for integration tests (no execution)
  - `tests/ej-smoke.sh` — smoke tri-run plan (writes `experiments/out/test`)
  - `tests/fixtures/` — small signed fixtures used by optional tests
- `build-macos.sh` — builds/signs the `.app`, generates evidence, produces `EntitlementJail.zip`
- `SIGNING.md` — signing/notarization policy and troubleshooting (procedure lives here)
- `EntitlementJail.md` — distribution user guide (self-contained; do not require repo context)

## Build (development)

Build the experiment harness + substrate:

```sh
make build-experiments
```

Build/sign the `.app` (requires a Developer ID Application identity):

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build
```

Inspection-friendly builds are the default (symbols + frame pointers + reduced Swift optimization). To build an optimized release:

```sh
EJ_INSPECTION=0 IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build
```

Notarization/stapling guidance lives in `SIGNING.md`.

## Test

Run everything:

```sh
make test
```

What `make test` does:

- Runs `tests/preflight.sh` and writes `tests/out/preflight.json`.
  - This is a **read-only** inspection step (codesign verification + entitlement extraction).
  - Integration tests use this to skip attach/entitlement tests when signatures are stale or missing.
- Runs runner unit tests + CLI integration tests (`EJ_INTEGRATION=1`).
- Runs the smoke harness (`tests/ej-smoke.sh`), writing artifacts under `experiments/out/test` (overwritten each run).

Optional:

- Set `EJ_DLOPEN_TESTS=1` to enable the `dlopen_external` integration test (it executes the signed test dylib initializer).

## JSON outputs (uniform envelope)

All JSON emitters in this repo (CLI commands, XPC clients, helper tools) share a uniform envelope:

- Contract + examples: `runner/README.md`
- Code: `runner/src/json_contract.rs`

Key rule for consumers: look at `result` for the outcome (`rc` or `exit_code`), and `data` for command-specific payload.

## Extension rules (high level)

This repo treats entitlements as the experimental variable. To add experiments safely:

- Prefer adding a **new XPC service target** (new directory under `xpc/services/<ServiceName>/`) with its own `Entitlements.plist`.
- Avoid “stage Mach‑O into writable/container location then exec-by-path” patterns; App Sandbox commonly denies `process-exec*` there.
- Any time you add a new executable to the bundle (helpers or XPC services), signing order matters; update `SIGNING.md` (policy/procedure lives there).
