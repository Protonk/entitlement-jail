# entitlement-jail

`entitlement-jail` is a **research/teaching repo** for exploring macOS App Sandbox and entitlement behavior (including “misleading” or security-sensitive entitlements) without collapsing “couldn’t run” into “denied”.

The core output is a **tri-run mismatch atlas**: for the same probe + inputs, produce three comparable outcomes under:

1. **baseline witness**: an unsandboxed “substrate” binary (no `sandbox-exec`, no `entitlement-jail`)
2. **policy witness**: the same substrate under `sandbox-exec -f <profile.sb> …` (hypothesis only; `sandbox-exec` is deprecated)
3. **entitlement witness**: in-process probes inside a selected embedded **XPC service target** (each `.xpc` is its own signed sandbox with its own entitlements)

Every result carries explicit layer attribution:

- **Seatbelt/App Sandbox**: only when an actual deny-op is observed via **host-side** unified log capture (in-app log capture is diagnostic only)
- **Quarantine/Gatekeeper**: measured via `com.apple.quarantine` deltas (and optional observer assessment; assessment is not execution)
- **Service/API refusal**: permission-shaped failures without a deny-op excerpt
- **World-shape effects**: containerization/path-class differences treated as an explicit dimension, not a background confound

## Why the design is XPC-first (and exec-by-path is not the model)

On stock macOS, sandboxed apps commonly hit `process-exec*` denials when attempting to execute binaries staged into **writable/container locations**. This repo intentionally does **not** support “exec arbitrary staged Mach-O by path”.

Instead, entitlements become a first-class independent variable only via **XPC services**:

- Each `.xpc` is a separate signed target with its own entitlements.
- Probes run **in-process** inside the service (avoids `process-exec*` as a precondition).

`run-system` / `run-embedded` still exist for specific demonstrations, but the entitlement lattice is expressed via XPC targets (see `xpc/README.md`).

## What’s inside (high level)

- **`EntitlementJail.app`**: sandboxed Rust launcher (`EntitlementJail.app/Contents/MacOS/entitlement-jail`)
  - `run-system`: allowlisted in-place platform binaries
  - `run-embedded`: bundle-embedded helper tools (sandbox inheritance; strict signing constraints)
  - `run-xpc`: delegate probe execution to a selected XPC service target
  - `quarantine-lab`: write/open/copy artifacts and report `com.apple.quarantine` deltas (no execution)
- **Main app entitlements (research defaults)**: `com.apple.security.app-sandbox` only. Debug/injection/JIT entitlements live on dedicated XPC targets, not the controller.
- **Entitlement lattice (XPC targets)**: one-knob-per-service, currently including:
  - minimal sandbox (baseline)
  - network client
  - Downloads read-write
  - user-selected executable (Quarantine Lab calibration)
  - bookmarks app-scope (calibrates the ScopedBookmarksAgent IPC boundary used by security-scoped bookmarks)
  - debuggable (`get-task-allow` + `disable-library-validation` for notarization compatibility)
  - plugin host relaxed (`disable-library-validation`)
  - DYLD env enabled (`allow-dyld-environment-variables`)
  - fully injectable at launch (disable-library-validation + allow-dyld-environment-variables)
  - JIT MAP_JIT (`allow-jit`)
  - JIT legacy RWX (`allow-unsigned-executable-memory`)
- **Experiment harness**: `experiments/bin/ej-harness` runs tri-runs and writes an `atlas.json`
- **Probe substrate**: `experiments/bin/witness-substrate` runs the same probes outside XPC (baseline/policy witnesses)

## Docs

- [runner/README.md](runner/README.md) — CLI/behavior manual (including Quarantine Lab + unsandboxed observer)
- [xpc/README.md](xpc/README.md) — XPC architecture and extension guide
- [experiments/README.md](experiments/README.md) — tri-run harness (baseline vs policy vs entitlement) + mismatch atlas
- [SIGNING.md](SIGNING.md) — signing order, entitlements, packaging/notarization, troubleshooting
- [CONTRIBUTING.md](CONTRIBUTING.md) — worked examples (including adding a new XPC service target)

## Quick start

Prefer the Makefile entrypoints for builds; they wrap the underlying scripts.

Build the harness + substrate:

```sh
make build-experiments
```

Build/sign the `.app`:

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build
```

Inspection-friendly Swift build (no optimization):

```sh
SWIFT_OPT_LEVEL=-Onone IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build
```

Run the default tri-run plan (writes `experiments/out/.../atlas.json` and prints the path):

```sh
./experiments/bin/ej-harness run
```

Run the debug/JIT lattice plan:

```sh
./experiments/bin/ej-harness run --nodes experiments/nodes/entitlement-lattice-debug-jit.json --plan experiments/plans/tri-run-debug-jit.json
```

## Research posture

Outputs emphasize provenance and **layer attribution** (Seatbelt vs quarantine/Gatekeeper vs “other”).

- The Quarantine Lab writes/opens artifacts and reports `com.apple.quarantine` deltas **without executing anything**.
- The quarantine observer is intentionally run **outside** `EntitlementJail.app` to avoid attribution mixing.
- Deny attribution is only valid when produced by **host-side** log capture; in-app log capture is diagnostic only and may be blocked by the app sandbox.
- If the harness cannot capture a deny-op for a permission-shaped failure, it records the capture attempts and treats the mechanism as “needs evidence”, not as “policy denied”.
