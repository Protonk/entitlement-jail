# entitlement-jail

`entitlement-jail` is a macOS research/teaching repo for exploring **App Sandbox + entitlement behavior** without turning every “couldn’t do X” into “the sandbox denied X”.

Most macOS “sandbox demos” collapse a bunch of failure modes into one bucket. A `posix_spawn` failure might be a missing file, a bad signature, a quarantine/Gatekeeper prompt, a path policy, or a Seatbelt denial — and those are different conversations. This repo tries to keep those conversations separate by default, and to make it easy to attach evidence to claims (for example, capturing `Sandbox:` deny lines when requested, and shipping signed “static evidence” inside the bundle).

It also tries to keep “entitlements as an experimental variable” structurally clean. Rather than staging binaries into writable locations and trying to exec them by path (a pattern that is commonly blocked and easy to misattribute), EntitlementJail runs probes **in-process** inside launchd-managed XPC services. Each `.xpc` is its own signed target with its own entitlements, so you can run the same probe code path under different entitlement profiles.

## What’s in the box

The shipped app bundle (`EntitlementJail.app`) contains a sandboxed CLI launcher and a “process zoo” of embedded XPC services:

`EntitlementJail.app/Contents/MacOS/entitlement-jail` (Rust; see `runner/`) is the main entrypoint. `EntitlementJail.app/Contents/XPCServices/*.xpc` (Swift; see `xpc/`) are the research targets: the same probes, signed over and over with different entitlements.

For “compare across witnesses” work, `experiments/` contains a tri-run harness that can execute the same probe three ways: a baseline run (unsandboxed substrate), a policy run (`sandbox-exec -f …`; hypothesis only, and `sandbox-exec` is deprecated), and an entitlement run (via `EntitlementJail.app … run-xpc …`, with the probe executed inside an XPC service). The result is an `atlas.json` mismatch map with explicit attribution rules; see `experiments/README.md`.

For reproducibility and downstream inspection, the app bundle also ships signed evidence files under `Contents/Resources/Evidence/` (hashes, entitlements, profile definitions, and stable `ej_*` marker symbols). The user-facing inspection commands live in `EntitlementJail.md`; the developer-facing behavior reference lives in `runner/README.md`.

## Doc map

- If you’re trying to *use the tool*, start with `EntitlementJail.md`.
- If you’re trying to understand *what the CLI claims/measures*, read `runner/README.md`.
- If you want to add or modify XPC targets (entitlements as the variable), read `xpc/README.md`.
- If you’re building/signing/notarizing, `SIGNING.md` is the canonical reference.
- If you’re extending or reporting on results, read `AGENTS.md`.

A quick repo layout:

- `runner/` — Rust CLI (builds `EntitlementJail.app/Contents/MacOS/entitlement-jail`)
- `xpc/` — Swift XPC substrate + in-process probes + XPC clients
- `experiments/` — tri-run harness + unsandboxed substrate + policy profiles
- `tests/` — smoke harness + preflight gate + fixtures
- `build-macos.sh` — builds/signs the `.app`, generates evidence, produces `EntitlementJail.zip`
- `SIGNING.md` — signing/notarization policy, procedure, and troubleshooting
- `EntitlementJail.md` — self-contained user guide for distribution

## Use

The intended distribution artifact is the notarized `.app` zip in GitHub releases. For downstream use you should only need `EntitlementJail.app` and `EntitlementJail.md`.

## Build

All build, signing, packaging, and notarization steps are intentionally centralized in [SIGNING.md](SIGNING.md). This README does not repeat commands or signing order; if you need to build or re-sign anything, follow that doc rather than improvising.

## Test

Run everything:

```sh
make test
```

`make test` starts with a read-only preflight (`tests/preflight.sh`) that verifies signatures and extracts entitlements into `tests/out/preflight.json`, so higher-level tests can skip cleanly when signing is stale or missing. It then runs runner unit tests and CLI integration tests (`EJ_INTEGRATION=1`), followed by the smoke harness (`tests/ej-smoke.sh`), which writes artifacts under `experiments/out/test` (overwritten each run).

If you set `EJ_DLOPEN_TESTS=1`, the `dlopen_external` integration test is enabled and will execute a signed test dylib initializer; treat that as intentional code execution.
