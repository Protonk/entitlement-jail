# EntitlementJail

EntitlementJail is a macOS research/teaching repo where the experiment variable is **entitlements**: you run the same in-process probes inside a zoo of **separately signed, launchd-managed XPC services**, each with its own entitlement profile, and collect stable JSON “witness records” of what happened.

Most of what gets maintained here is the “lab surface”:

- the probe implementations and their safety boundaries,
- the set of base entitlement profiles plus auto-generated injectable twins (one twin per service),
- the `inherit_child` paired-process harness (frozen two-bus protocol + scenario/matrix witness),
- the stable JSON output contract (for downstream tooling), and
- the evidence + tests that keep the bundle and its claims honest.

## Core commitments

- **Entitlements are the variable**: the knob is OS-enforced, separately signed XPC services inside one app; each base service has a build-generated injectable twin with a fixed overlay (variants are first-class).
- **Outcomes first; attribution second**: outputs are witness records (rc/errno/paths/timing) without quietly upgrading them into stronger claims about *why* they happened.
- **Deterministic sessions for attach/debug**: `xpc session` exposes explicit lifecycle events (PID/readiness/wait barriers), so tracing and debugging can coordinate without racing service startup.
- **Evidence is a first-class artifact**: entitlement profiles are derived from *signed* entitlements in built artifacts during the build and embedded into the `.app` for inspection/verification.
- **`inherit_child` is an inspection substrate**: a frozen two-bus protocol (event bus vs rights bus), scenario routing, strict witness invariants, and self-diagnosing failures protected by smoke + golden fixtures.
- **Success is an access delta**: probes record post-action checks; success is “access delta observed”, not “rc==0” (see `sandbox_extension --op update_file_rename_delta` and `inherit_child`).

## What ships

This repo builds a single distributable specimen:

- `EntitlementJail.app` — the bundle you run and inspect
  - `Contents/MacOS/entitlement-jail` (Rust launcher; host-side)
  - `Contents/XPCServices/*.xpc` (Swift services; sandboxed; entitlements vary per service)
  - `Contents/MacOS/ej-inherit-child` + `Contents/MacOS/ej-inherit-child-bad` (paired-process helpers; also embedded per ProbeService bundle)
  - `Contents/Resources/Evidence/*` (generated manifests: entitlements, hashes, profiles, symbols)
- `EntitlementJail.md` — the user guide shipped alongside the app

## The Core Model
>Profiles → Sessions → Probes → Witnesses

The preferred execution surface is in-process probes dispatched by `probe_id` (not arbitrary path execution). If you want a three-way comparison (baseline vs `sandbox-exec` vs XPC), the tri-run harness under `experiments/` produces a mismatch atlas.

## Where To Learn

If you're...
- using the app / workflows: [`EntitlementJail.md`](EntitlementJail.md)
- orienting yourself in the repo: [`AGENTS.md`](AGENTS.md)
- contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- signing/distributing: [`SIGNING.md`](SIGNING.md)
- testing: [`tests/README.md`](tests/README.md)
- changing...
  - CLI behavior/output contracts: [`runner/README.md`](runner/README.md)
  - XPC services, probes, or session semantics: [`xpc/README.md`](xpc/README.md)
  - the tri-run experiment harness: [`experiments/README.md`](experiments/README.md)
