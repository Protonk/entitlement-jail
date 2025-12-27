# EntitlementJail

EntitlementJail is a macOS research/teaching repo that’s intentionally biased toward producing **witness records** (structured outcome descriptions) without quietly upgrading those outcomes into stronger claims about *why* they happened.

## What This Repo Optimizes For

It’s most useful when you treat a “permission-shaped failure” as a *routing problem*: missing files, signing validity, quarantine/Gatekeeper, launchd/XPC behavior, filesystem permissions, and Seatbelt/App Sandbox can all produce similar-looking symptoms. This repo tries to keep those layers explicit and keep the output contract stable enough for downstream tooling.

- **Entitlements as a real experimental variable**: the “thing you run” isn’t one binary; it’s an app bundle that embeds many separately signed executables. The core research targets are launchd-managed XPC services, each signed with a distinct entitlement profile.
- **Outcomes first; attribution second**: probes emit outcomes (rc/errno/paths/timing) as JSON envelopes. If you want deny evidence, use an explicit outside-the-sandbox witness (`sandbox-log-observer`) rather than baking attribution into every probe.
- **Deterministic attachment**: `xpc session` exposes a deliberate, lifecycle-aware service session surface (PID, readiness events, and a wait barrier) so debuggers/tracers can attach without racing startup.
- **Reverse-engineer-friendly code**: the Swift/Rust code is written to be read directly (and to be easy to instrument), not to hide control flow behind clever abstractions.

## The Product Shape

The intended distribution artifact is only the set of:

- `EntitlementJail.app` (the bundle) + [`EntitlementJail.md`](EntitlementJail.md) (the user guide)

Inside the bundle:

- `Contents/MacOS/entitlement-jail` — the host-side launcher (Rust; plain-signed; not sandboxed).
- `Contents/XPCServices/*.xpc` — the process zoo (Swift; sandboxed; entitlements vary per-service).
- `Contents/Resources/Evidence/*` — signed “static evidence” for inspection (entitlements, hashes, profiles, trace symbols).

The user guide is written deliberately as the only window (outside of CLI `--help`) into intent for the end user. 

## The Core Model (Profiles → Sessions → Probes → Witnesses)

Most work in EntitlementJail has the same shape:

1. Pick a **profile** (an embedded XPC service signed with a specific entitlement set).
2. Open a **session** (`entitlement-jail xpc session`) if you need deterministic attach/liveness, or use `entitlement-jail xpc run` for a one-shot run.
3. Run one or more **probes** (by `probe_id`) inside the service.
4. Read the resulting **witness record** (JSON). If you need deny evidence, collect it separately with `sandbox-log-observer`.

The “unit of variation” is a whole separately-signed, launchd-managed service — not a transient child process that inherits a grab bag of state.

If you want a 3-witness comparison (baseline vs `sandbox-exec` vs XPC), the tri-run harness lives under [`experiments/`](experiments/) (see [`experiments/README.md`](experiments/README.md)) and produces a mismatch atlas.

## Where To Start (Documents)

- If you’re using the built artifact: [`EntitlementJail.md`](EntitlementJail.md)
- If you’re contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- If you’re changing signing/distribution: [`SIGNING.md`](SIGNING.md)
- If you’re changing CLI behavior/output contracts: [`runner/README.md`](runner/README.md)
- If you’re changing XPC services, probes, or session semantics: [`xpc/README.md`](xpc/README.md)
- If you’re changing the tri-run experiment harness: [`experiments/README.md`](experiments/README.md)
- If you’re trying to orient yourself in the repo (layout + invariants): [`AGENTS.md`](AGENTS.md)
