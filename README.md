# PolicyWitness

PolicyWitness is a macOS tool to instrument App Sandbox and entitlement effects without hand-waving. It gives you a structured witness of what ran and what changed alongside on-demand lifecycle context about the sandboxed service and any child processes. Together, this makes sandbox attribution reproducible by separating OS policy enforcement from early process death, harness failures, and session restarts.

For sandbox instrumentation, the “API” you usually get back is just EPERM/EACCES (or a killed process), which rarely tells you what policy check fired, which operation/path/class triggered it, or whether you even reached the code you think you reached. Seatbelt/unified-log deny lines are often the only concrete explanation the OS will give you, but they’re easy to miss (wrong PID, process exits fast, log filtering, “deny” is silent for some paths) and easy to mis-correlate after the fact. 

PolicyWitness avoids these issues because it keeps the control plane outside the sandbox and treats the XPC service as the sandbox boundary. That posture lets it start the service deterministically, record its PID, and observe lifecycle outcomes even when sandboxed code fails fast. When a probe needs liveness across multiple operations, it uses a durable session so all phases run in the same service process context. It also requires ultra-early sentinels and explicit lifecycle events from the service and any child helpers so “no event stream” becomes diagnostic rather than ambiguous. 

What’s hard in computing security is making correct claims about boundaries. The sandbox is an especially hard boundary to make a claim about because it often collapses into ambiguous signals, depends on identity and context, and frequently requires external evidence to attribute a denial. PolicyWitness makes claims by producing per-phase, per-process witnesses with durable-session context and explicit lifecycle signals.

## The Core Model
>Profiles → Sessions → Probes → Witnesses

The preferred execution surface is in-process probes dispatched by `probe_id` (not arbitrary path execution). If you want a three-way comparison (baseline vs `sandbox-exec` vs XPC), the tri-run harness under `experiments/` produces a mismatch atlas.

## Commitments

* Signed profiles are the variable: the sandbox boundary lives in separately signed XPC services (and variants) embedded in one app, so the same probe runs under OS-enforced entitlement differences rather than ad-hoc inheritance tricks.
* Witness over interpretation: probes emit per-phase action/outcome records (rc/errno/paths/timing) and access-delta checks, so success and failure are defined by observable transitions, not return codes or narrative attribution.
* Lifecycle is part of the experiment: the control plane stays outside the sandbox and uses durable sessions plus explicit lifecycle signals and ultra-early sentinels so fast exits, restarts, and missing child event streams are diagnosable.
* Two-bus child semantics are explicit: inherit_child separates structured events from SCM_RIGHTS capability passing and enforces protocol validation so child/harness mismatches surface as explicit protocol errors rather than silent misreads.

## What ships

This repo builds a single distributable specimen:

- `PolicyWitness.app` — the bundle you run and inspect
  - `Contents/MacOS/policy-witness` (Rust launcher; host-side)
  - `Contents/XPCServices/*.xpc` (Swift services; sandboxed; entitlements vary per service)
  - `Contents/MacOS/pw-inherit-child` + `Contents/MacOS/pw-inherit-child-bad` (paired-process helpers; also embedded per ProbeService bundle)
  - `Contents/Resources/Evidence/*` (generated manifests: entitlements, hashes, profiles, symbols)
- `PolicyWitness.md` — the user guide shipped alongside the app

## Where To Learn

If you're...
- using the app / workflows: [`PolicyWitness.md`](PolicyWitness.md)
- orienting yourself in the repo: [`AGENTS.md`](AGENTS.md)
- contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- signing/distributing: [`SIGNING.md`](SIGNING.md)
- testing: [`tests/README.md`](tests/README.md)
- changing...
  - CLI behavior/output contracts: [`runner/README.md`](runner/README.md)
  - XPC services, probes, or session semantics: [`xpc/README.md`](xpc/README.md)
  - the tri-run experiment harness: [`experiments/README.md`](experiments/README.md)
