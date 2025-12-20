# Experiment Harness (tri-run mismatch atlas)

This directory contains an experiment harness that treats:

- `entitlement-jail` / XPC targets as the **entitlement-defined runtime witness**
- `sandbox-exec` + `.sb` profiles as the **policy-defined runtime witness** (hypothesis only; `sandbox-exec` is deprecated)

The core unit is a **tri-run row**: for the same `probe_id` and `inputs`, emit three comparable outcomes:

1. **baseline** (no `sandbox-exec`, no `entitlement-jail`)
2. **policy** (`sandbox-exec -f <profile.sb> ...`)
3. **entitlement** (`EntitlementJail.app/.../entitlement-jail run-xpc <xpc-service> ...`, with probes executed *in-process* inside the service)

The output is a **mismatch atlas**: where policy↔entitlement parity matches, and where it fails (with explicit layer attribution).

## Contract (frozen)

### Probe row schema

Every probe row is:

```json
{
  "probe_id": "string",
  "inputs": { "kind": "probe|quarantine-lab", "argv": ["..."], "payload_class": "optional" },
  "expected_side_effects": ["string"],
  "capture_spec": { "capture_sandbox_log": true }
}
```

### Probe result schema

Every witness run is normalized into:

```json
{
  "rc": 0,
  "normalized_outcome": "string",
  "errno_or_error": { "errno": 1, "error": "string" },
  "stdout_ref": "relative/path/to/stdout.txt",
  "stderr_ref": "relative/path/to/stderr.txt",
  "layer_attribution": {
    "seatbelt_deny_op": "string|null",
    "service_refusal": "string|null",
    "quarantine_delta": "string|null",
    "world_shape_change": "string|null"
  },
  "sandbox_log_excerpt_ref": "relative/path/to/sandbox-log.txt"
}
```

Hard rule: “couldn’t run” is never collapsed into “denied”. If an outcome cannot be attributed, it is reported as `unknown_needs_evidence` (not as “policy denied”).

## Lattice + profiles

Entitlements are a first-class independent variable **only via XPC service targets** (not via child-process inheritance).

See:

- `experiments/nodes/entitlement-lattice.json` for the entitlement lattice (E0–E3)
- `experiments/policy/` for the “attempted equivalent” `.sb` profiles (P0–P3)

Quarantine Lab is the calibration anchor where parity should fail for principled reasons: quarantine metadata deltas are not a Seatbelt policy knob.

## Build + run

Build the harness + unsandboxed substrate:

```sh
./experiments/build-experiments.sh
```

Build/sign the `.app` with embedded XPC services (see `SIGNING.md` for identities/entitlements order):

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' ./build-macos.sh
```

Run a tri-run plan:

```sh
./experiments/bin/ej-harness run
```

Artifacts land under `experiments/out/…/atlas.json` (the harness prints the absolute path it wrote).

## Notes

- Policy witness profiles in `experiments/policy/*.sb` use `HOME` as a profile parameter; the harness passes it automatically via `sandbox-exec -D HOME=<path> ...`.
- Sandbox log excerpts are best-effort and PID-scoped: for probe runs the harness keys log searches on `ProcessName(pid)` from the JSON `details.pid` field, to avoid cross-run contamination.
