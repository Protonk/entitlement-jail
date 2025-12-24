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
  "row_id": "string (optional; defaults to probe_id)",
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
  "sandbox_log_excerpt_ref": "relative/path/to/sandbox-log.txt",
  "sandbox_log_capture": {
    "attempts": [
      {
        "start_iso8601": "string",
        "end_iso8601": "string",
        "predicate": "string",
        "term": "string",
        "observed_deny": true,
        "deny_op": "string|null",
        "excerpt_ref": "relative/path/to/sandbox-log.txt"
      }
    ]
  },
  "path_evidence": {
    "effective_path_class": "host_path|container_path|synthesized_temp_path|other_path|null",
    "paths": {
      "target_path": {
        "raw": "string",
        "realpath": "string|null",
        "path_class": "string",
        "realpath_class": "string|null"
      }
    }
  }
}
```

Hard rule: “couldn’t run” is never collapsed into “denied”. `seatbelt_deny_op` is only set when a deny line is actually observed (via sandbox log capture); otherwise it remains `null` and the capture attempts record whether a deny line was observed in the window.

`row_id` is used for artifact directory naming. If you want multiple rows that use the same `probe_id` with different `inputs.argv` (for example multiple `fs_op` variants), set distinct `row_id` values.

## Lattice + profiles

Entitlements are a first-class independent variable **only via XPC service targets** (not via child-process inheritance).

See:

- `experiments/nodes/entitlement-lattice.json` for the entitlement lattice (E0–E4)
- `experiments/nodes/entitlement-lattice-debug-jit.json` for the debug/JIT/profile lattice (E0, E5–E10; policy profile remains P0_minimal as a baseline reference)
- `experiments/policy/` for the “attempted equivalent” `.sb` profiles (P0–P4)

Quarantine Lab is the calibration anchor where parity should fail for principled reasons: quarantine metadata deltas are not a Seatbelt policy knob.

## Build + run

Build the harness + unsandboxed substrate (preferred: Makefile):

```sh
make build-experiments
```

Inspection-friendly Swift build (no optimization):

```sh
SWIFT_OPT_LEVEL=-Onone make build-experiments
```

Build/sign the `.app` with embedded XPC services (preferred: Makefile; see `SIGNING.md` for identities/entitlements order):

Signing, packaging, and distribution procedures are centralized in [SIGNING.md](../SIGNING.md). This README intentionally does not repeat signing commands or identity guidance; follow the signing doc to produce a runnable `EntitlementJail.app` for entitlement witness runs.

Run a tri-run plan:

```sh
./experiments/bin/ej-harness run
```

Run the trimmed lattice (E0–E2):

```sh
./experiments/bin/ej-harness run --nodes experiments/nodes/entitlement-lattice-e0-e2.json
```

Run the debug/JIT lattice plan:

```sh
./experiments/bin/ej-harness run --nodes experiments/nodes/entitlement-lattice-debug-jit.json --plan experiments/plans/tri-run-debug-jit.json
```

Note: `dlopen_external` is a manual probe (requires an explicit path or `EJ_DLOPEN_PATH`), and DYLD env behavior is intentionally not exercised here.

Run the parametric demo plan (shows `row_id` with multiple `fs_op` rows):

```sh
./experiments/bin/ej-harness run --plan experiments/plans/tri-run-parametric-demo.json
```

Run the smoke plan (minimal, low-side-effect):

```sh
./experiments/bin/ej-harness run --plan experiments/plans/tri-run-smoke.json
```

Artifacts land under `experiments/out/…/atlas.json` (the harness prints the absolute path it wrote).

## Notes

- Policy witness profiles in `experiments/policy/*.sb` use `HOME` as a profile parameter; the harness passes it automatically via `sandbox-exec -D HOME=<path> ...`.
- Sandbox log capture is best-effort and PID-scoped: for probe runs the harness keys log searches on `ProcessName(pid)` from the JSON `details.probe_pid`/`details.service_pid` fields (falls back to `details.pid`), to avoid cross-run contamination.
- Entitlement witness tightening: when a probe returns a permission-shaped error and no deny op is observed, the harness automatically retries sandbox log capture with a wider window and a stricter predicate (see `sandbox-log-retry.txt` when present).
- When invoking `EntitlementJail.app` commands from a sandboxed context, write outputs under the container home (the JSON `output_dir` is authoritative). Do not assume repo paths are writable from inside the sandbox; copy artifacts out as needed.
