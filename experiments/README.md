# `experiments/` (tri-run harness: mismatch atlas)

This is developer documentation for the experiment harness under `experiments/`. It’s a **tri-run** runner that executes the same probe inputs three ways and writes a structured **mismatch atlas** (`atlas.json`) describing where the witnesses agree and where they diverge.

The tri-run witnesses are:

1. **baseline** — an unsandboxed Swift substrate binary
2. **policy** — the same substrate under `sandbox-exec -f <profile.sb>` (hypothesis witness; `sandbox-exec` is deprecated)
3. **entitlement** — `PolicyWitness.app` running probes inside sandboxed XPC services (entitlements are the variable)

Related docs:

- CLI behavior and JSON envelopes: [runner/README.md](../runner/README.md)
- XPC services as entitlement targets: [xpc/README.md](../xpc/README.md)
- End-user workflows (matrix runs, log capture, evidence): [PolicyWitness.md](../PolicyWitness.md)
- Build/sign the app bundle: [SIGNING.md](../SIGNING.md)

## What lives in `experiments/`

Build outputs:

- `bin/pw-harness` — the tri-run harness (built from `harness/main.swift`)
- `bin/witness-substrate` — the baseline/policy witness runner (built from `substrate/main.swift`)

Sources:

- `build-experiments.sh` — compiles the two binaries above using `xcrun swiftc`
- `harness/main.swift` — tri-run orchestration, normalization, mismatch classification, log capture
- `substrate/main.swift` — unsandboxed “witness substrate” that runs the same in-process probes as XPC services

Inputs:

- `plans/*.json` — which probes to run (rows)
- `nodes/*.json` — which “lattice nodes” to run them across (policy profile + XPC service ids)
- `policy/*.sb` — SBPL profiles used by the policy witness (`sandbox-exec`)

Outputs:

- `out/<plan-id>-<timestamp>/atlas.json` plus per-row artifacts (`stdout.txt`, `stderr.txt`, sandbox log excerpts, copied policy profiles)

## Build

Preferred entrypoint:

```sh
make build-experiments
```

This runs `./experiments/build-experiments.sh`, which:

- builds `experiments/bin/witness-substrate` from:
  - `xpc/ProbeAPI.swift`
  - `xpc/InProcessProbeCore.swift`
  - `experiments/substrate/main.swift`
- builds `experiments/bin/pw-harness` from:
  - `xpc/ProbeAPI.swift`
  - `experiments/harness/main.swift`

Useful knobs:

- `SWIFT_OPT_LEVEL=-Onone make build-experiments` for a more inspection-friendly build
- `SWIFT_MODULE_CACHE=...` to relocate the Swift module cache (defaults to `./.tmp/swift-module-cache`)

## Run

The harness CLI is intentionally tiny:

```sh
./experiments/bin/pw-harness run [options]
```

Options (see `experiments/harness/main.swift` for the authoritative defaults):

- `--plan <path>` (default: `experiments/plans/tri-run-default.json`)
- `--nodes <path>` (default: `experiments/nodes/entitlement-lattice.json`)
- `--out-dir <dir>` (default: `experiments/out/<plan-id>-<timestamp>`)
- `--substrate <path>` (default: `experiments/bin/witness-substrate`)
- `--policy-witness <path>` (default: `PolicyWitness.app/Contents/MacOS/policy-witness`)

The command prints the absolute path to the written `atlas.json` (one line).

Common runs:

```sh
./experiments/bin/pw-harness run
./experiments/bin/pw-harness run --plan experiments/plans/tri-run-smoke.json
./experiments/bin/pw-harness run --nodes experiments/nodes/entitlement-lattice-e0-e2.json
./experiments/bin/pw-harness run --nodes experiments/nodes/entitlement-lattice-debug-jit.json --plan experiments/plans/tri-run-debug-jit.json
```

## The witness model (what’s being compared)

### Baseline and policy use the same probe implementation

The baseline and policy witnesses both execute `experiments/bin/witness-substrate`. That binary calls directly into `xpc/InProcessProbeCore.swift`, so probe behavior is shared with the XPC services.

The policy witness is simply:

```sh
/usr/bin/sandbox-exec -D HOME=/Users/<you> -f <profile.sb> <baseline argv...>
```

The `-D HOME=...` parameter is required because the SBPL profiles reference `(param "HOME")`.

### Entitlement witness goes through `PolicyWitness.app`

The entitlement witness uses the shipped CLI and the XPC services specified by the node:

- probe rows → `PolicyWitness.app/.../policy-witness xpc run --service <service> <probe-id> ...`
- quarantine-lab rows → `PolicyWitness.app/.../policy-witness quarantine-lab <service> <payload-class> ...`

Those commands rely on a built and signed `PolicyWitness.app` with the expected embedded services. See [SIGNING.md](../SIGNING.md).

### About `sandbox-exec`

`sandbox-exec` is deprecated. In this repo it’s treated as a **policy-defined runtime witness** for teaching/research only, not as a faithful model of App Sandbox.

## Semantics harnesses (treat these as contracts)

Some probes are intentionally “semantics harnesses”: their outputs encode how to interpret tricky OS behavior, and the repo defends them with smoke + fixtures.

- `sandbox_extension --op update_file_rename_delta`:
  - Records the deny→allow transition (`open_read` `EPERM` before consume; issue+consume allow in the same process context).
  - Records that the grant is path-scoped (inode-preserving rename does not transfer access to the new path).
  - Shows that `update_file(path)` can retarget access; `update_file_by_fileid` may return `rc==0` with no access delta (rc is not evidence).
  - Defines success as “access delta observed” and records `*_changed_access` plus post-call access checks per candidate.
  - Enforces uncheatable gating (destination non-existent, inode-preserving/same-device rename) and stops with distinct normalized outcomes when the premise fails.
  - Persists full stat snapshots and wait/poll observations (`--wait-for-external-rename`) so host choreography is reproducible.
  - Frozen demonstration: `tests/fixtures/update_file_rename_delta/` (scrubbed fixtures compared by `tests/suites/smoke/update_file_rename_delta_fixtures.sh`).

- `inherit_child`:
  - Uses durable sessions and strict phase ordering so “before/after” semantics are tested in the same process context.
  - Splits transports (event bus vs rights bus) so SCM_RIGHTS FD passing cannot corrupt structured JSONL events.
  - Uses an ultra-early sentinel and actual socketpair FDs (no hardcoded fd numbers); protocol version/namespace/cap-id validation makes mismatches explicit (`child_protocol_violation`/`protocol_error`).
  - Records stop mechanics (start-suspended + stop markers) and callsite ids/backtraces to localize denies; a run with no child-emitted events is interpreted as early child failure, not a sandbox deny.
  - Frozen demonstration: `tests/fixtures/inherit_child/` (scrubbed fixtures compared by `tests/suites/smoke/inherit_child_fixtures.sh`).

## Inputs (plans + nodes)

### Plan (`experiments/plans/*.json`)

A plan is a list of probe rows. Minimal schema (matches `ProbePlan`/`ProbeRow` in `experiments/harness/main.swift`):

```json
{
  "plan_id": "tri-run-smoke",
  "probes": [
    {
      "row_id": "optional (defaults to probe_id)",
      "probe_id": "probe_catalog",
      "inputs": { "kind": "probe", "argv": [] },
      "expected_side_effects": ["none"],
      "capture_spec": { "capture_sandbox_log": false }
    }
  ]
}
```

`inputs.kind`:

- `probe` → runs `witness-substrate probe <probe-id> ...` for baseline/policy and `policy-witness xpc run ...` for entitlement
- `quarantine-lab` → runs `witness-substrate quarantine-lab ...` for baseline/policy and `policy-witness quarantine-lab ...` for entitlement

`row_id`:

- Drives artifact directory naming.
- If omitted, defaults to `probe_id`.
- If you want multiple variants of the same `probe_id` (e.g. several `fs_op` arg sets), set distinct `row_id` values.

Ephemeral port substitution:

- If any `inputs.argv` contains `--port 0`, the harness starts a harness-owned localhost TCP server and substitutes the chosen port into all witnesses for that row.

Host-coordinated actions (optional):

- Probe rows may include `host_actions` to perform host-side file operations *during* a witness run (useful when the witness is sandboxed and cannot perform the action itself).
- The harness supports:
  - `kind=rename` with `{from,to,delay_ms}`.
- When `host_actions` are present, the harness allocates a per-run directory under `/tmp/policy-witness-harness/pw-harness/...` and provides one template variable:
  - `{{PW_HARNESS_RUN_DIR}}` (substituted into both `inputs.argv` and `host_actions` fields).
- Host action paths are refused unless they live under `/tmp/policy-witness-harness` (or `/private/tmp/policy-witness-harness`).
- The harness writes a best-effort transcript to `host-actions.txt` under each run directory; set `PW_HARNESS_KEEP_ACTION_ARTIFACTS=1` to keep the temporary harness directory after the run.

### Nodes / lattice (`experiments/nodes/*.json`)

Nodes define the “lattice” you run the plan across. Minimal schema (matches `EntitlementLattice`/`EntitlementNode` in `experiments/harness/main.swift`):

```json
{
  "nodes": [
    {
      "node_id": "E0_minimal",
      "policy_profile": "experiments/policy/P0_minimal.sb",
      "xpc_probe_service_bundle_id": "com.yourteam.policy-witness.ProbeService_minimal",
      "xpc_quarantine_service_bundle_id": "com.yourteam.policy-witness.QuarantineLab_default"
    }
  ]
}
```

Notes:

- `policy_profile` is copied into the output bundle under `nodes/<node_id>/policy-profile.sb` so an atlas is self-contained.
- `xpc_quarantine_service_bundle_id` is optional. If a plan row is `kind=quarantine-lab` and a node omits the quarantine service id, the harness writes a synthetic “service missing” result for that witness (rows are not dropped).
- Bundle ids may target either base or injectable variants. Injectable twins use the `.injectable` bundle id suffix (for example `com.yourteam.policy-witness.ProbeService_minimal.injectable`) and are generated automatically during the app build.

### Policy profiles (`experiments/policy/*.sb`)

These are intentionally small, teaching-grade SBPL profiles (“attempted equivalents”), not a claim of equivalence to App Sandbox entitlements.

Profiles typically use a `HOME` parameter and a helper like:

```lisp
(subpath (string-append (param "HOME") "/Downloads"))
```

The harness passes that parameter automatically.

## Outputs (atlas + artifacts)

### Directory layout

Default output directory:

- `experiments/out/<plan-id>-<timestamp>/`

Key contents:

- `atlas.json` — the mismatch atlas (JSON, sorted keys; compact)
- `nodes/<node_id>/policy-profile.sb` — the materialized SBPL profile used for that node
- `<row_id>/baseline/stdout.txt` and `stderr.txt`
- `<row_id>/<node_id>/policy/stdout.txt` and `stderr.txt`
- `<row_id>/<node_id>/entitlement/stdout.txt` and `stderr.txt`
- Optional sandbox log excerpts under each run directory:
  - `sandbox-log.txt`
  - `sandbox-log-retry.txt` (only for entitlement permission-shaped errors with no deny observed on first attempt)

### Atlas schema (contract)

The harness emits an `Atlas`:

```json
{
  "plan_id": "tri-run-smoke",
  "created_at_iso8601": "2025-12-24T07:18:06Z",
  "nodes": [/* copies of node objects */],
  "rows": [/* TriRunRow */]
}
```

Each `TriRunRow` contains:

- the original inputs (`probe_id`, `row_id`, `inputs`, `expected_side_effects`, `capture_spec`)
- the selected node (`node_id`, `policy_profile_ref`, `entitlement_service_bundle_id`)
- the three normalized witness results (`baseline`, `policy`, `entitlement`)
- the exact argv used for each witness (`*_cmd_argv`)
- a computed `parity` classification

Normalized witness results (`ProbeResult`) look like:

```json
{
  "rc": 0,
  "normalized_outcome": "ok",
  "errno_or_error": { "errno": null, "error": null },
  "stdout_ref": "relative/path/to/stdout.txt",
  "stderr_ref": "relative/path/to/stderr.txt",
  "layer_attribution": {
    "seatbelt_deny_op": null,
    "service_refusal": null,
    "quarantine_delta": null,
    "world_shape_change": null
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
        "deny_op": "file-read-data",
        "observation": "deny_observed",
        "excerpt_ref": "relative/path/to/sandbox-log.txt"
      }
    ]
  },
  "path_evidence": {
    "effective_path_class": "host_path|container_path|synthesized_temp_path|other_path|null",
    "paths": {
      "target_path": {
        "raw": "/path",
        "realpath": "/private/path",
        "path_class": "string",
        "realpath_class": "string|null"
      }
    }
  }
}
```

Hard rule: “couldn’t run” is never collapsed into “denied”. `seatbelt_deny_op` is only set when a deny line is actually observed in captured logs; otherwise it remains `null` and the capture attempts record what was searched and what was (not) observed.

### Parity classification

The harness computes a `parity.parity_class` for each row/node comparing **policy vs entitlement**:

- `match` — outcomes and relevant attribution fields line up
- `mismatch_seatbelt` — `seatbelt_deny_op` differs (deny observed in one witness but not the other)
- `mismatch_quarantine` — `quarantine_delta` differs (expected for user-selected / quarantine experiments)
- `mismatch_world_shape` — container/world-shape differs (e.g. containerized home)
- `mismatch_service_mediated` — service-mediated mismatch without a path-class confound (e.g. `normalized_outcome` differs)
- `path_class_confound` — mismatch, but the effective path class differs (host vs container vs tmp), making it confounded
- `incomparable` — witness failed or output was unparseable

## Extending the harness (common edits)

### Add a new probe to the experiment plan

1. Implement the probe in `xpc/InProcessProbeCore.swift` (so XPC services and the substrate share it).
2. Add a row to a plan under `experiments/plans/`.
3. If it’s a “permission-shaped” probe, consider setting `capture_spec.capture_sandbox_log=true`.

### Add a new entitlement node

1. Add a new node to one of the lattices under `experiments/nodes/`.
2. Ensure the corresponding XPC service exists under `xpc/services/` and is embedded/signed into `PolicyWitness.app`.
   - See [xpc/README.md](../xpc/README.md) and [CONTRIBUTING.md](../CONTRIBUTING.md#toy-example-adding-a-new-xpc-service).
3. Rebuild the app (`make build`) so the service exists and Evidence is regenerated.

### Add or modify a policy profile

1. Add/edit an SBPL profile under `experiments/policy/`.
2. Reference it from your node (`policy_profile`).
3. Keep profiles small and explicit: the policy witness is a hypothesis knob, not “the sandbox”.
