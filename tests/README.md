# `tests/` (test runner + suites)

This is developer documentation for the test harness under `tests/`. These tests exist to answer two questions:

1. **Does the bundle basically work?** (end-to-end smoke)
2. **Did we break a contract?** (CLI integration + pure unit tests)

The test harness is intentionally **machine-readable**: every test emits structured JSONL events (suite/test/step) and a per-run summary.

Related docs:

- User guide / workflows: [PolicyWitness.md](../PolicyWitness.md)
- Contributing philosophy + build tour: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Signing/build procedure: [SIGNING.md](../SIGNING.md)
- CLI contract + integration tests: [runner/README.md](../runner/README.md)
- XPC services/probes/session design: [xpc/README.md](../xpc/README.md)
- Tri-run harness (baseline/policy/entitlement): [experiments/README.md](../experiments/README.md)

## How to run tests

Preferred entrypoint:

```sh
make test
```

Direct runner (useful for local iteration / agent loops):

```sh
./tests/run.sh --all
./tests/run.sh --suite preflight
./tests/run.sh --suite unit
./tests/run.sh --suite integration
./tests/run.sh --suite smoke
```

Notes:

- Preflight is inspection-only (codesign/entitlements); unit tests are pure logic; integration/smoke tests will execute the CLI and launch XPC services.
- Most integration/smoke tests assume a built `PolicyWitness.app` at the repo root. Build via the signed pipeline in [CONTRIBUTING.md](../CONTRIBUTING.md) / [SIGNING.md](../SIGNING.md).

## Suite layout

All suites live under `tests/suites/` and are run by suite runners:

- `tests/suites/preflight/run.sh`
  - Runs `tests/suites/preflight/preflight.sh`
  - Produces a preflight JSON report used to gate some integration checks.
- `tests/suites/unit/run.sh`
  - Runs Rust unit tests (`cargo test --bins`).
- `tests/suites/integration/run.sh`
  - Runs Rust integration tests (`cargo test --tests`), primarily `runner/tests/cli_integration.rs`.
- `tests/suites/smoke/run.sh`
  - Runs end-to-end smoke scripts under `tests/suites/smoke/*.sh` (XPC run, XPC session, quarantine lab, observer, experiments tri-run).

### Smoke: `inherit_child` is a contract surface (not a one-off)

The smoke suite treats `inherit_child` as an inspection substrate with frozen contracts:

- scenario routing (`--scenario <name>` is a catalog, not bespoke code paths),
- two transports (event bus vs rights bus),
- strict witness invariants (fields always present even on failures),
- self-diagnosing normalized outcomes (protocol violations vs sandbox denials vs expected abort canary),
- and host-side sandbox log capture integration (`--capture-sandbox-logs` attaches an excerpt to the same JSON artifact).

These expectations are asserted in `tests/suites/smoke/xpc_app_smoke.sh`.

### Smoke: `update_file_rename_delta` asserts meaning (not just shape)

`sandbox_extension --op update_file_rename_delta` is a semantics harness: tests assert that success is an **access delta observed**, not “`rc==0`”.

- The happy path transcript is defended (pre-consume deny → post-consume allow on the old path; inode-preserving rename does not transfer access to the new path; `update_file(new_path)` restores access).
- Candidate sweeps must include per-candidate post-call access checks and `*_changed_access` signals (avoid “errno hunting”).
- Premise failures stop early with distinct normalized outcomes before additional side effects (for example `dest_preexisted`, and rename premise failures like cross-device/inode-changed/timeout/ambiguous when exercised).

## Golden fixtures (`inherit_child`)

`inherit_child` witness outputs are protected by scrubbed golden fixtures so schema drift and “silent loss of debuggability” regressions are obvious.

- Fixtures live under `tests/fixtures/inherit_child/`.
- The smoke test `tests/suites/smoke/inherit_child_fixtures.sh` runs representative scenarios, scrubs volatile fields (PIDs, timestamps, run ids), and compares the result to the fixture JSON.
- Update fixtures by running the fixture test with `PW_UPDATE_FIXTURES=1` (only do this when you intend a schema/content change).

Example:

```sh
PW_UPDATE_FIXTURES=1 ./tests/suites/smoke/inherit_child_fixtures.sh
```

Tools:

- `tests/tools/scrub_inherit_child_witness.py` — produces stable scrub output and preserves contract-critical fields (protocol version/namespace, outcome_summary, capability_results shape, etc).
- `tests/tools/compare_json_fixture.py` — compares scrubbed output to a fixture with a readable diff.
- `tests/tools/validate_inherit_child_fixtures.py` — validates fixture schema/invariants; run from the unit suite.

## Golden fixtures (`update_file_rename_delta`)

`update_file_rename_delta` is also protected by scrubbed golden fixtures:

- Fixtures live under `tests/fixtures/update_file_rename_delta/` (do not add commentary inside the JSON).
- The smoke test `tests/suites/smoke/update_file_rename_delta_fixtures.sh` runs representative cases, scrubs volatile fields, and compares to fixtures.
- The fixtures intentionally encode “easy-to-misread” facts: rename can silently change meaning, and `update_file_by_fileid` may return `rc==0` with no access delta (rc is not evidence).

## Output contract (`tests/out/`)

Every invocation of `tests/run.sh` overwrites the prior run output so tooling can read stable paths:

```
tests/out/
  run.json
  events.jsonl
  suites/<suite>/<test_id>/
    report.json
    events.jsonl
    artifacts/...
```

Files:

- `run.json`: one summary object for the entire run (counts + list of per-test reports).
- `events.jsonl`: all structured test events across all suites/tests (one JSON object per line).
- `suites/<suite>/<test_id>/report.json`: test-level status (`pass`/`fail`/`skip`), duration, artifact dir.
- `suites/<suite>/<test_id>/events.jsonl`: test-local event stream.

If you want deterministic identifiers for tooling, set:

- `PW_TEST_RUN_ID=<string>` (embedded in JSON events + `run.json`)
- `PW_TEST_OUT_DIR=<path>` (must be within `tests/out/`; the runner wipes it at start)

## Event stream format (`events.jsonl`)

All scripts should emit events via `tests/lib/testlib.sh`.

Event schema:

- `schema_version: 1`
- `kind: "test_event"`
- required grouping fields: `run_id`, `suite`, `test_id`, `step`, `status`

Example event line:

```json
{
  "schema_version": 1,
  "kind": "test_event",
  "run_id": "20250105T120000Z_a1b2c3d4",
  "suite": "smoke",
  "test_id": "xpc.session_smoke",
  "step": "trigger_wait_fifo",
  "status": "info",
  "ts_unix_ms": 1700000000000,
  "duration_ms": null,
  "message": "trigger wait FIFO",
  "data": null
}
```

The intent is that a retrospective machine analysis can:

- group lines by `(run_id, suite, test_id)`,
- reconstruct step ordering via `ts_unix_ms` and `step`,
- and locate artifacts via `report.json` (or event `data` fields).

## Environment variables (common)

Harness output:

- `PW_TEST_RUN_ID`: override run id (default generated).
- `PW_TEST_OUT_DIR`: override output root (default `tests/out`; the runner overwrites it each run).

CLI location:

- `PW_BIN`: used by smoke scripts to locate the launcher (`PolicyWitness.app/Contents/MacOS/policy-witness` by default).
- `PW_BIN_PATH`: used by Rust integration tests (`runner/tests/cli_integration.rs`) to override the launcher path.

Optional integration toggles:

- `PW_DLOPEN_TESTS=1`: enable `dlopen_external` integration checks (requires signed test dylib fixture).

Build/probe helpers:

- `PW_INSPECTOR_BIN`: override the `pw-inspector` path used by preflight.

## Adding a new test

Pick the suite based on what the test touches:

- Pure parsing/formatting logic → Rust unit tests in `runner/src/*` (`#[test]`).
- CLI behavior contracts → Rust integration tests in `runner/tests/`.
- “Does the built `.app` basically work?” → add a new script in `tests/suites/smoke/`.

For new shell tests:

1. Source `tests/lib/testlib.sh`.
2. Call `test_begin "<suite>" "<stable.test_id>"`.
3. Use `test_step` for each major action and write artifacts under `$PW_TEST_ARTIFACTS`.
4. End with `test_pass` or `test_fail` (prefer `trap ... ERR` + `test_fail` for failures).

Keep test ids stable. Treat them like API identifiers for dashboards and long-term trend analysis.

## Build-time guardrails (signing/evidence)

The build generates Evidence by inspecting **signed** binaries. `tests/build-evidence.py` is both:

- the Evidence generator (`profiles.json`, `manifest.json`, `symbols.json`), and
- an invariant checker for “this bundle is a coherent specimen”.

Notable guardrail: the `inherit_child` helper entitlements are verified during the build (good helper must be “app-sandbox + inherit only”; the bad helper must carry the intended contaminating key). This makes signing/twinning regressions fail early, before runtime smoke tests.
