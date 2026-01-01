# inherit_child dynamic_extension crash postmortem (and why signposts mattered)

This is a hermetic, narrative account of diagnosing and fixing a crash in the `inherit_child` probe’s `dynamic_extension` scenario while adding **optional, off-by-default** Unified Logging signposts (`--signposts`, `--capture-signposts`).

It is written to be understandable **without** repo access. Where repo context helps, I refer to **repo-relative paths** (e.g. `xpc/InProcessProbeCore.swift`). Any absolute user paths are either omitted or rewritten to `/Users/username/...`.

## Executive summary

- **Symptom:** `inherit_child --scenario dynamic_extension` intermittently failed as an `xpc_error` with the XPC connection being interrupted/invalidated (e.g. `NSCocoaErrorDomain Code=4097`), and the smoke suite sometimes ended with `make: *** [test] Error 1` despite mostly “pass” looking output.
- **Immediate cause:** the XPC service process (`ProbeService_temporary_exception`) was **crashing** (SIGBUS / stack guard), which manifests on the host as “connection interrupted.”
- **Root cause:** `probeInheritChild` (for `dynamic_extension`) called the large `probeSandboxExtension` implementation **nested** inside the XPC service worker thread, pushing that thread over its (small) stack limit; the crash triggered during path/name validation in `resolveFsTarget(...)` while already stack-constrained.
- **Fix:** remove the nested `probeSandboxExtension` call from `probeInheritChild`; inline the minimum required “issue token” and “consume token” calls (`sandbox_extension_issue_file`, `sandbox_extension_consume`) in `xpc/InProcessProbeCore.swift`.
- **Outcome:** `bash tests/suites/smoke/inherit_child_fixtures.sh` passes, and `./tests/run.sh --all` passes (when run unsandboxed so XPC can launch).

## Glossary (minimal)

- **XPC client**: Swift executable under `PolicyWitness.app/Contents/MacOS/` that speaks `NSXPCConnection` to a service.
- **XPC service**: the `.xpc` bundle under `PolicyWitness.app/Contents/XPCServices/` hosting probe execution.
- **`inherit_child`**: a two-process probe that coordinates a parent (in service) and a spawned child helper; uses an event bus (JSONL) + rights bus (`SCM_RIGHTS`).
- **`dynamic_extension`**: `inherit_child` scenario that issues/consumes sandbox extension tokens (requires temporary exception entitlements).
- **Signpost**: Unified Logging `os_signpost` interval events used for latency/lifecycle tracing.

## System + harness context (“thread context”)

### Repo architecture slice relevant to this bug

- The CLI is Rust (`runner/`) and shells out to embedded Swift clients under `PolicyWitness.app/Contents/MacOS/` for XPC operations.
- Probes run inside XPC services (`PolicyWitness.app/Contents/XPCServices/*.xpc`), and the Swift service executes probe logic from `xpc/InProcessProbeCore.swift`.
- `inherit_child` is a **frozen substrate**: protocol framing and witness semantics are contracts. Fixes should avoid changing the wire format.

### Execution constraints that materially affected debugging

- Running under a sandboxed harness can block:
  - **Keychain access** (codesigning identity lookup) and
  - **XPC service lookup/launch** (leading to `lookup error 159 - Sandbox restriction`).
- This created two failure modes:
  1) **Sandboxed run:** host gets `NSCocoaErrorDomain Code=4099 ... failed at lookup with error 159 - Sandbox restriction`.
  2) **Unsandboxed run:** XPC launches, but the service **crashes**, yielding `NSCocoaErrorDomain Code=4097 ... connection interrupted`.

The fix work required running builds/tests **unsandboxed** (so the XPC service could launch and crash reports could be produced consistently).

### Harness settings observed during debugging

These are not app-level properties; they were properties of the interactive environment used while iterating:

- Filesystem sandbox: “workspace-write”
- Network: restricted
- Command approval: “on-request”

Practical effect: some commands required being run “unsandboxed” (e.g., keychain identity lookup, running the XPC-based smoke tests).

## Repro recipes (pre-fix and post-fix)

All commands assume working directory is `<REPO_ROOT>`.

### Targeted failing repro (pre-fix)

This is the essence of what the smoke fixture runs (with arguments matching `tests/suites/smoke/inherit_child_fixtures.sh`):

```bash
PolicyWitness.app/Contents/MacOS/policy-witness \
  xpc run --profile temporary_exception \
  inherit_child \
  --scenario dynamic_extension \
  --path-class tmp \
  --target specimen_file \
  --name pw_fixture_dynamic.txt \
  --create
```

Observed host-side error shape (pre-fix, unsandboxed):

- `normalized_outcome='xpc_error'`
- error mentions `NSCocoaErrorDomain Code=4097 "connection to service ... interrupted"`

Observed host-side error shape (pre-fix, sandboxed environment):

- `normalized_outcome='xpc_error'`
- error mentions `NSCocoaErrorDomain Code=4099` and `failed at lookup with error 159 - Sandbox restriction`

### “Looks like it passed but make failed” repro (pre-fix)

Running the full suite could end with `make: *** [test] Error 1` even when most steps printed `pass`. The underlying cause was a smoke script failing without writing a `report.json`, so `tests/out/run.json` could appear green while the suite still returned non-zero.

### Post-fix verification

```bash
# Build (requires signing identity)
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' ./build.sh

# Targeted fixture
bash tests/suites/smoke/inherit_child_fixtures.sh

# Full suite
./tests/run.sh --all
```

## Timeline narrative (what happened, in order)

### 0) Initial confusing failure report (“everything printed pass”)

The observable surface was:

- `./tests/run.sh --all` printed a full suite run with many `pass` messages.
- The overall command still returned non-zero (`make test` ended as `Error 1`).

This was later explained by “a smoke script failed but didn’t write `tests/out/.../report.json`,” so:
- the suite runner correctly returned failure, but
- `tests/out/run.json` could still show `ok: true` because it only counts tests that produced a `report.json`.

### 1) Feature work: add optional signposts to understand lifecycle + delays

Goal: a **new, additive, off-by-default** way for users to observe lifecycle timing and delays across:
- Rust CLI orchestration
- Swift XPC client
- Swift XPC service
- `inherit_child` parent/child choreography

Implementation highlights:
- Introduced a Swift helper `xpc/Signposts.swift`:
  - `PWSignposts` gating: enabled only if `PW_ENABLE_SIGNPOSTS=1` (or per-thread override).
  - `PWTraceContext` (threadDictionary): correlation id and related context.
  - `PWSignpostSpan`: `os_signpost(.begin/.end)` wrapper emitting messages like `pw_corr=<id> label=<label>`.
- Added `--signposts` and `--capture-signposts` to the CLI (Rust) so users can opt in:
  - `--capture-signposts` implies `--signposts`.
  - When capturing, the host runs an embedded observer to pull signposts out of Unified Logging after the probe finishes and injects them into the JSON under `data.host_signpost_capture`.
- Added `runner/src/bin/signpost-log-observer.rs` and embedded it at `PolicyWitness.app/Contents/MacOS/signpost-log-observer`.

One concrete gotcha found and fixed during this work:

- `/usr/bin/log show --style json` outputs a **single JSON array** (not JSONL).
- The observer was updated to accept either JSON arrays or JSONL, and a unit test was added to lock in the behavior (`parses_json_array_output`).

### 2) First break: Swift compile errors for new signpost types

The experiments smoke suite builds “witness substrate” using a Swift compile line that explicitly listed sources. Once `xpc/InProcessProbeCore.swift` referenced `PWTraceContext` / `PWSignpostSpan`, the witness substrate build failed with errors like:

- `error: cannot find 'PWTraceContext' in scope`
- `error: cannot find 'PWSignpostSpan' in scope`

Fix:
- Add `xpc/Signposts.swift` to the witness substrate build inputs in `experiments/build-experiments.sh`.
- Document the new dependency in `experiments/README.md`.

### 3) Confusing test failure: suite non-zero without a clear failing report

Running `./tests/run.sh --all` could end non-zero with limited visibility into which smoke test actually failed.

Root cause:
- `tests/run.sh` builds `tests/out/run.json` by scanning for `tests/out/suites/*/*/report.json`.
- The failing smoke script (`tests/suites/smoke/inherit_child_fixtures.sh`) previously exited early (due to `set -e`) without writing its `report.json`, so the run summary could look “ok” even while the suite returned `1`.

Fix:
- Update `tests/suites/smoke/inherit_child_fixtures.sh` to:
  - trap `ERR`,
  - always route failure through `test_fail`,
  - include a compact JSON summary of the probe output when it fails.

This made the failure **obvious and attributable**.

### 4) Two distinct failure modes: sandboxed lookup vs real crash

After improving reporting, the failing case surfaced clearly as:

- `normalized_outcome='xpc_error'`

But the *error message differed* depending on execution context:

1) **Sandboxed harness (not the app sandbox; the test runner environment):**
   - `Code=4099 ... invalidated: failed at lookup with error 159 - Sandbox restriction`
   - This is “XPC cannot launch at all in this environment.”

2) **Unsandboxed (normal local execution):**
   - `Code=4097 ... connection ... interrupted`
   - This strongly suggested “service launched, then died.”

From here on, debugging focused on the unsandboxed crash path.

### 4.1) Concrete failure output after improving reporting

After the smoke fixture was updated to always report failures, the two modes looked like:

Sandboxed environment (cannot launch XPC service):

```text
FAIL: [smoke/inherit_child.fixtures] ... normalized_outcome='xpc_error' error='... Code=4099 ... failed at lookup with error 159 - Sandbox restriction ...'
```

Unsandboxed environment (service launches, then dies):

```text
FAIL: [smoke/inherit_child.fixtures] ... normalized_outcome='xpc_error' error='... Code=4097 "connection to service with pid <n> named ... interrupted" ...'
```

The key pivot was recognizing that **the Code=4099 path is environmental**, but **the Code=4097 path indicates a real crash to investigate**.

### 5) Establish ground truth: collect crash reports

Crash reports were generated under:

```text
~/Library/Logs/DiagnosticReports/
  ProbeService_temporary_exception-*.ips
```

Key fact: `.ips` files are **JSON** (two JSON objects: the first line is a small header object, and the rest is a full JSON object).

We used a small Python snippet to parse and extract frames (conceptually):

```python
first_line, rest = open(path).read().split("\n", 1)
meta = json.loads(first_line)
main = json.loads(rest)
frames = main["threads"][main["faultingThread"]]["frames"]
```

Representative crash metadata (from one of the reports):
- OS: `macOS 14.4.1 (23E224)`
- CPU: `ARM-64`
- Exception: `EXC_BAD_ACCESS (SIGBUS)` with `KERN_PROTECTION_FAILURE` (stack guard style fault)

How crash reports were located (example command):

```bash
ls -t ~/Library/Logs/DiagnosticReports | head
```

Example filenames seen during debugging:

```text
ProbeService_temporary_exception-2026-01-01-091247.ips
ProbeService_temporary_exception-2026-01-01-091312.ips
ProbeService_temporary_exception-2026-01-01-094500.ips
```

### 6) What the crash reports showed (the “aha”)

Multiple crash reports (`ProbeService_temporary_exception-2026-01-01-091247.ips`, `...-091312.ips`, `...-094500.ips`) consistently implicated a nested call chain:

```
InProcessProbeCore.probeInheritChild
  └─ issueToken(...)           (a helper local to inherit_child)
      └─ InProcessProbeCore.probeSandboxExtension
          └─ InProcessProbeCore.resolveFsTarget
              └─ (string/path validation)
```

Example top frames (abridged) from `ProbeService_temporary_exception-2026-01-01-091247.ips`:

```
00 _GraphemeBreakingState.shouldBreak(between:and:)
01 _StringGuts._opaqueCharacterStride(startingAt:)
...
06 static InProcessProbeCore.isSinglePathComponent(_:)
07 static InProcessProbeCore.resolveFsTarget(directPath:pathClass:target:requestedName:)
08 static InProcessProbeCore.probeSandboxExtension(argv:)
09 issueToken #1 (issueArgs:) in static InProcessProbeCore.probeInheritChild(argv:eventSink:)
10 static InProcessProbeCore.probeInheritChild(argv:eventSink:)
...
31 _dispatch_workloop_worker_thread
32 _pthread_wqthread
33 start_wqthread
```

The signature (`SIGBUS` + protection failure at an address near stack guard) and the fact that this happens on a dispatch workloop worker thread strongly suggested **stack exhaustion** rather than a semantic sandbox denial.

### 7) Why this happened (RCA)

The `dynamic_extension` scenario requires issuing and consuming a sandbox extension token.

Originally, `probeInheritChild` implemented this by calling a nested helper (`issueToken`) that internally invoked the full `probeSandboxExtension` probe implementation (which is large and has many code paths, local variables, and Foundation usage).

That meant, within the XPC service worker thread:

- `probeInheritChild` (already a large function)
  - called into `probeSandboxExtension` (also large)
    - which called into `resolveFsTarget` (string/path logic)

On macOS, XPC service workloop threads commonly have **smaller stacks** than main threads. A nested call from one large “probe” implementation into another large “probe” implementation is a recipe for stack guard faults, even if the crash point appears inside “innocent” string/path code.

In short: **this wasn’t a sandbox denial**; it was a *resource exhaustion crash* caused by architectural “probe calls probe” nesting on a constrained stack.

### 8) Fix strategy: avoid nesting the big probe

Principle: keep `inherit_child` as a stable substrate and avoid broad refactors; apply a surgical change that reduces stack pressure.

Fix in `xpc/InProcessProbeCore.swift`:

- Remove the nested `issueToken(...) -> probeSandboxExtension(...)` path.
- Inline the minimum token issuance logic in `probeInheritChild`:
  - resolve the target path (same semantics as before),
  - optionally create the specimen file,
  - call `sandbox_extension_issue_file` via `dlsym` and `unsafeBitCast`,
  - free the token with `sandbox_extension_free` when available,
  - record the same parent-side events/witness fields.
- Replace the prior “consume” operation that called back into `probeSandboxExtension` with a direct `sandbox_extension_consume` call (the handle-returning variant that worked on this system).

This preserved behavior while dramatically reducing call depth and stack usage.

Pseudocode sketch of the key change (not literal code):

```text
// Before:
inherit_child.dynamic_extension:
  token = probeSandboxExtension("--op issue_file ...")
  ...
  probeSandboxExtension("--op consume --token token")

// After:
inherit_child.dynamic_extension:
  token = dlsym("sandbox_extension_issue_file")(class, path)
  ...
  handle = dlsym("sandbox_extension_consume")(token)
```

### 9) Validation

After rebuilding a signed app bundle (`./build.sh`) and running tests unsandboxed:

- `bash tests/suites/smoke/inherit_child_fixtures.sh` passed.
- `./tests/run.sh --all` passed.

## How signposts were used (and what “capture” means)

Signposts were added to illuminate:
- XPC client “run probe” lifetime
- XPC service “run probe” lifetime
- key `inherit_child` parent phases (spawn, wait points, token issue/consume)
- long waits or suspicious delays (e.g., semaphores, polling loops)

### Enabling (off-by-default)

Users enable signposts explicitly:
- `--signposts` (emit signposts during execution)
- `--capture-signposts` (also harvest them after the fact and attach to JSON)

Internally:
- Rust sets `PW_ENABLE_SIGNPOSTS=1` in the environment when requested.
- Swift checks `PW_ENABLE_SIGNPOSTS` via `PWSignposts.isEnabled()`.
- Correlation context flows via `correlation_id` fields and (for child helpers) via `PW_CORRELATION_ID`.

### Capturing

`--capture-signposts` runs `PolicyWitness.app/Contents/MacOS/signpost-log-observer`, which queries Unified Logging with a predicate matching `subsystem == "com.yourteam.policy-witness"` and `eventMessage CONTAINS "pw_corr=<id>"`.

Notable gotcha that was fixed:
- `/usr/bin/log show --style json` returns a **JSON array**, not JSONL; the observer now handles both.

## Appendix A: Example failing fixture report snippet (sanitized)

This is representative of the `report.json` content after improving `tests/suites/smoke/inherit_child_fixtures.sh` failure reporting (formatted and sanitized; paths rewritten):

```json
{
  "suite": "smoke",
  "test_id": "inherit_child.fixtures",
  "status": "fail",
  "message": "inherit_child fixture scenario=dynamic_extension profile=temporary_exception failed (exit_code=1): kind='probe_response' normalized_outcome='xpc_error' error='xpc error: Error Domain=NSCocoaErrorDomain Code=4097 ... connection ... interrupted ...'",
  "artifacts_dir": "tests/out/suites/smoke/inherit_child.fixtures/artifacts"
}
```

## Appendix B: Crash report frame excerpts (sanitized)

From `ProbeService_temporary_exception-2026-01-01-091247.ips` (abridged):

```text
06 static InProcessProbeCore.isSinglePathComponent(_:)
07 static InProcessProbeCore.resolveFsTarget(directPath:pathClass:target:requestedName:)
08 static InProcessProbeCore.probeSandboxExtension(argv:)
09 issueToken #1 (issueArgs:) in static InProcessProbeCore.probeInheritChild(argv:eventSink:)
10 static InProcessProbeCore.probeInheritChild(argv:eventSink:)
...
31 _dispatch_workloop_worker_thread
```

From `ProbeService_temporary_exception-2026-01-01-091312.ips` (abridged):

```text
00 swift_getAssociatedTypeWitness
01 == infix<A>(_:_:)
02 static InProcessProbeCore.resolveFsTarget(directPath:pathClass:target:requestedName:)
03 static InProcessProbeCore.probeSandboxExtension(argv:)
04 issueToken #1 (issueArgs:) in static InProcessProbeCore.probeInheritChild(argv:eventSink:)
05 static InProcessProbeCore.probeInheritChild(argv:eventSink:)
...
29 _dispatch_workloop_worker_thread
```

## Appendix C: Signpost capture example (user-facing)

Generate a correlation id and run a probe with signposts enabled:

```bash
corr="$(uuidgen)"
PolicyWitness.app/Contents/MacOS/policy-witness \
  xpc run --profile temporary_exception \
  --correlation-id "${corr}" \
  --capture-signposts \
  inherit_child --scenario dynamic_extension --path-class tmp --target specimen_file --name pw_fixture_dynamic.txt --create
```

The JSON response (only when `--capture-signposts` is used) includes an additive field:

```text
data.host_signpost_capture = {
  "capture_status": "captured" | "requested_unavailable",
  "observer_path": ".../PolicyWitness.app/Contents/MacOS/signpost-log-observer",
  "observer_args": [...],
  "observer_report": { "kind": "signpost_log_observer_report", ... }   // when captured
}
```

## Why this was hard (best effort)

1) **The failure signal lied by omission.** On the host side, “connection interrupted” is indistinguishable from many causes: crash, hang, jetsam, entitlement mismatch, sandbox kill, launchd refusal, etc.
2) **The sandboxed harness introduced a different error.** `4099 lookup error 159` is not the same bug as the `4097` crash path, but it initially masked the real issue.
3) **The test runner didn’t always record the failure.** Without a `report.json`, the run summary could look “green” even when the suite returned `1`.
4) **Multi-process, multi-language stack.** Rust CLI → Swift client → Swift XPC service → child helper, with different logging surfaces and different failure semantics.
5) **Stack overflows in Swift don’t look like recursion.** The backtrace shows string operations, but the underlying trigger is “stack already exhausted by large frames and nested calls,” which is unintuitive until you see the stack guard style SIGBUS pattern.

## Messy notes / memory / low-confidence hypotheses (explicitly quarantined)

Everything in this section is **LOW CONFIDENCE** unless otherwise stated.

- I suspected that `--path-class tmp` path resolution (Foundation URL/standard directory resolution) might be “stacky” enough to trigger the guard when nested under another large probe; I tried special-casing `tmp`/`home` to use `TMPDIR`/`HOME` env variables. It helped localize but did not fully resolve until nesting was removed.
- I briefly suspected a `sandbox_extension_*` API calling convention mismatch across OS versions (some variants return `Int32`, others return “handle-like” values); in the end, the observed crash signature was clearly stack-related, not a bad symbol call.
- I temporarily replaced one computed list (`SandboxExtensionOp.allCases`-style) with a constant string to avoid an early crash seen during instrumentation. This may have been correlation noise rather than causality.
- It’s possible some of the “hardness” was amplified by signpost instrumentation changing timing/stack layout slightly; however, crash reports without signposts also showed the same chain.

## Appendix D: File/change index (high level)

Signposts feature (additive, off-by-default):
- `xpc/Signposts.swift`: gating + correlation context + signpost span wrapper.
- `xpc/ProbeAPI.swift`: plumb `enable_signposts` fields through JSON request types.
- `xpc/client/main.swift`, `xpc/quarantine-client/main.swift`: enable/propagate signposts and correlation.
- `xpc/ProbeServiceSessionHost.swift`, `xpc/QuarantineLabServiceHost.swift`: set trace context + wrap probe/session operations with spans.
- `runner/src/main.rs`: add `--signposts`, `--capture-signposts`, and inject `data.host_signpost_capture` when requested.
- `runner/src/bin/signpost-log-observer.rs`: observer tool (and JSON array parsing fix).
- `build.sh`, `runner/Cargo.toml`, `tests/build-evidence.py`: build/embed/evidence updates for new binary.
- `experiments/build-experiments.sh`, `experiments/README.md`: include `xpc/Signposts.swift` in witness substrate build.

Crash fix (dynamic_extension):
- `xpc/InProcessProbeCore.swift`: remove nested `probeSandboxExtension` usage from `inherit_child` and inline token issue/consume logic.

Test reporting:
- `tests/suites/smoke/inherit_child_fixtures.sh`: trap and produce an actionable failing `report.json` with probe summary.
