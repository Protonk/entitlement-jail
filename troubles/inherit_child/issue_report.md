## 1. Executive summary

While adding optional Unified Logging signposts and running the smoke suite, the `inherit_child --scenario dynamic_extension` fixture began failing intermittently. The only visible symptom at first was a host-side `xpc_error` (“connection interrupted/invalidated”), and the full test run could end non‑zero even when most output looked like a clean pass.

The investigation focused on making the failure attributable and then separating environmental failures from real defects. The smoke fixture was hardened to always surface a compact JSON summary on failure, which exposed two distinct error shapes depending on execution context (XPC lookup blocked vs. XPC connection interrupted). Running in an unsandboxed context allowed the XPC service to launch reliably and produce crash reports, and those reports consistently implicated a deep, nested call chain inside the service leading to a stack-guard fault.

The issue was resolved by eliminating the “probe calls probe” nesting in the `inherit_child` implementation for the `dynamic_extension` scenario: instead of invoking the full `sandbox_extension` probe from inside `inherit_child`, the minimum token issue/consume operations were inlined directly in the `inherit_child` code path. In parallel, signpost capture tooling was made robust to `/usr/bin/log show --style json` output shape, and the smoke fixture reporting changes ensured any recurrence would be immediately diagnosable rather than presenting as a generic XPC interruption.

## 2. Location

PolicyWitness is a macOS research/teaching tool that keeps its control plane outside the sandbox (a host-side CLI) while executing probes inside separately signed, sandboxed XPC services. This issue sits on the critical path where the smoke suite drives `policy-witness xpc run … inherit_child --scenario dynamic_extension`, the CLI optionally enables and captures signposts, and a dedicated observer parses Unified Logging output for attachment to the probe JSON.

* [inherit_child_fixtures.sh](sandbox:/mnt/data/inherit_child_fixtures.sh)  — Smoke fixture runner that executes each `inherit_child` scenario (including `dynamic_extension`), scrubs output deterministically, and fails with an extracted, high-signal JSON summary when the probe exits non‑zero.
* [signpost-log-observer.rs](sandbox:/mnt/data/signpost-log-observer.rs) — Rust helper tool invoked for `--capture-signposts` that shells out to `/usr/bin/log show --signpost --style json`, then parses begin/end signpost events into span records keyed by correlation id.
* [main.rs](sandbox:/mnt/data/main.rs) — Rust entry point for the `policy-witness` CLI that parses `--signposts`/`--capture-signposts`, propagates signpost enablement via `PW_ENABLE_SIGNPOSTS`, and injects host-side capture artifacts back into the JSON envelope.

## 3. Impetus

The problem surfaced during routine validation: running the smoke fixtures after signpost-related changes caused the `dynamic_extension` scenario to fail intermittently, with the CLI reporting an XPC-layer error rather than a structured `inherit_child` witness outcome. At the time of discovery, the only stable fact was that a command that “should” return a JSON `probe_response` with `rc==0` sometimes returned a non‑zero exit and an XPC interruption message.

```bash
# tests/suites/smoke/inherit_child_fixtures.sh (excerpt)

"${PW}" xpc run --profile "${profile}" inherit_child --scenario "${scenario}" "$@" >"${out_json}"

test_step "inherit_child_dynamic_extension" "inherit_child fixture: dynamic_extension"
CURRENT_STEP="inherit_child_dynamic_extension"
run_fixture "dynamic_extension" "temporary_exception" --path-class tmp --target specimen_file --name pw_fixture_dynamic.txt --create
```

The immediate failure signature at discovery time did not distinguish “sandbox denial,” “protocol/harness failure,” “service refused to launch,” or “service crashed mid‑probe.” The only clues were host-side Cocoa/XPC error codes (e.g., “connection interrupted” vs. “failed at lookup”), which required deliberate triage before any root-cause work could begin.

## 4. Root cause analysis

The `dynamic_extension` scenario exists specifically to exercise a parent/child capability ferry where the parent acquires access via a sandbox extension token and then demonstrates the child’s “acquire vs. use” behavior. Pre-fix behavior implemented this by calling a large, general-purpose sandbox-extension probe (`probeSandboxExtension`) from within the already-large `inherit_child` probe implementation—i.e., a “probe calls probe” nesting inside the XPC service execution thread.

That nesting was the critical defect: the `inherit_child` probe path (parent orchestration + child spawn + witness bookkeeping) already consumes meaningful stack, and the `sandbox_extension` probe path adds additional stack pressure through argument parsing, path resolution/validation, and Foundation/String-heavy routines. On the XPC service’s dispatch worker thread (which is commonly stack-constrained compared to a process main thread), the combined stack usage crossed the guard threshold, producing a crash signature consistent with stack exhaustion (SIGBUS / protection failure at the stack guard).

Because the failure was an in-service crash rather than a handled error, the host could only observe an XPC connection interruption/invalidatation, which the CLI normalized as an `xpc_error`. The apparent “intermittency” was an artifact of stack-layout/timing sensitivity (and, in some runs, environmental restrictions that prevented service lookup entirely), not evidence of nondeterministic sandbox policy behavior.

## 5. Exploration

The first step in making progress was improving the fidelity of failure reporting in the smoke fixture itself. The fixture runner was updated to trap errors and, on non‑zero probe exit, parse the JSON artifact (when present) to extract a compact summary (`kind`, `normalized_outcome`, and a bounded `error` string) rather than letting the script abort with `set -e` and minimal context.

```bash
# tests/suites/smoke/inherit_child_fixtures.sh (excerpt)

trap fail ERR

"${PW}" xpc run --profile "${profile}" inherit_child --scenario "${scenario}" "$@" >"${out_json}"
pw_status=$?
if [[ ${pw_status} -ne 0 ]]; then
  summary="$(
    /usr/bin/python3 - "${out_json}" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
except Exception as e:
    print(f"invalid_json: {e}")
    raise SystemExit(0)
result = data.get("result") or {}
normalized = result.get("normalized_outcome")
err = result.get("error") or result.get("stderr") or ""
if isinstance(err, str):
    err = err.replace("\n", "\\n")
print(f"kind={data.get('kind')!r} normalized_outcome={normalized!r} error={err[:240]!r}")
PY
  )"
  test_fail "… failed (exit_code=${pw_status}): ${summary}"
fi
```

Once that was in place, the failure separated cleanly into two distinct modes that had previously been conflated: a “cannot even launch the service” mode and a “service launches then dies” mode. This distinction was critical, because only the latter corresponds to a real defect in the probe implementation.

```text
# Mode A: XPC lookup blocked by the surrounding execution environment
normalized_outcome='xpc_error'
error='… NSCocoaErrorDomain Code=4099 … failed at lookup with error 159 - Sandbox restriction …'

# Mode B: XPC service launches, then connection is interrupted (service crash)
normalized_outcome='xpc_error'
error='… NSCocoaErrorDomain Code=4097 … connection to service with pid <n> … interrupted …'
```

In parallel, signposts were being added as an opt-in observability layer spanning CLI orchestration, XPC client/service boundaries, and probe phases. On the CLI side, signposts are enabled by setting `PW_ENABLE_SIGNPOSTS=1` for the embedded Swift XPC client, and `--capture-signposts` triggers a post-run harvest step that invokes the embedded observer and injects its report under `data.host_signpost_capture`.

```rust
// main.rs (excerpt): enable signposts for the XPC probe client + harvest them after the run.

fn run_xpc_probe(..., enable_signposts: bool) -> Result<(String, i32, String), String> {
    let cmd_path = resolve_contents_macos_tool("xpc-probe-client")?;
    let mut cmd = Command::new(&cmd_path);
    cmd.arg("run").arg(service_id).arg(probe_id).args(probe_args);
    if enable_signposts {
        cmd.env("PW_ENABLE_SIGNPOSTS", "1");
    }
    ...
}

fn capture_signposts(correlation_id: &str, plan_id: Option<&str>, row_id: Option<&str>)
  -> Result<serde_json::Value, String> {
    let observer = resolve_contents_macos_tool("signpost-log-observer")?;
    let mut args = vec![
        "--correlation-id".to_string(), correlation_id.to_string(),
        "--last".to_string(), "2m".to_string(),
        "--format".to_string(), "jsonl".to_string(),
    ];
    ...
}
```

That post-run harvesting step depended on a new observer binary that wraps `/usr/bin/log show --signpost --style json`. Early validation uncovered that `log show --style json` emits a single JSON array (not JSONL), so the observer had to accept both shapes. The observer now checks whether stdout begins with `'['` and parses as an array when present, and it has a unit test locking that behavior in.

```rust
// signpost-log-observer.rs (excerpt): accept either JSON array or JSONL.

fn parse_spans(stdout: &str) -> (...) {
    ...
    let trimmed_all = stdout.trim();
    if trimmed_all.starts_with('[') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed_all) {
            if let Some(items) = value.as_array() {
                for item in items { process_record(item, ...); }
            }
        }
    } else {
        for line in stdout.lines() { ... } // JSONL path
    }
    ...
}

#[test]
fn parses_json_array_output() {
    let stdout = r#"[{"process":"svc",...,"signpostType":"begin",...},{"process":"svc",...,"signpostType":"end",...}]"#;
    let (parsed_json_lines, _, spans, unmatched_begin, unmatched_end) = parse_spans(stdout);
    assert_eq!(parsed_json_lines, 2);
    assert_eq!(spans.len(), 1);
    ...
}
```

With environment-caused lookup failures excluded (by running unsandboxed), the focus shifted to the 4097 “connection interrupted” path. Crash reports were then collected for the relevant XPC service (`ProbeService_temporary_exception`), and those `.ips` reports (JSON) were parsed to extract faulting-thread frames. The workflow was explicitly “trust the crash report over the host symptom,” because NSXPCConnection interruption is a generic proxy for many causes.

```python
# inherit_child_crash.md (excerpt): parse .ips crash reports (JSON) and extract frames.

first_line, rest = open(path).read().split("\n", 1)
meta = json.loads(first_line)
main = json.loads(rest)
frames = main["threads"][main["faultingThread"]]["frames"]
```

The extracted frames were consistent across reports and implicated a nested call chain: `probeInheritChild` → a helper that issues a token → `probeSandboxExtension` → `resolveFsTarget` (string/path validation). Combined with the exception signature (SIGBUS / protection failure near the stack guard) and the fact that the fault occurred on a dispatch workloop worker thread, this pointed away from “sandbox denial semantics” and toward “stack exhaustion induced by nesting two large probe implementations.”

```text
# Crash frame excerpt (sanitized, representative)

06 static InProcessProbeCore.isSinglePathComponent(_:)
07 static InProcessProbeCore.resolveFsTarget(...)
08 static InProcessProbeCore.probeSandboxExtension(argv:)
09 issueToken #1 (...) in static InProcessProbeCore.probeInheritChild(...)
10 static InProcessProbeCore.probeInheritChild(...)
...
31 _dispatch_workloop_worker_thread
32 _pthread_wqthread
```

## 6. Fix

The fix was intentionally surgical: remove the nested `probeSandboxExtension` invocation from the `inherit_child` implementation for the `dynamic_extension` scenario, and inline only the minimum required sandbox extension SPI calls. Concretely, the `inherit_child` code path now issues the file extension token directly (via the relevant `sandbox_extension_issue_file` entry point), then consumes it directly (via `sandbox_extension_consume`), while preserving the existing witness/protocol contract and avoiding the extra stack depth and large local frames induced by routing through the full sandbox-extension probe machinery.

Supporting work tightened the overall diagnostic loop without changing user-visible defaults: signposts remain off-by-default and become active only when explicitly enabled; `--capture-signposts` harvests signposts into the probe JSON using the observer tool; and the smoke fixture now reliably emits actionable summaries on failure. Together, these changes convert a previously ambiguous “XPC interrupted” symptom into a reproducible, attributable defect class, and they prevent recurrence from being masked by early script exits or logging format mismatches.

## 7. Appendix

```bash
# inherit_child_fixtures.sh (excerpt): deterministic fixture mechanism (scrub + compare)

out_json="${OUT_DIR}/inherit-child-${scenario}.json"
scrubbed_json="${OUT_DIR}/inherit-child-${scenario}.scrub.json"
fixture_json="${FIXTURE_DIR}/${scenario}.json"

"${PW}" xpc run --profile "${profile}" inherit_child --scenario "${scenario}" "$@" >"${out_json}"
/usr/bin/python3 "${SCRUB_TOOL}" --in "${out_json}" --out "${scrubbed_json}"
/usr/bin/python3 "${COMPARE_TOOL}" "${scrubbed_json}" "${fixture_json}"
```

```rust
// signpost-log-observer.rs (excerpt): default predicate ties spans to a correlation id.

fn default_predicate(subsystem: &str, correlation_id: &str) -> String {
    let escaped_subsystem = subsystem.replace('"', "\\\"");
    let term = format!("pw_corr={correlation_id}");
    let escaped_term = term.replace('"', "\\\"");
    format!(
        r#"(subsystem == "{}") AND (eventMessage CONTAINS[c] "{}")"#,
        escaped_subsystem, escaped_term
    )
}
```

```rust
// main.rs (excerpt): --capture-signposts implies signposts, and capture status is explicit.

"--capture-signposts" => {
    capture_signposts_flag = true;
    signposts_flag = true;
    idx += 1;
}

let mut capture = serde_json::json!({
    "capture_status": if report_json.is_some() { "captured" } else { "requested_unavailable" },
    "observer_path": observer.display().to_string(),
    "observer_args": args,
    "observer_exit_code": exit_code,
});
```
