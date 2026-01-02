# PolicyWitness: Trust Boundaries, Evidence Chain, and Failure Taxonomy

*(Security / System Internals / Reverse Engineering Companion)*

## System model and trust boundaries

PolicyWitness is explicitly structured as a **control plane outside the sandbox** plus a **process zoo inside the sandbox**. The Rust launcher (`policy-witness`) orchestrates and packages results, but the sandbox boundary lives in separately signed XPC services whose entitlements are the variable under test. The result is a system where “what happened” is recorded as a structured witness, and “why it happened” is treated as an attribution problem that often requires external evidence (unified-log denies, crash reports, explicit lifecycle markers).

From a security/internals perspective, the key boundary clarifications are:

* **Host-side CLI is not the enforcement context.** It may report transport-layer symptoms (XPC lookup failures, interruptions) that are not policy outcomes. Treat host errors as “channel health” unless corroborated.
* **XPC services are the enforcement context.** This is where entitlement checks, App Sandbox enforcement, and the probe’s actual syscalls occur.
* **Child helpers (e.g., for `inherit_child`) are additional principals.** They can die early, have different entitlements, and can be used as canaries for inheritance contracts; “no child events” is a diagnostic signal, not a denial claim.
* **Observers are external evidence gatherers.** They run outside the sandbox boundary and are designed to attach evidence (deny lines, signpost timelines) to a probe’s JSON record without changing probe semantics. 

The practical upshot: **no single surface is authoritative**. Host JSON is authoritative for the experiment transcript and identity metadata; unified-log denies are authoritative for “Seatbelt/App Sandbox denied”; crash reports are authoritative for fast-death; and protocol/witness invariants are authoritative for distinguishing harness failures from policy outcomes.

## Identity, entitlement, and variant model

PolicyWitness’s “identity model” is not “one binary with flags.” It is **many separately signed service bundles**, each representing a stable entitlement profile, plus a build-generated twin variant for instrumentation. This has two consequences for security review and RE work:

1. **Entitlements are not inferred—they are part of the specimen.** Profiles map to XPC services with concrete entitlements. The right way to reason about behavior is “which signed principal executed the syscall,” not “which CLI argument I passed.”

2. **Variants create deliberate “high concern” surfaces.** Each base profile can have an `@injectable` twin with an instrumentation overlay (`get-task-allow`, `disable-library-validation`, `allow-dyld-environment-variables`, `allow-unsigned-executable-memory`). That changes both threat model and expected observability (e.g., enabling debugger attach or injection). Treat this as an explicit switch in risk posture.

Operationally, there are three useful identity checks a security engineer will want to perform early:

* **Verify evidence manifests and signing consistency** before treating results as meaningful (`verify-evidence`, `inspect-macho`, evidence bundle checks).
* **Confirm the intended service principal** (profile + variant) matches the one that actually ran (`show-profile`, `describe-service`, and probe responses that include service identity/PID).
* **Treat “temporary exception” profiles as a separate threat tier**, especially those enabling sandbox extension issuance (e.g., `temporary_exception` for `file-issue-extension`).

## Capability ferry model and protocol invariants

`inherit_child` is not just a probe; it is a **frozen inspection substrate** used to turn sandbox inheritance and capability transport into repeatable acquire/use experiments. It enforces a two-bus model:

* **Event bus:** child→parent JSONL `events[]` plus a sentinel; parent→child byte payloads (bookmark bytes).
* **Rights bus:** dedicated `SCM_RIGHTS` FD passing for file/dir/socket capabilities.
  **Hard invariant:** *never pass FDs over the event bus.*

For security and RE framing, the important points are:

* The protocol is explicitly designed to prevent **confusion bugs** from being misread as sandbox outcomes: versioning, cap-id validation, and protocol mismatch paths are normalized as protocol violations rather than silent misinterpretation.
* The substrate is built to make “early death” diagnosable: ultra-early sentinels and explicit lifecycle events mean the absence of child events is itself evidence of pre-event failure (crash/abort) rather than an implied denial.
* This substrate is also a reverse engineering affordance: it gives you stable points to hook (service lifecycle, child spawn markers, capability handoff boundaries) without needing to infer intent from syscall traces alone.

## Evidence chain and admissible claims

PolicyWitness’s most security-relevant design choice is that it distinguishes **witness** from **attribution**. The JSON record provides a reproducible transcript (rc/errno, resolved paths, per-phase outcomes), but certain claims are treated as *higher bar* because the OS often produces ambiguous in-band signals.

A useful “admissibility” mapping for investigations:

* **Claim: “Operation failed with EPERM/EACCES.”**
  Required: probe witness record (in-band).
  Not sufficient for: “sandbox denied.” 

* **Claim: “Seatbelt/App Sandbox denied this operation.”**
  Required: a matching unified-log deny line for the relevant PID/time window (out-of-band evidence), ideally attached via `--capture-sandbox-logs` or collected by `sandbox-log-observer`. 

* **Claim: “Service crashed (not denied).”**
  Required: crash report (`.ips`) for the service principal and a correlation (pid/time/correlation-id). Host-side `NSCocoaErrorDomain Code=4097` is a symptom, not proof.

* **Claim: “Harness/protocol bug (not policy).”**
  Required: explicit normalized outcome indicating protocol violation / bus I/O failure / expected abort canary, plus witness fields showing missing sentinel/events.

This framing is why the smoke fixtures explicitly prioritize surfacing the **normalized outcome + bounded error** on failure: it keeps transport symptoms, harness failures, and policy-shaped failures from collapsing into a single “XPC error” bucket. 

## Failure taxonomy

When something fails, the fastest way to avoid false conclusions is to classify along two axes: **launch vs. runtime**, and **policy-shaped vs. liveness-shaped**.

1. **Launch / lookup failures (nothing ran in the service)**
   Typical surface: `NSCocoaErrorDomain Code=4099 … failed at lookup … Sandbox restriction`.
   Interpretation: the execution environment blocked service lookup/launch; you did not reach the probe’s syscall surface. This is common under constrained harnesses and must be separated from app sandbox semantics.

2. **Runtime interruption (service launched, then died or dropped connection)**
   Typical surface: `NSCocoaErrorDomain Code=4097 … connection … interrupted`.
   Interpretation: treat as “service unhealthy” until you have a crash report or explicit service-side lifecycle evidence. The `inherit_child dynamic_extension` incident is a canonical example: the host symptom was XPC interruption, but the ground truth was a stack-guard crash in the service thread.

3. **Permission-shaped failures (syscall returned EPERM/EACCES, service stayed alive)**
   Interpretation: do not claim “sandbox denied” unless deny evidence is captured for the correct PID/time window. The tool’s own docs are explicit that EPERM/EACCES is not sufficient for attribution. 

4. **Protocol/harness failures (explicit normalized outcomes)**
   Interpretation: treat as substrate failure; these are “tool correctness” problems, not policy results. `inherit_child` intentionally preserves distinct normalized outcomes for protocol violations and expected abort canaries so they don’t masquerade as sandbox behavior.

## Forensics playbook: artifacts and correlation

A security engineer or RE typically wants “what do I collect, and how do I correlate it” more than a narrative. The minimal playbook:

* **Crash reports (.ips) as ground truth for fast death**
  Location: `~/Library/Logs/DiagnosticReports/` (service-name prefixed, e.g., `ProbeService_*…ips`).
  Format: `.ips` is JSON (often header JSON line + main JSON body).
  Correlate by: service PID (when available in witness), timestamp, and correlation-id tags in signposts (if enabled).

* **Sandbox deny evidence as ground truth for “denied” attribution**
  Best: run with `--capture-sandbox-logs` so deny excerpts are attached to the same JSON artifact; otherwise use `sandbox-log-observer` out-of-band with the service PID + process name extracted from the witness. 

* **Timeline evidence (signposts) to separate “slow / blocked / hung” from “never reached code”**
  Enable with `--signposts` and optionally attach with `--capture-signposts`. Captured signposts should be treated as best-effort evidence: they support ordering and latency claims, but absence of signposts is not proof of absence unless you can establish signposts were enabled for that principal.
  Implementation note (checked-in observer): the signpost observer shells out to `/usr/bin/log show --signpost --style json` and filters by subsystem + `eventMessage CONTAINS "pw_corr=<id>"`; it also defends against output shape changes by handling both JSONL and single JSON-array output (see `signpost-log-observer.rs`). It caps captured log bytes (1 MiB) and records truncation explicitly. (Source: the attached `signpost-log-observer.rs` file.)

* **Fixture/test harness artifacts as “diagnostic amplifiers”**
  The smoke fixture runner for `inherit_child` is designed to turn failures into actionable summaries by parsing the probe’s JSON output even when the probe exits non-zero, then scrubbing and comparing against stable fixtures. This is an example of a “high-signal failure surface” that security engineers will appreciate because it prevents multi-process failures from collapsing into a generic non-zero exit. 

## Private SPI/ABI dependency index

For internals specialists and reverse engineers, the “stability risk register” is as important as the functional story. PolicyWitness intentionally interacts with private sandbox extension SPI to demonstrate and measure behavior (issue/consume/release/update). That implies:

* **Symbols may vary across OS releases**, and wrapper functions can succeed without causing observable access changes. The docs explicitly warn that return codes (e.g., `rc==0`) are not evidence; probes define success as “access delta observed” via post-call access checks in the witness.
* **Token formats and call variants matter.** The user guide documents token formatting options and experimental maintenance calls such as `update_file_by_fileid`, including the existence of “call variants” to pin an ABI path during debugging. This is the kind of detail an RE will use as an index when comparing behavior across macOS versions. 
* **Avoid “probe calls probe” patterns in constrained contexts.** The `dynamic_extension` crash shows why: stacking “large probe implementations” can exceed service-thread stack constraints and manifest as misleading transport errors. The architectural guidance from a stability perspective is: keep high-risk SPI interactions local and shallow, and preserve substrate invariants/witness schema.

## Security review checklist

This is the checklist that tends to matter in a security engineering review of tooling like this:

* **Execution surface constraints remain intact**

  * No “exec arbitrary path” feature exists; execution is identifier-dispatched probes inside signed services.
  * `run-system` is restricted to platform-style paths; `run-embedded` is restricted to signed helpers in the app bundle.

* **Risk signals are discoverable and honest**

  * High-concern variants (`@injectable`) and high-concern profiles (e.g., temporary exceptions) are surfaced as risk tiers/reasons, derived from actual entitlements rather than hand-maintained labels.

* **Evidence capture cannot be coerced into unintended exfiltration**

  * Sandbox deny capture should be PID-scoped and time-bounded; signpost capture should be correlation-id scoped and predicate-bounded.
  * Capture artifacts should record tri-state status (not requested / requested unavailable / captured) so absence is interpretable.

* **Protocol surfaces fail closed**

  * `inherit_child` protocol/version/cap-id mismatches produce explicit normalized outcomes rather than undefined behavior.
  * A run with no child events is treated as diagnostic of early death, not as implied policy denial.

* **Witness semantics stay observational**

  * For “maintenance” and extension-style probes: success is defined by an observable access delta, not by SPI return codes.
  * Attribution claims (“sandbox denied”) require external evidence, not just permission-shaped errno.

* **Tests reinforce hermetic interpretability**

  * Smoke fixtures should surface normalized outcomes and bounded errors on failure, and should continue to produce artifacts even when a subprocess exits non-zero. (`inherit_child_fixtures.sh` is an example of this pattern.) 

## Attached references (for the companion document)

* [PolicyWitness.md](sandbox:/mnt/data/PolicyWitness.md) 
* [AGENTS.md](sandbox:/mnt/data/AGENTS.md) 
* [README.md](sandbox:/mnt/data/README.md) 
* [inherit_child dynamic_extension crash postmortem](sandbox:/mnt/data/inherit_child_crash.md) 
* [inherit_child smoke fixtures](sandbox:/mnt/data/inherit_child_fixtures.sh) 
* [signpost-log-observer.rs](sandbox:/mnt/data/signpost-log-observer.rs)
