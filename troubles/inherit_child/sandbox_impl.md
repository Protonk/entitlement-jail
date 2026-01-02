## PolicyWitness maintainer report: child inheritance, entitlement contracts, and sandbox monitoring (with `inherit_child` as the substrate)

This report is meant for maintainers who already live inside the PolicyWitness model (Profiles → Sessions → Probes → Witnesses) and need a crisp, *operationally useful* mental model of what “parent/child inheritance” means in this project, what is actually being measured, and what instrumentation/contract surfaces must stay stable.

It deliberately does **not** describe any specific incident timeline, root cause, or fix history. Instead it distills the durable engineering lessons about (1) entitlement inheritance contracts, (2) child helper behavior and capability transfer, and (3) sandbox monitoring and attribution in a multi-process probe.

---

### 1) The core confusion: “entitlements passing” vs “sandbox state inheritance”

In macOS sandbox work, people say “the child inherits entitlements” as shorthand, but for PolicyWitness this shorthand is exactly the trap.

PolicyWitness’s stance (and the architecture) is:

* **Entitlements vary via XPC services, not by expecting entitlement propagation across exec.**
  The control plane stays host-side and unsandboxed; the sandbox boundary is the chosen XPC service bundle (and its variant). You want *OS-enforced* entitlement differences? You select a different service/profile, you do not try to “smuggle” entitlements into a child.

* **`inherit_child` exists specifically to make inheritance *observable* and *discriminable*** across multiple processes without turning every ambiguous failure into “maybe the sandbox denied it.”
  It’s a harness, not “just another probe.” Its job is to separate:

  * “child never ran user code” (diagnostic),
  * “child ran but protocol broke” (harness),
  * “child ran and got EPERM/EACCES” (possibly sandbox, possibly something else),
  * “child was intentionally mis-entitled and got aborted” (expected canary behavior),
  * “capability transfer succeeded even when independent acquisition failed” (the interesting boundary).

So the right framing is:

* **Static identity controls** (entitlements, signing identity, service bundle selection) define *which sandbox regime applies*.
* **Dynamic capabilities** (FDs, sandbox extensions, bookmarks, etc.) define *what access can be exercised at runtime*.
* The “inheritance” question you actually care about is:
  **Which parts of the parent’s effective access model survive an exec boundary, and which must be ferried explicitly?**

`inherit_child` is PolicyWitness’s “microscope slide” for that question.

---

### 2) `inherit_child` is a frozen inspection substrate, not an experiment sandbox

Maintainership-wise, treat `inherit_child` as a *contract surface* in three dimensions:

1. **Wire framing (two-bus protocol)**
2. **Witness schema (InheritChildWitness + events + capability_results)**
3. **Scenario names and semantics (fixtures depend on them)**

This is not negotiable because:

* smoke/fixtures scrub and compare the JSON outputs,
* tooling depends on stable, parseable structures,
* and the entire point is that “we can make a claim about a boundary” without needing bespoke investigator narrative.

If you change anything that affects those surfaces:

* bump protocol version where appropriate,
* update both ends (parent/service and child helper),
* and update fixtures + scrubbers.

---

### 3) The entitlement inheritance **contract** is explicit and enforced as a canary

PolicyWitness codifies “inheritance is valid” as a checkable property of the **child helper binary**, not a vague OS promise.

#### 3.1 What `inherit_contract_ok` means in practice

Inside the service, before any child choreography is trusted, the parent reads signing info for the child helper and computes:

* which `com.apple.security.*` keys exist, and
* whether the set of sandbox entitlements is *exactly*:

  * `com.apple.security.app-sandbox = true`
  * `com.apple.security.inherit = true`
  * **and no other** `com.apple.security.*` keys.

This is intentionally strict. It prevents “silent entitlement contamination” from masquerading as confusing runtime behavior.

You get `inherit_contract_ok` in the witness precisely so that “child died early” remains diagnosable rather than forever ambiguous.

#### 3.2 Why the canary exists (`inherit_bad_entitlements`)

The `inherit_bad_entitlements` scenario exists to keep this contract from drifting unnoticed. It is a deliberate regression tripwire:

* `pw-inherit-child-bad` is intentionally mis-entitled.
* The OS is expected to abort it.
* The probe’s normalized outcome makes this visible (`child_abort_expected` vs `child_abort_missing`), and the witness still carries identity fields so you can check what the child’s entitlements looked like.

From a maintainer’s perspective, this canary is not “just another test.” It’s your *sentinel that the platform contract you are assuming still exists*.

---

### 4) The multi-process reality: why the helper is embedded per-service

A detail that matters constantly for maintainership: **sandboxed XPC services cannot assume they can read or execute binaries from the host app bundle.**

`inherit_child` explicitly prefers the **service bundle copy** of the child helper:

* `ProbeService_*/Contents/MacOS/pw-inherit-child`
* `ProbeService_*/Contents/MacOS/pw-inherit-child-bad`

…and only falls back to the app-bundle copy if available.

This is not cosmetic:

* it avoids “works on my machine” behaviors where the service accidentally reads from a location it won’t be allowed to read in a stricter sandbox regime,
* and it keeps the child helper part of the same signed, inspectable service “world.”

This is also why build-evidence guardrails exist: you are validating not only the app-level helpers, but the per-service embedded copies across variants.

---

### 5) What `inherit_child` actually measures: **acquire vs use** (matrix model)

The harness is intentionally matrix-shaped:

1. **Parent acquires** a capability (or sets up the conditions for acquisition).
2. **Child attempts to acquire** the same capability independently.
3. **Child attempts to use** the ferried capability.

“Capability” is scenario-dependent:

* rights bus: file FD, dir FD, socket FD
* event bus: bookmark bytes

The key insight is that *sandbox denials are usually about the acquisition step*, while *possession-based capabilities (FDs) can allow use even when acquisition is denied*.

This makes “inheritance” testable without needing philosophical arguments about which exact internal policy check fired.

The witness exposes this directly:

* `capability_results[].parent_acquire`
* `capability_results[].child_acquire`
* `capability_results[].child_use`
* plus a deterministic scan view in `outcome_summary`.

---

### 6) The two-bus protocol is the reason this probe is reliable

The protocol is designed to prevent the most common way multi-process instrumentation lies to you: mixing structured events with FD passing and then mis-parsing your own telemetry.

#### 6.1 Event bus

* Transport: socketpair
* Child → parent: **JSONL events**, plus a single ultra-early sentinel line
* Parent → child: structured payload header + raw bytes (used for bookmark ferry)

Critical properties:

* The **first bytes** out of the child include a sentinel with protocol version + namespace, and it records which FDs the child believes it is using.
* If you get **no child-emitted events**, that is *diagnostic*: “child died before writing,” not “sandbox denied the operation.”

#### 6.2 Rights bus

* Transport: a separate socketpair dedicated to `SCM_RIGHTS`
* Parent → child: binary header (cap_id + meta fields) plus the FD in ancillary data

Critical properties:

* **Never pass FDs over the event bus.**
* The protocol uses meta fields to carry at least the protocol version (so the child can reject mismatches deterministically).

#### 6.3 Protocol validation is not optional

The harness treats protocol mismatches as first-class outcomes (`child_protocol_violation`, `child_*_bus_io_error`) rather than allowing undefined behavior to masquerade as “sandbox weirdness.”

As a maintainer, that’s the discipline: if your instrumentation is broken, you should see “instrumentation is broken,” not a permission-shaped failure.

---

### 7) Child lifecycle controls exist to make “attach and attribute” real

The child helper supports runtime knobs that are specifically there to turn “I think it denied” into “I can show you *where and when* it denied.”

* `--stop-on-entry`
  Start-suspended spawn + ultra-early stop marker so debugger attach is deterministic and not race-y.

* `--stop-on-deny`
  On `EPERM/EACCES` events, emit op + callsite + best-effort backtrace, then stop. This is essential for disambiguating:

  * which code path actually hit the deny,
  * whether the deny is in child acquire vs child use.

* `--stop-auto-resume`
  Lets scripted runs continue after a stop without requiring an interactive debugger.

Parent side uses `waitpid(..., WUNTRACED)` and explicit stop/resume tracking so the witness includes lifecycle context (`child_stopped`, `child_resumed`, `child_exited`).

---

### 8) Scenario semantics (and what each tells you about inheritance)

The stable scenario catalog is not just user-facing; it is a maintainer-facing semantic contract.

#### 8.1 `dynamic_extension` (parent-only dynamic grant + FD ferry)

Purpose: make “dynamic access” observable as a delta, and make explicit what does **not** automatically carry across to the child.

Operationally:

* The parent obtains a dynamic permission token (and later consumes it) to enable opening a target path.
* The child attempts its own acquisition.
* The parent then ferries the acquired FD over the rights bus.
* The child attempts to use the FD.

The important concept is: **dynamic grant vs capability possession**.
Even if the child cannot independently acquire access, use of a ferried capability can succeed.

This is exactly the kind of boundary confusion PolicyWitness is trying to resolve for users: “it was denied” can become “it was denied *at acquisition*, but use succeeded when the capability was ferried.”

#### 8.2 `matrix_basic` (file/dir/socket FD ferries)

Purpose: establish that the two-bus harness is correct and general.

It exercises:

* open a file and pass file FD
* open a directory and pass dir FD (then do openat-style actions)
* connect a local UNIX socket and pass socket FD (send/recv)

This gives you:

* both acquisition and use surfaces,
* and a sanity check that rights bus FD passing is working.

#### 8.3 `bookmark_ferry` (security-scoped bookmark bytes over event bus)

Purpose: exercise a “dynamic capability that is not an FD” and has explicit API-mediated lifecycle:

* parent constructs bookmark bytes
* child resolves bookmark, checks staleness, attempts startAccessing, then attempts access

The witness captures:

* resolve error shapes (including domain/code)
* staleness
* whether startAccessing succeeded
* access attempt outcomes

This scenario is particularly good at demonstrating that “payload ferry” is different from “FD ferry,” and why the event bus exists at all.

#### 8.4 `lineage_basic` (child spawns grandchild, re-ferries event bus)

Purpose: verify that “lineage” remains observable and that event bus ferry can be repeated.

This is less about capability itself and more about maintaining visibility across generations:

* lineage metadata (depth, pid, ppid) becomes part of the event stream.

#### 8.5 `inherit_bad_entitlements` (expected abort canary)

Purpose: ensure the inheritance contract is still enforced by the OS and your entitlements are still what you think they are.

It’s a premise test. If this stops behaving as expected, you should treat subsequent inheritance conclusions as suspect until you re-ground the model.

---

### 9) Monitoring: what PolicyWitness can and cannot prove from inside the sandbox

Inside the sandbox boundary, many signals collapse into EPERM/EACCES or process death. PolicyWitness’s monitoring posture is: **attach evidence outside the boundary, and plumb it into the same JSON artifact** so you can attribute.

#### 9.1 Sandbox deny evidence (`sandbox-log-observer`)

* Runs outside the sandbox boundary.
* Requires **PID + process name**.
* The CLI can attach the lookback excerpt under:

  * `data.host_sandbox_log_capture` always when requested, and
  * for `inherit_child`, additionally summarize into:

    * `data.witness.sandbox_log_capture_status`
    * `data.witness.sandbox_log_capture`

The “tri-state” status matters:

* `not_requested`: you didn’t ask
* `requested_unavailable`: you asked but lacked a PID, the observer couldn’t run, or couldn’t find a report
* `captured`: you have an observer report

This is how “no deny log” becomes interpretable rather than misleading silence.

Maintainer implication:
If you ever regress `child_pid` plumbing or break the JSON location the host expects to parse, you’ve broken evidence capture and turned attribution back into guesswork.

#### 9.2 Signposts: timeline stitching across Rust → Swift client → service → child

Signposts are intentionally:

* optional,
* off-by-default,
* best-effort.

When enabled, they provide time-ordered spans that let you correlate:

* request dispatch
* session open/wait
* spawn
* token issue/consume phases
* capability send/receive
* stop/resume
* exit

The capture path is host-side:

* `--capture-signposts` runs an observer after the run and attaches a structured timeline under `data.host_signpost_capture`.

Maintainer implications:

* Signpost gating must remain strict (no accidental overhead by default).
* Correlation context must remain consistent and flow into the child (environment propagation matters).
* The observer must remain robust to output shape changes from the underlying log tooling, because the entire point is “best effort, no surprises.”

#### 9.3 Sessions: durable process context + explicit lifecycle events

`xpc session` exists so that:

* “same process context” is not a hope but a guarantee, and
* debugging attaches can happen once, before probe execution.

For inheritance work, the presence of lifecycle events like:

* `child_spawned / child_stopped / child_exited`
  is what prevents “no events” from being a dead end.

---

### 10) Failure taxonomy: how to keep maintainers (and users) from mis-attributing

A lot of maintainership is keeping the tool honest about “what did we actually observe.”

Here’s the taxonomy that `inherit_child` already encodes, and that future changes should preserve:

#### 10.1 XPC boundary failures (`normalized_outcome = xpc_error`)

Host-side XPC errors are not sandbox denials; they mean “the boundary failed.”

You must keep distinguishing at least:

* lookup/launch refusal (environmental restriction / sandbox restriction / bad bundle layout)
* connection interrupted/invalidated (service died, crashed, was killed, or exited)

Maintainership requirement: preserve the error detail (domain/code/message) so downstream tooling can separate these.

#### 10.2 Harness/premise failures

Examples (non-exhaustive):

* `child_missing`
* `spawn_failed`
* `socketpair_failed`
* `child_*_bus_io_error`
* `child_protocol_violation`

These must remain clearly non-sandbox conclusions.

#### 10.3 Expected abort canaries

`child_abort_expected` is a *success condition* for `inherit_bad_entitlements`.
If you ever collapse this into “failure,” you remove a major guardrail.

#### 10.4 Permission-shaped operation failures (the dangerous middle)

Within capability results:

* `errno == EPERM || errno == EACCES` is *permission-shaped*, not necessarily “Seatbelt deny.”

PolicyWitness’s mitigation is:

* explicit phase/callsite events,
* optional backtrace on deny,
* and optional sandbox log capture attached to the same artifact.

Maintainer requirement: don’t regress those visibility hooks, especially in the “child acquire” phase. That’s where the story usually lives.

---

### 11) Maintainer guidance: how to evolve this area without breaking the project’s epistemics

#### 11.1 Keep probes self-contained; avoid “probe calls probe” patterns

Even when it’s tempting to reuse logic, deeply nesting large probe implementations inside other probes in the XPC service context is a recurring reliability hazard. The correct pattern is:

* extract small, side-effect-contained helpers,
* keep the in-service call depth and frame size disciplined,
* and preserve `inherit_child`’s mission: *instrumentation failure must not masquerade as sandbox outcome.*

#### 11.2 Guardrails you should not weaken

* **No arbitrary path exec** stays enforced.
* **Service bundle embedding** of helpers stays required.
* **Strict inheritance entitlement contract** stays strict.
* **Two-bus separation** stays absolute.
* **Protocol validation** stays explicit and fail-closed.
* **Witness identity fields** must be present even if child emits no events.

#### 11.3 Plumbing invariants to protect

* `child_pid` must be consistently available in the JSON path the host tooling expects.
* `process_name`/`service_name` must remain available for observers.
* `correlation_id` must remain stable and flow into child env when signposts are enabled.
* `sandbox_log_capture_status` tri-state semantics must not be collapsed.

#### 11.4 Test discipline: fixtures are not optional

The `inherit_child_fixtures` suite is doing real work:

* it locks scenario semantics,
* it locks witness structure (post-scrub),
* and it catches “small changes” that would otherwise produce non-reproducible attribution later.

Treat fixture updates as a design review event:
If you’re changing output, you’re changing what claims the tool can make.

---

### 12) High-value future extensions (if you want to deepen inheritance understanding without expanding scope wildly)

These are additive ideas that preserve the current model while sharpening “inheritance” discrimination:

1. **Add a “no_inherit” sibling helper scenario**
   A helper that is app-sandboxed but lacks the inherit entitlement, so you can compare:

   * same parent,
   * same spawn mechanism,
   * different inheritance contract,
   * same capability matrix.
     This would give an explicit “inherit vs no-inherit” baseline inside the same substrate.

2. **Add a “post-grant child re-acquire” phase for dynamic grants**
   If you want to test whether a dynamic grant affects only the parent or also changes what the child can acquire later, add a second child acquisition attempt *after* the parent has applied the dynamic change, explicitly labeled in events and summarized in outcome_summary.

3. **Dual-PID sandbox log capture**
   For inheritance questions, denies can occur in parent or child. Capturing both `service_pid` and `child_pid` excerpts (when requested) would make attribution more complete without changing the probe’s semantics.

4. **Explicit “sentinel observed” boolean + parse results in witness**
   You already infer this from event stream behavior; making it explicit would help downstream tooling classify early-death vs “child ran but never got to phase X.”

---

## Closing: what you can confidently claim (and what you should resist claiming)

With the current substrate, PolicyWitness can make strong, checkable claims of the form:

* “The child helper matched the inheritance contract (`inherit_contract_ok` true), reached user code (sentinel/events), and behaved differently in **acquire** vs **use** phases under a known service sandbox regime, with optional deny evidence attached.”

What it should resist (and what maintainers should protect against) are claims of the form:

* “It was denied by the sandbox” based solely on `EPERM`/`EACCES` without phase/callsite and (when needed) external evidence attachment.

`inherit_child` exists precisely to avoid that trap.
