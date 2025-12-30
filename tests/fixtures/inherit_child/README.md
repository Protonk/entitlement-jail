# `inherit_child` fixtures (how to read them)

These JSON files are **scrubbed** `inherit_child` witnesses (see `tests/tools/scrub_inherit_child_witness.py`). They exist to preserve the meaning of the witness without editing the JSON to add commentary.

Facts encoded by fields you can see in the fixtures:

- Two-channel design: the harness uses an event bus (JSONL events + sentinel) and a rights bus (`SCM_RIGHTS` FD passing). The fixtures preserve that the witness carries both transports via `child_event_fd_present` and `child_rights_fd_present`.
- Sentinel proves the child reached user code: `events[]` includes `phase: "child_sentinel"` (for example `dynamic_extension.json`). Missing `child_sentinel` (and missing other child phases) implies the child died before writing, not a sandbox deny.
- Protocol version/namespace/cap-id validation is enforced: fixtures record `protocol_version` and `capability_namespace`, and protocol violations are a distinct failure class (`normalized_outcome: "child_protocol_violation"` with structured `protocol_error` in full output).
- Protocol violations are distinct from sandbox denies: protocol errors do not get “upgraded” into deny-shaped outcomes; they stay explicitly attributable to the harness/protocol.
- Stop mechanics are start-suspended and observable: stop-on-entry/deny emits explicit `events[].phase` markers (kept when present) so “stop points that matter” are testable without a debugger.
- Callsite IDs/backtraces localize denies: `events[]` include scrubbed booleans (`callsite`, `backtrace`, `backtrace_error`) so deny localization regressions are visible without raw addresses.
- Sandbox log capture status semantics are recorded: `sandbox_log_capture_status` is tri-state (`not_requested|requested_unavailable|captured`), so absence of logs is interpretable.

Examples:

- `dynamic_extension.json` shows a sentinel + a deny-shaped timeline with callsite/backtrace signals.
- `matrix_basic.json` shows multiple capabilities in `capability_results[]`.
- `inherit_bad_entitlements.json` demonstrates the expected abort canary and the “no child-emitted events implies early child failure” interpretation.
