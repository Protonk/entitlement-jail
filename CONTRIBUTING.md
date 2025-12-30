# Contributing to EntitlementJail

This repo is a research/teaching tool. Contributions are welcome, but “the product” here is not just code — it’s *inspectable behavior* plus the written guides that explain what that behavior is supposed to mean.

## What good contributions look like (in this repo)

### Documentation + comments are part of the product

If a change affects behavior, outputs, or safety boundaries, it needs matching words.

- Keep the docs in sync with reality:
  - End-user workflows live in `EntitlementJail.md`.
  - The authoritative CLI contract lives in `runner/README.md`.
  - XPC architecture/extension guidance lives in `xpc/README.md`.
  - Build/signing procedure lives in `SIGNING.md`.
- Use code comments for *why*, not *what*:
  - Document invariants (“we intentionally refuse X”) and the reason they exist.
  - Document assumptions that a reverse engineer or future maintainer will trip over (bundle paths, signing order, service naming).

Robots read code comments even if humans may not; if comments are present, keep them accurate — they materially help understanding.

### Tests are awkward here — try anyway

This is a macOS app-bundle + signing + XPC repo. Some tests are inherently “unwieldy” (they depend on signing state, launchd/XPC behavior, unified logging, filesystem layout, etc.). That’s understood — but it’s valuable to add *some* coverage when you can.

Preferred options, in roughly increasing integration cost:

- **Rust unit tests** for pure logic (JSON envelopes, parsing, path policy helpers).
- **CLI integration tests** in `runner/tests/cli_integration.rs` (expects a built `EntitlementJail.app` or `EJ_BIN_PATH`).
- **Smoke scripts** in `tests/suites/smoke/` for end-to-end “does the bundle basically work”.

If you can’t write a durable automated test, add a small smokeable workflow to docs (a command that produces a witness JSON) so reviewers have a consistent way to verify your change.

### `inherit_child` is a frozen contract surface

`inherit_child` is not a one-off probe; it is an inspection substrate with frozen contracts and regression protection.

If you change `inherit_child`, treat these as compatibility requirements:

- **Two-bus separation is mandatory**: event bus is bytes/JSONL; rights bus is `SCM_RIGHTS`. Do not pass FDs over the event bus.
- **Protocol + witness schema are contracts**: `xpc/ProbeAPI.swift` (`InheritChildProtocol`, `InheritChildWitness`) is authoritative. If you break framing, bump the protocol version and update both parent + child together.
- **Scenario names are part of the probe contract**: they are enumerated by a single catalog (`xpc/InProcessProbeCore.swift`) and are exercised by smoke + golden fixtures. Don’t silently rename/drop scenarios.
- **Self-diagnosing failures matter**: protocol violations, bus I/O errors, and expected abort canaries must remain distinct normalized outcomes (don’t collapse them into “deny-shaped” failures).
- **Golden fixtures must be updated intentionally**: if you change witness schema or deterministic fields like `outcome_summary`, update `tests/fixtures/inherit_child/` via the fixture harness (`EJ_UPDATE_FIXTURES=1`) and keep the scrub/compare tools accurate.

### Probes are multi-phase transcripts (not single return codes)

When a probe’s semantics depend on “before vs after”, the probe must be a multi-phase transcript:

- Success criteria are access deltas (“access delta observed”); return codes alone are insufficient (`rc==0` is not evidence).
- Action + outcome are first-class per phase: record what was attempted and what happened (rc/errno and post-action checks).
- For candidate sweeps (for example `update_file_by_fileid`), per-candidate post-call checks are required (avoid “errno hunting”).
- Rename/move experiments must gate on uncheatable premises (inode-preserving, same device, destination non-existent) and return distinct normalized outcomes when the premise fails.
- Durable sessions are required for extension liveness claims; otherwise probes degenerate to fresh-start semantics.
- Guardrail identity fields must remain present even when the child never emits events (bundle id, team id, entitlements, contract_ok).

For transport-heavy probes (especially `inherit_child`), contributor requirements also include:

- Raw `write(2)` emission (avoid fragile `FileHandle` paths), actual FD propagation (no hardcoded fd numbers), and an ultra-early sentinel.
- Two-channel separation (event bus vs rights bus), protocol version/namespace/cap-id validation, and strict cap-id handling (protocol violations are distinct from sandbox denies).
- Smoke tests + scrubbed golden fixtures should assert both shape and meaning (ordering invariants, access deltas, early-stop outcomes), including premise-failed fixtures as well as happy fixtures.

### Write Swift like you want it trivially reverse-engineered

EntitlementJail’s Swift is intentionally “inspection-friendly”. Optimize for clarity over cleverness:

- Prefer straightforward control flow and explicit types over “cute” abstractions.
- Keep request/response structs in `xpc/ProbeAPI.swift` stable; treat them like an API.
- Avoid unnecessary reflection, runtime magic, or metaprogramming that makes traces and disassembly noisy.
- Keep strings (probe ids, `normalized_outcome` labels, error text) stable and descriptive as they become part of witness records.

## Building EntitlementJail.app (developer guide)

The build produces a single distributable artifact: `EntitlementJail.app` (plus `EntitlementJail.zip` for notarization/distribution flows).

Canonical signing/packaging procedures live in `SIGNING.md`. This section is the “tour” version: how the build is structured and what you’ll need to know when changing it. For XPC build layout details, also see `xpc/README.md`.

### If you’re changing `build.sh`, keep these in mind

These are the “sharp edges” contributors commonly hit:

- The build depends on a **bundle layout contract**. Paths like `Contents/MacOS/xpc-probe-client` and `Contents/XPCServices/*.xpc` are assumed by docs, tests, and the evidence system.
- Don’t “fix” signing by adding `codesign --deep` to the signing steps. Sign known nested binaries explicitly, then sign the outer `.app` last (verification can use `--deep`).
- XPC services are discovered by directory enumeration. The script assumes:
  - directory name == service name,
  - service bundle name == `<ServiceName>.xpc`,
  - executable name == `<ServiceName>`.
- If you add a new embedded executable (helper/tool/service), make sure it’s:
  - placed in the bundle where the runtime expects it,
  - signed appropriately,
  - included in Evidence generation/verification expectations (often “rebuild and re-run evidence generation” is enough; sometimes you also need to teach the evidence generator about new helper names).
- If you touch `inherit_child`, keep the per-service helper embedding/signing steps aligned with `xpc/InProcessProbeCore.swift` path resolution and the inheritance entitlements guardrails in `tests/build-evidence.py`.
- `SWIFT_MODULE_CACHE` is intentionally set to a repo-local writable directory; don’t move it back to a path that sandboxed harnesses commonly block.

## Toy example: adding a new XPC service

The clean way to add an “entitlements as a variable” target is to add a new `.xpc` service under `xpc/services/`.

Here’s a minimal “copy and tweak” example that creates a new probe service with a small entitlement delta.

### 1) Copy an existing service directory

```sh
cp -R xpc/services/ProbeService_minimal xpc/services/ProbeService_example_combo
```

### 2) Update `Info.plist` to match the new service name

Edit `xpc/services/ProbeService_example_combo/Info.plist`:

- `CFBundleExecutable` → `ProbeService_example_combo`
- `CFBundleName` → `ProbeService_example_combo`
- `CFBundleIdentifier` → `com.yourteam.entitlement-jail.ProbeService_example_combo`

The directory name, plist names, and executable name must line up: the build script compiles the service binary to `.../<ServiceName>.xpc/Contents/MacOS/<ServiceName>`.

### 3) Change entitlements (the actual “variable”)

Edit `xpc/services/ProbeService_example_combo/Entitlements.plist` to add entitlements you want to study. For example:

- `com.apple.security.app-sandbox` = `true` (keep)
- `com.apple.security.network.client` = `true`
- `com.apple.security.files.downloads.read-write` = `true`

### 4) Rebuild (and let Evidence regenerate)

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build
```

After rebuilding, the new service will be embedded and signed, and `profiles.json` will gain a new profile derived from its signed entitlements.
The build will also generate an injectable twin (`<ServiceName>__injectable` with bundle id `<base>.injectable`) automatically; do not create a second entitlements file for it.

### 5) Make it discoverable (docs)

If the new service is intended to be a stable research target, also update:

- `xpc/README.md` (list the service and what’s different about it)
- `EntitlementJail.md` (if users are expected to run it by profile)

If your entitlement adds a “high concern” capability, update the risk classifier in `tests/build-evidence.py` so the profile carries the correct risk signal.
