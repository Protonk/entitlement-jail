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

### Tests are awkward here — still try

This is a macOS app-bundle + signing + XPC repo. Some tests are inherently “unwieldy” (they depend on signing state, launchd/XPC behavior, unified logging, filesystem layout, etc.). That’s understood — but it’s still valuable to add *some* coverage when you can.

Preferred options, in roughly increasing integration cost:

- **Rust unit tests** for pure logic (JSON envelopes, parsing, path policy helpers).
- **CLI integration tests** in `runner/tests/cli_integration.rs` (expects a built `EntitlementJail.app` or `EJ_BIN_PATH`).
- **Smoke scripts** in `tests/suites/smoke/` for end-to-end “does the bundle basically work”.

If you can’t write a durable automated test, add a small smokeable workflow to docs (a command that produces a witness JSON) so reviewers have a consistent way to verify your change.

### Write Swift like you want it trivially reverse-engineered

EntitlementJail’s Swift is intentionally “inspection-friendly”. Optimize for clarity over cleverness:

- Prefer straightforward control flow and explicit types over “cute” abstractions.
- Keep request/response structs in `xpc/ProbeAPI.swift` stable; treat them like an API.
- Avoid unnecessary reflection, runtime magic, or metaprogramming that makes traces and disassembly noisy.
- Keep strings (probe ids, `normalized_outcome` labels, error text) stable and descriptive as they become part of witness records.

## Building EntitlementJail.app (developer guide)

The build produces a single distributable artifact: `EntitlementJail.app` (plus `EntitlementJail.zip` for notarization/distribution flows).

Canonical signing/packaging procedures live in `SIGNING.md`. This section is the “tour” version: how the build is structured and what you’ll need to know when changing it.

### Quick build

`build-macos.sh` requires `IDENTITY` to be set to a **Developer ID Application** identity in your keychain.

```sh
IDENTITY='Developer ID Application: YOUR NAME (TEAMID)' make build
```

### How `build-macos.sh` is structured (high-level tour)

Think of `build-macos.sh` as a pipeline:

1. **Validate signing identity**
   - Fails early if `IDENTITY` is missing or not present in `security find-identity -p codesigning`.
2. **Build Rust tools**
   - Builds the launcher and supporting tools from `runner/Cargo.toml`.
3. **Assemble the app bundle layout**
   - Creates `EntitlementJail.app/Contents/...` and installs the launcher at `Contents/MacOS/entitlement-jail`.
4. **Build Swift clients + XPC services**
   - Compiles embedded XPC client helpers (`xpc-probe-client`, `xpc-quarantine-client`).
   - Enumerates `xpc/services/*` and compiles each directory into `Contents/XPCServices/<ServiceName>.xpc`.
5. **Codesign nested code (inside-out)**
   - Signs embedded helpers/tools/services first, then signs the outer `.app` last.
   - Each XPC service is signed with the entitlements in its own `xpc/services/<ServiceName>/Entitlements.plist`.
6. **Generate “Evidence” manifests**
   - Runs `tests/build-evidence.py` to write `Contents/Resources/Evidence/{manifest.json,profiles.json,symbols.json}`.
   - `profiles.json` is derived from *actual signed entitlements* (extracted via `codesign -d --entitlements`), not from repo metadata.
7. **Package the zip**
   - Uses `ditto` to create `EntitlementJail.zip` (the zip isn’t signed; the `.app` inside is).

### If you’re changing `build-macos.sh`, keep these in mind

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

### 5) Make it discoverable (docs)

If the new service is intended to be a stable research target, also update:

- `xpc/README.md` (list the service and what’s different about it)
- `EntitlementJail.md` (if users are expected to run it by profile)

If your entitlement adds a “high concern” capability that should require explicit acknowledgement, update the risk classifier in `tests/build-evidence.py` so the profile lands in the right tier.
