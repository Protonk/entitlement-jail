# AGENTS.md (automation contract)

This file is written for downstream automation/agents. Treat it as a “research integrity” contract for how to extend or operate this repo without accidentally producing misleading security claims.

## Repo discovery (do not assume layout)

- Do not hardcode repo structure beyond what the user explicitly asked for.
- Discover entrypoints and paths by reading the docs and inspecting the filesystem:
  - Start at `README.md`.
  - Follow links to `runner/README.md`, `xpc/README.md`, and `SIGNING.md`.
  - Inspect the actual on-disk bundle/layout you are operating on (for example, whether `EntitlementJail.app` exists, whether XPC services are embedded, etc.).
- Do not assume a built `.app` exists. If you need one, build it; if you can avoid building it, avoid building it.

## Witness hygiene (layer attribution is mandatory)

When reporting results, always keep “what happened” and “which subsystem caused it” separate.

- Do not conflate “couldn’t launch” with “denied by sandbox”.
  - Example: `posix_spawn` failure may be a missing file, invalid signature, quarantine/Gatekeeper prompting behavior, `execve` policy, or a Seatbelt denial.
  - If you didn’t capture a sandbox denial signal, don’t claim “sandbox denied”.
- Always keep layer attribution explicit:
  - **Seatbelt/App Sandbox** (process-exec restrictions, container boundaries, extension grants)
  - **Quarantine/Gatekeeper** (`com.apple.quarantine`, assessment, prompting)
  - **Other** (codesign validity, missing timestamp, path validation, filesystem permissions, launchd/XPC issues)
- Default posture is “write + observe only”.
  - No silent execution of produced artifacts.
  - If an experiment produces an executable artifact, treat it as a specimen: record metadata and assessment signals, but do not run it unless the user explicitly requests that you do so.

Practical implications:

- Prefer “observer” style tools that inspect metadata (`xattr`, `spctl --status`, optional `spctl --assess`) over tools that execute the artifact.
- If you perform a Gatekeeper assessment (`spctl --assess`), state clearly that it is an assessment signal, not a faithful simulation of Finder double-click prompting.

## Extension rules (how to add new experiments safely)

### Entitlements as an experimental variable: prefer XPC services

- If the goal is “toggle entitlements and observe behavior”, prefer adding a **new XPC service target** (each `.xpc` is its own signed target with its own entitlements) over adding more child-process inheritance helpers.
- Rationale: XPC services are launchd-managed and are the Apple-preferred way to structure helper-like functionality; inheritance is fragile and has strict entitlement constraints (see `xpc/README.md`).

### Embedded helpers: bundle-embedded only

If you add embedded helper executables:

- They must live inside the `.app` bundle (for example under `Contents/Helpers/...`).
- Do not reintroduce “stage Mach-O into container/writable location then exec by path” patterns. This repo’s core constraint is that App Sandbox commonly denies `process-exec*` for writable/container locations.
- Any signing/notarization steps must be documented in `SIGNING.md` (do not duplicate procedures here).

### Dangerous/misleading entitlements posture

This repo may document and demonstrate “misleading” or security-sensitive entitlements, but must do so with explicit boundary markers:

- What runs where (main app vs helper vs XPC service vs unsandboxed observer)
- What was measured vs what was not measured
- What was explicitly **not executed**
- Which subsystem is responsible for observed differences (Seatbelt vs quarantine/Gatekeeper vs other)

Avoid language that implies stronger claims than what was tested (for example “this entitlement allows execution” when only a quarantine bit changed).

## Signing attention (policy, not procedure)

- Any time you add a new Mach-O executable to the app bundle (helpers, XPC services, etc.), it requires explicit signing/sandboxing attention.
- Apple calls this out as a common failure mode for sandboxed apps; helpers and XPC services are included (see [Apple Developer QA1773: Common app sandboxing issues](https://developer.apple.com/library/archive/qa/qa1773/_index.html?utm_source=chatgpt.com)).
- All signing, packaging, and optional notarization guidance must live in `SIGNING.md`: [SIGNING.md](SIGNING.md).
