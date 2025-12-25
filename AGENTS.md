# AGENTS.md

## Conceptual router (start here)

This file is a “research integrity” contract for anyone (human or agent) extending, operating, or reporting on this repo. EntitlementJail is deliberately designed to produce *witness records* — structured descriptions of outcomes — without quietly smuggling in stronger claims about why those outcomes happened.

Before you touch code, run experiments, or write up results, orient yourself in the project’s two core ideas:

First, EntitlementJail is not a single binary that “has entitlements”. It is an app bundle that intentionally contains *many* separately signed executables: a plain-signed host-side launcher plus a zoo of sandboxed XPC services, each with its own entitlement profile. This makes entitlements a first-class experimental variable without leaning on fragile child-process inheritance or “exec by path” patterns.

Second, when something fails on macOS, there are multiple layers that can plausibly be responsible. A clean writeup keeps “what happened” (return codes, errno, paths, timing, logs) separate from “which subsystem caused it” (Seatbelt/App Sandbox, quarantine/Gatekeeper, or something else like signing validity or launchd/XPC behavior). This repo’s documentation, tools, and output formats are built around that separation.

If you’re trying to use the distributed artifact, treat `EntitlementJail.app` + `EntitlementJail.md` as the product. If you’re trying to understand what the CLI does and what it claims to measure, use `runner/README.md` as the authoritative behavior manual. If you’re modifying how entitlements are varied, live primarily in `xpc/` and follow `xpc/README.md` (XPC services are the preferred research target boundary). If you’re building or distributing artifacts, keep all signing, packaging, and (optional) notarization procedure in `SIGNING.md`.

When you are about to interpret a “permission-shaped failure”, slow down and route it through the attribution stack: does the file exist and is the path what you think it is; is the code signed the way you think it is; is the artifact quarantined; did a sandbox denial actually occur; did launchd/XPC fail to start the service; did the tool refuse an operation by design? This repo is most useful when you keep that stack explicit in your notes and outputs.

## Repo discovery (do not assume layout)

Do not assume the layout you remember from last week is the one you have on disk today. Start with `README.md`, then follow through to `runner/README.md`, `xpc/README.md`, and `SIGNING.md`. Finally, inspect the actual bundle/layout you’re operating on (for example: does `EntitlementJail.app` exist, are the XPC services embedded under `Contents/XPCServices`, are there helper tools under `Contents/MacOS`, and does the evidence directory exist under `Contents/Resources/Evidence`).

## Witness hygiene (layer attribution is mandatory)

When reporting results, always keep “what happened” and “which subsystem caused it” separate. “Couldn’t launch” is an outcome; “sandbox denied” is an attribution claim that requires evidence.

A `posix_spawn` (or similar) failure may be a missing file, an invalid signature, quarantine/Gatekeeper prompting behavior, an `execve` policy boundary, or a Seatbelt denial. If you didn’t capture a sandbox denial signal, don’t claim “sandbox denied”.

Keep layer attribution explicit. In this repo, the primary layers we care about are Seatbelt/App Sandbox (process-exec restrictions, container boundaries, extension grants), quarantine/Gatekeeper (`com.apple.quarantine`, assessment, prompting), and “other” causes (signature validity, missing secure timestamps, path validation, filesystem permissions, launchd/XPC issues, and repo-internal refusals-by-design).

Default posture is “write + observe only”. No silent execution of produced artifacts. If an experiment produces an executable artifact, treat it as a specimen: record metadata and assessment signals, but do not run it unless the user explicitly requests that you do so.

Practical implications:

Prefer “observer” style metadata inspection over tools that execute the artifact. If you perform a Gatekeeper assessment, state clearly that it is an assessment signal, not a faithful simulation of Finder double-click prompting. Suggested observer commands (and all signing/distribution procedure) live in `SIGNING.md`.

## Extension rules (how to add new experiments safely)

### Entitlements as an experimental variable: prefer XPC services

If the goal is “toggle entitlements and observe behavior”, prefer adding a **new XPC service target**. Each `.xpc` is its own signed target with its own entitlements, which keeps the experimental variable crisp and avoids inheritance edge cases. XPC services are launchd-managed and are the Apple-preferred way to structure helper-like functionality; inheritance is fragile and has strict entitlement constraints (see `xpc/README.md`).

### Embedded helpers: bundle-embedded only

If you add embedded helper executables, they must live inside the `.app` bundle (for example under `Contents/Helpers/...`). Do not reintroduce “stage Mach‑O into a container/writable location then exec by path” patterns; this repo’s core constraint is that App Sandbox commonly denies `process-exec*` for writable/container locations, and the whole point is to avoid misattributing that failure mode. Any signing/notarization steps must be documented in `SIGNING.md` (do not duplicate procedures here).

### Dangerous/misleading entitlements posture

This repo may document and demonstrate “misleading” or security-sensitive entitlements, but must do so with explicit boundary markers. Always spell out what runs where (main app vs helper vs XPC service vs unsandboxed observer), what was measured vs what was not measured, what was explicitly **not executed**, and which subsystem is responsible for observed differences (Seatbelt vs quarantine/Gatekeeper vs other).

Avoid language that implies stronger claims than what was tested (for example “this entitlement allows execution” when only a quarantine bit changed).

## Signing attention (policy, not procedure)

Any time you add a new Mach‑O executable to the app bundle (helpers, XPC services, etc.), it requires explicit signing/sandboxing attention. Apple calls this out as a common failure mode for sandboxed apps; helpers and XPC services are included (see [Apple Developer QA1773: Common app sandboxing issues](https://developer.apple.com/library/archive/qa/qa1773/_index.html)). All signing, packaging, and optional notarization guidance must live in `SIGNING.md`: [SIGNING.md](SIGNING.md).
