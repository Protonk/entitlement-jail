# entitlement-jail

`entitlement-jail` is a **research/teaching tool** for exploring macOS App Sandbox and entitlement behavior (including “misleading” or security-sensitive entitlements). It is intentionally not a distribution-grade product.

The core constraint behind the design is that the App Sandbox commonly denies `process-exec*` for executables staged into **writable/container locations**, so “exec arbitrary staged Mach-O by path” is not a supported model. Instead, the supported execution surfaces are:

- `run-system`: in-place platform binaries (`/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`, `/usr/libexec`, `/System/Library`)
- `run-embedded`: bundle-embedded, correctly signed helper tools (sandbox inheritance)
- `run-xpc`: `launchd`-managed XPC targets (preferred for entitlements-as-a-variable research)

Apple’s guidance is to prefer XPC services for helper-like functionality, and sandbox inheritance has strict entitlement constraints (see [Apple Developer: Enabling App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html?utm_source=chatgpt.com)).

## What’s inside

- [runner/README.md](runner/README.md) — CLI/behavior manual (including Quarantine Lab + unsandboxed observer)
- [xpc/README.md](xpc/README.md) — XPC architecture and extension guide
- [experiments/README.md](experiments/README.md) — tri-run harness (baseline vs policy vs entitlement) + mismatch atlas
- [SIGNING.md](SIGNING.md) — signing order, entitlements, packaging/notarization, troubleshooting
- [CONTRIBUTING.md](CONTRIBUTING.md) - Worked examples including adding a new xpc service

## Research posture

Outputs emphasize provenance and **layer attribution** (Seatbelt vs quarantine/Gatekeeper vs “other”). The Quarantine Lab writes/opens artifacts and reports `com.apple.quarantine` deltas **without executing anything**; the observer is intentionally run outside the sandboxed app to avoid attribution mixing.
