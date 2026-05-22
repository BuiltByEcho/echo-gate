# Echo Gate Release Checklist

Echo Gate v0 is public as a local-first CLI release. The default product path runs on the user's machine with local state and local secret storage.

## Current Live Surface

- GitHub: `https://github.com/BuiltByEcho/echo-gate`
- npm: `echo-gate`
- CLI: `echo-gate`
- Primary data path: local state and local secret storage.
- Optional remote prototype: Convex remains experimental and opt-in only.

## Verified

- Build passes.
- Tests pass.
- npm audit is clean.
- npm dry-run package contents are expected.
- Bare `echo-gate` autostarts the local gateway for the TUI.
- Local-first API, key, policy, approval, receipt, secret, and spend-limit flows are covered by tests.

## Before Public Announcement

- Do not publish API keys.
- Do not paste `ECHO_GATE_ADMIN_TOKEN`.
- Keep the smoke `echo` tool as the public proof path until real adapters are added.
- Frame Keychain as recommended on macOS, with local JSON as the default user choice.

## Later Hardening

- Add x402/Bankr payment gate.
- Add per-tool owner metadata and trust scores.
- Continue dogfooding macOS Keychain prompts and interactive TUI setup flows.
