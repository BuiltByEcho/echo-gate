# Echo Gate Launch Checklist

Echo Gate is in private staging until Dustin explicitly approves public posting, npm publishing, or GitHub release.

## Current Live Surface

- Public base: `https://storage.builtbyecho.xyz/echo-gate`
- Health: `https://storage.builtbyecho.xyz/echo-gate/health`
- VPS process: PM2 `echo-gate`
- Route helper: PM2 `echo-gate-caddy-route`
- Primary data path: local state and local secret storage.
- Optional remote prototype: Convex `echo-gate` dev deployment `dev:hearty-kookabura-959`.

## Verified

- Build passes.
- Tests pass.
- Local-first build/test gates pass.
- Public health endpoint returns `ok`.
- Public tools endpoint lists the registered `echo` tool.
- Unauthenticated tool calls fail with `401`.
- Admin key creation works.
- Tool calls with valid API keys work and write receipts.
- Key revocation works.
- Revoked keys fail with `401`.
- Caddy route helper is running under PM2 and re-applies `storage.builtbyecho.xyz` routes through the Caddy admin API.

## Before Public Announcement

- Decide whether to keep the launch URL under `storage.builtbyecho.xyz/echo-gate` or add a dedicated DNS record later.
- Decide whether the first public demo is just `/health` + narrative, or whether to show a real API-key demo.
- Do not publish API keys.
- Do not paste `ECHO_GATE_ADMIN_TOKEN`.
- Keep the smoke `echo` tool as the public proof path until real adapters are added.

## Later Hardening

- Add signed receipts.
- Add x402/Bankr payment gate.
- Add per-tool owner metadata and trust scores.
- Add a small dashboard or static status page.
