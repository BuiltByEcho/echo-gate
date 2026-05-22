---
name: echo-gate
description: Use Echo Gate when registering, exposing, calling, securing, auditing, or operating agent-callable tools through the BuiltByEcho gateway. Covers tool registry entries, API keys, receipts, authenticated calls, Convex-backed state, private staging, VPS health checks, and the future x402 paid-tool path.
---

# Echo Gate

Echo Gate is the control layer for agent tools: registry, permissions, API keys, receipts, limits, and paid-call readiness before an agent touches anything real.

Use this skill when a task involves:

- registering an agent-callable tool
- creating, listing, or revoking Echo Gate API keys
- calling a tool through the gateway
- checking receipts for tool calls
- operating the VPS service
- checking private staging health
- preparing a tool for x402/Bankr paid access

## Current Status

- Public staging base: `https://storage.builtbyecho.xyz/echo-gate`
- Health: `https://storage.builtbyecho.xyz/echo-gate/health`
- Local project: `projects/echo-gate`
- Package: `@builtbyecho/echo-gate`
- Convex project: `echo-gate`
- Convex deployment: `dev:hearty-kookabura-959`
- VPS PM2 processes: `echo-gate`, `echo-gate-caddy-route`
- Status: private staging until Dustin explicitly approves public launch.

## API Surface

- `GET /health`
- `GET /tools`
- `POST /tools`
- `POST /keys`
- `GET /keys`
- `DELETE /keys/:id`
- `POST /tools/:slug/call`
- `GET /receipts`

Admin routes require `Authorization: Bearer <ECHO_GATE_ADMIN_TOKEN>`.

Tool calls require `Authorization: Bearer egk_...`.

## CLI

From the project root:

```bash
npm run build
npm test
node bin/echo-gate.js health
node bin/echo-gate.js tools
node bin/echo-gate.js create-key --name demo --tool echo
node bin/echo-gate.js call echo --json '{"hello":"world"}'
node bin/echo-gate.js receipts
node bin/echo-gate.js keys
node bin/echo-gate.js revoke-key <id>
```

Use env vars:

- `ECHO_GATE_URL`
- `ECHO_GATE_KEY`
- `ECHO_GATE_ADMIN_TOKEN`

## VPS Operations

Deploy only after local checks pass:

```bash
npm run build
npm test
ECHO_GATE_ADMIN_TOKEN=... ECHO_GATE_PORT=8792 npm run deploy:vps
```

Check live health:

```bash
curl -sS https://storage.builtbyecho.xyz/echo-gate/health
ssh vps 'pm2 list --no-color | grep echo-gate'
```

Do not paste or store the admin token in chat, docs, memory, commits, or public issue comments.

## Release Rules

- Do not announce publicly until Dustin explicitly approves.
- Do not publish API keys.
- Keep `echo` as the smoke tool until real adapters are ready.
- Before launch, verify build, tests, public health, unauthenticated `401`, valid-key call, receipt write, and key revocation.
- x402/Bankr paid tool calls are planned, not live yet.
