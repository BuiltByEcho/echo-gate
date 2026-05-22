# Echo Gate

Echo Gate is the control plane for agent tools: registry, permissions, secret firewalling, receipts, limits, and paid-call readiness before an agent touches anything real.

Status: public v0 local-first release. Echo Gate is designed to run on the user's machine by default; no external database is required for the main product path.

## What v0 Does

- Registers agent-callable tools.
- Exposes tools behind one HTTP gateway.
- Verifies API keys.
- Keeps upstream secrets server-side and injects them only when the gateway calls a tool.
- Routes approval-required tools through a human approval queue.
- Supports per-bot/per-tool access policies: `deny`, `auto`, `approval`, and `limited`.
- Enforces lifetime or rolling-window spend limits before execution.
- Stores local-first state by default under `~/.config/echo-gate`.
- Stores secrets in local JSON by default, with optional macOS Keychain storage as the recommended safer route on Mac.
- Records receipts for every call.
- Ships a CLI for registration, calls, key creation, and receipt inspection.
- Uses a durable local control plane by default.
- Does not require Convex or any external database for the default product path.

## Local Start

```bash
npm install -g echo-gate
echo-gate
```

For development from source:

```bash
npm install
npm run build
npm test
ECHO_GATE_STORE=local npm run dev
```

## Gateway API

- `GET /health`
- `GET /tools`
- `POST /tools/:slug/call`
- `GET /receipts`

Tool calls require:

```http
Authorization: Bearer egk_...
```

## CLI

```bash
echo-gate
echo-gate setup
echo-gate health
echo-gate tools
echo-gate call echo --json '{"hello":"world"}'
echo-gate receipts
echo-gate keys
echo-gate revoke-key <id>
echo-gate secret add GITHUB_TOKEN
echo-gate access set --key <id> --tool github-issues --mode approval
echo-gate approvals
echo-gate approve <id>
echo-gate deny <id>
```

Set the gateway URL with `ECHO_GATE_URL`; defaults to `http://localhost:8787`.

Run `echo-gate` with no arguments to open the terminal control panel. It shows local gateway status, tool/key/receipt counts, and keyboard-first navigation for setup, secrets, access, approvals, receipts, tools, and bot keys. Secret creation is available inside the TUI with arrow keys, tab, enter, and backend selection.

Keyboard shortcuts:

- Arrow keys or `j`/`k` move.
- `enter` opens a section.
- `space` selects or toggles where supported.
- `r` refreshes gateway status.
- `esc` or `backspace` goes back.
- `q` quits.

Run `echo-gate setup` for the guided flow. It registers a protected capability and creates a scoped bot key. Secret values stay local; the setup flow stores env/local secret references such as `GITHUB_TOKEN`, not raw upstream secrets.

By default, `echo-gate secret add` writes to local JSON under `~/.config/echo-gate`. On macOS, users can opt into the safer Keychain route:

```bash
echo-gate secret add GITHUB_TOKEN --backend macos-keychain
```

Keychain secrets are generic password items under service `com.builtbyecho.echo-gate.secret`. Echo Gate keeps only non-secret metadata in `~/.config/echo-gate/secrets.json` for those entries. `echo-gate secret backend` shows the active default and the recommended backend for the current platform.

Register an HTTP tool that needs a secret without exposing the secret to the agent:

```bash
export GITHUB_TOKEN=...
echo-gate add-tool \
  --slug github-issues \
  --name "GitHub Issues" \
  --type http \
  --url https://example.com/github/issues \
  --secret-header authorization=GITHUB_TOKEN
```

Or store the secret locally first:

```bash
echo-gate secret add GITHUB_TOKEN
echo-gate secret test GITHUB_TOKEN
```

Create a key that can only call specific tools and cannot spend past a rolling cap:

```bash
echo-gate create-key --name demo-agent --tool github-issues --spend-limit-micros 100000 --spend-window-seconds 86400
```

Create a bot key with a per-tool access policy:

```bash
echo-gate create-key \
  --name research-agent \
  --tool github-issues \
  --policy github-issues=approval
```

Change access later:

```bash
echo-gate access set --key <key-id> --tool github-issues --mode limited --spend-limit-micros 5000000
```

Add `--spend-window-seconds <seconds>` to make a limited policy reset on a rolling window.

For approval-gated calls, Echo Gate returns `202` with an approval id. Echo Gate stores the pending payload locally. The human can then run:

```bash
echo-gate approvals
echo-gate approve <approval-id>
```

Approving executes the stored call and records the receipt. The agent can poll:

```bash
ECHO_GATE_KEY=egk_... echo-gate approval-status <approval-id>
```

## Build Notes

Echo Gate v0 intentionally keeps execution simple. It has a built-in `echo` adapter and an outbound HTTP adapter. The important surface is the control plane contract: tool registry, key auth, secret injection, call proxying, policy checks, and signed receipts.

Set `ECHO_GATE_RECEIPT_SIGNING_KEY` in production to attach HMAC signatures to receipts.

## VPS Deploy

```bash
ECHO_GATE_ADMIN_TOKEN=... npm run deploy:vps
```

The deploy script uses the `vps` SSH alias by default and installs the service as PM2 process `echo-gate`.
