# VPS Deployment

Echo Gate is designed to run as a long-lived Node process behind Caddy or Nginx.

## Environment

Required:

```bash
ECHO_GATE_PORT=8787
ECHO_GATE_ADMIN_TOKEN=
```

Optional:

```bash
ECHO_GATE_STORE=local
CONVEX_URL=
ECHO_GATE_ENABLE_EXPERIMENTAL_CONVEX=
ECHO_GATE_BIND=127.0.0.1
ECHO_GATE_RECEIPT_SIGNING_KEY=
NODE_ENV=production
```

`ECHO_GATE_STORE=local` is the default and recommended mode. Convex is experimental development-only code; it is not the secure local-first product path. To test it deliberately, set `ECHO_GATE_STORE=convex`, `CONVEX_URL`, and `ECHO_GATE_ENABLE_EXPERIMENTAL_CONVEX=1`.
Set `ECHO_GATE_RECEIPT_SIGNING_KEY` to sign every receipt with HMAC-SHA256.

## PM2

```bash
npm ci --omit=dev
npm run build
pm2 start dist/src/server.js --name echo-gate
pm2 save
```

## Caddy

```caddy
gate.builtbyecho.xyz {
  reverse_proxy 127.0.0.1:8787
}
```

Do not put upstream tool secrets in any remote store. Local JSON is the default secret backend. On macOS, recommend Keychain through `echo-gate secret add --backend macos-keychain`; on VPS, use environment variables or the local secret backend.

Production mode refuses to start unless `ECHO_GATE_ADMIN_TOKEN` is set. API keys created by Echo Gate are shown once; store them as secrets and rotate if exposed.
