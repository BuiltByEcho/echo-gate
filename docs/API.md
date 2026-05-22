# Echo Gate API

## Health

```http
GET /health
```

## Tools

```http
GET /tools
POST /tools
```

`POST /tools` requires admin authorization when `ECHO_GATE_ADMIN_TOKEN` is set.

```json
{
  "slug": "echo",
  "name": "Echo Test Tool",
  "description": "Returns the payload.",
  "targetType": "echo"
}
```

HTTP-backed tools use:

```json
{
  "slug": "example",
  "name": "Example API",
  "targetType": "http",
  "targetUrl": "https://example.com/agent-call"
}
```

HTTP tools can inject server-side secrets by environment variable or local secret-store reference. The secret value is never returned by the API. Local JSON is the default secret backend. On macOS, users can choose the recommended safer Keychain backend, which stores secrets as generic password items under service `com.builtbyecho.echo-gate.secret`.

```json
{
  "slug": "github-issues",
  "name": "GitHub Issues",
  "targetType": "http",
  "targetUrl": "https://example.com/github/issues",
  "secretHeaders": {
    "authorization": "GITHUB_TOKEN"
  }
}
```

Tools can also be registered with `approvalRequired: true`. Calls to those tools create an approval request and return `202 approval_required` until the human approves.

Echo Gate currently executes HTTP tools with `POST` and a JSON body. Registered tools with other methods fail before upstream execution. The default upstream timeout is 30 seconds; for tests or local tuning, set `ECHO_GATE_HTTP_TIMEOUT_MS` to a lower positive value.

## Keys

```http
POST /keys
GET /keys
DELETE /keys/:id
Authorization: Bearer <admin-token>
```

```json
{
  "name": "demo",
  "allowedTools": ["echo"],
  "policies": {
    "echo": { "mode": "auto" }
  },
  "spendLimitMicros": 100000,
  "spendWindowSeconds": 86400
}
```

The response includes the API key secret once. `spendLimitMicros` is a whole-key cap. Add `spendWindowSeconds` to make that cap rolling instead of lifetime.

Key list and revoke responses never include key hashes or full secrets.

Set a per-key/per-tool policy:

```http
PUT /keys/:id/policies/:slug
Authorization: Bearer <admin-token>
```

```json
{
  "mode": "limited",
  "spendLimitMicros": 10000,
  "spendWindowSeconds": 3600
}
```

Policy modes:

- `deny` blocks calls before execution.
- `auto` executes immediately.
- `approval` creates a pending approval.
- `limited` executes until the policy spend cap is reached. `limited` must include `spendLimitMicros`; add `spendWindowSeconds` for rolling per-tool caps.

## Calls

```http
POST /tools/:slug/call
Authorization: Bearer egk_...
Content-Type: application/json
```

The gateway response includes the tool result and a receipt.

When `ECHO_GATE_RECEIPT_SIGNING_KEY` is set, receipts include `signedAt` and `signature`. The signature is HMAC-SHA256 over the stable JSON receipt body without the `signature` field.

Calls are denied before upstream execution when:

- the key is missing, invalid, revoked, or not allowed for the tool
- the tool requires approval
- the key would exceed its spend limit
- the key/tool would exceed a rolling window cap

Approval-gated calls return `202` with an approval record. Echo Gate stores the pending payload. When the human approves, Echo Gate executes the stored call and records the receipt.

Approvals fail closed if the key/tool is denied, revoked, or over budget by the time the human approves.

Agents can poll:

```http
GET /approvals/:id/status
Authorization: Bearer egk_...
```

For compatibility, agents can also retry the same call with `x-echo-gate-approval-id: <approval-id>` after approval.

## Approvals

```http
GET /approvals?status=pending&limit=50
GET /approvals/:id
POST /approvals/:id/decision
Authorization: Bearer <admin-token>
```

```json
{
  "decision": "approved"
}
```

Use `denied` to reject a pending approval.
Approval list limits are clamped to `1..200`.

## Receipts

```http
GET /receipts?limit=50
Authorization: Bearer <admin-token>
```

Receipts include request ids, tool ids, key prefix, status, input/output hashes, duration, and HTTP status.
List limits are clamped to `1..200`.
