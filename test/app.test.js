import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, stat } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { createApp } from "../dist/src/app.js";
import { LocalControlPlane } from "../dist/src/control/local.js";
import { MemoryControlPlane } from "../dist/src/control/memory.js";
import { hmacSha256, stableStringify } from "../dist/src/crypto.js";
import { localSecretPath, setLocalSecret } from "../dist/src/secrets/local.js";

const execFileAsync = promisify(execFile);

test("health reports ready", async () => {
  const app = createApp({ control: new MemoryControlPlane() });
  const response = await app.request("/health");
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.equal(body.service, "echo-gate");
});

test("tool call requires an API key", async () => {
  const app = createApp({ control: new MemoryControlPlane() });
  const response = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify({ hello: "world" }),
    headers: { "content-type": "application/json" },
  });
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "missing_key" });
});

test("tool call records a receipt", async () => {
  const control = new MemoryControlPlane();
  const key = await control.createKey({ name: "test", allowedTools: ["echo"] });
  const app = createApp({ control, receiptSigningKey: "receipt-secret" });

  const response = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify({ hello: "world" }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.result.ok, true);
  assert.equal(body.result.payload.hello, "world");
  assert.equal(body.receipt.status, "ok");
  assert.equal(body.receipt.toolSlug, "echo");
  assert.equal(typeof body.receipt.signedAt, "number");
  assert.equal(body.receipt.signature, expectedReceiptSignature(body.receipt, "receipt-secret"));

  const receipts = await control.listReceipts(10);
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0].outputHash, body.receipt.outputHash);
  assert.equal(receipts[0].signature, body.receipt.signature);
});

test("admin token protects registry writes", async () => {
  const app = createApp({ control: new MemoryControlPlane(), adminToken: "secret" });
  const response = await app.request("/tools", {
    method: "POST",
    body: JSON.stringify({ slug: "x", name: "X", targetType: "echo" }),
    headers: { "content-type": "application/json" },
  });
  assert.equal(response.status, 401);
});

test("admin token protects admin read and decision routes", async () => {
  const control = new MemoryControlPlane();
  const app = createApp({ control, adminToken: "secret" });
  const routes = [
    "/keys",
    "/receipts",
    "/approvals",
  ];

  for (const route of routes) {
    const response = await app.request(route);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "admin_required" });
  }

  const decision = await app.request("/approvals/missing/decision", {
    method: "POST",
    body: JSON.stringify({ decision: "approved" }),
    headers: { "content-type": "application/json" },
  });
  assert.equal(decision.status, 401);
});

test("tool registration validates slug and HTTP target URL", async () => {
  const app = createApp({ control: new MemoryControlPlane(), adminToken: "secret" });

  const invalidSlug = await app.request("/tools", {
    method: "POST",
    body: JSON.stringify({ slug: "Bad Slug", name: "Bad", targetType: "echo" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer secret",
    },
  });
  assert.equal(invalidSlug.status, 400);
  assert.equal((await invalidSlug.json()).error, "invalid_tool");

  const missingUrl = await app.request("/tools", {
    method: "POST",
    body: JSON.stringify({ slug: "http-no-url", name: "No URL", targetType: "http" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer secret",
    },
  });
  assert.equal(missingUrl.status, 400);
  assert.deepEqual(await missingUrl.json(), { error: "http_tool_requires_target_url" });
});

test("admin can list and revoke keys", async () => {
  const control = new MemoryControlPlane();
  const app = createApp({ control, adminToken: "secret" });

  const create = await app.request("/keys", {
    method: "POST",
    body: JSON.stringify({ name: "launch-smoke", allowedTools: ["echo"] }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer secret",
    },
  });
  assert.equal(create.status, 201);
  const created = await create.json();
  assert.ok(created.secret.startsWith("egk_"));

  const list = await app.request("/keys", {
    headers: { authorization: "Bearer secret" },
  });
  assert.equal(list.status, 200);
  const listed = await list.json();
  assert.equal(listed.keys.some((key) => key.id === created.key.id), true);
  assert.equal("hash" in listed.keys[0], false);

  const revoke = await app.request(`/keys/${created.key.id}`, {
    method: "DELETE",
    headers: { authorization: "Bearer secret" },
  });
  assert.equal(revoke.status, 200);
  const revoked = await revoke.json();
  assert.equal(revoked.key.status, "revoked");

  const call = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify({ should: "fail" }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${created.secret}`,
    },
  });
  assert.equal(call.status, 401);
  assert.deepEqual(await call.json(), { error: "revoked_key" });

  const revokeMissing = await app.request("/keys/missing", {
    method: "DELETE",
    headers: { authorization: "Bearer secret" },
  });
  assert.equal(revokeMissing.status, 404);
  assert.deepEqual(await revokeMissing.json(), { error: "key_not_found" });
});

test("set policy reports missing keys", async () => {
  const app = createApp({ control: new MemoryControlPlane(), adminToken: "secret" });
  const response = await app.request("/keys/missing/policies/echo", {
    method: "PUT",
    body: JSON.stringify({ mode: "approval" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer secret",
    },
  });
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: "key_not_found" });
});

test("http tools inject server-side secret headers without listing env refs", async () => {
  process.env.ECHO_GATE_TEST_SECRET = "Bearer server-side-secret";
  const server = http.createServer((request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({
      authorization: request.headers.authorization,
    }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const control = new MemoryControlPlane();
    const app = createApp({ control, adminToken: "secret" });

    const register = await app.request("/tools", {
      method: "POST",
      body: JSON.stringify({
        slug: "secret-api",
        name: "Secret API",
        targetType: "http",
        targetUrl: `http://127.0.0.1:${port}`,
        secretHeaders: { authorization: "ECHO_GATE_TEST_SECRET" },
      }),
      headers: {
        "content-type": "application/json",
        authorization: "Bearer secret",
      },
    });
    assert.equal(register.status, 201);
    const registered = await register.json();
    assert.equal("secretHeaders" in registered.tool, false);
    assert.deepEqual(registered.tool.secretHeaderNames, ["authorization"]);

    const key = await control.createKey({ name: "secret-test", allowedTools: ["secret-api"] });
    const call = await app.request("/tools/secret-api/call", {
      method: "POST",
      body: JSON.stringify({ ok: true }),
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${key.secret}`,
      },
    });
    assert.equal(call.status, 200);
    const body = await call.json();
    assert.equal(body.result.authorization, "Bearer server-side-secret");
  } finally {
    delete process.env.ECHO_GATE_TEST_SECRET;
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("http tools fail closed when a configured local secret is missing", async () => {
  const control = new MemoryControlPlane();
  const app = createApp({ control, adminToken: "secret" });
  const register = await app.request("/tools", {
    method: "POST",
    body: JSON.stringify({
      slug: "missing-secret-api",
      name: "Missing Secret API",
      targetType: "http",
      targetUrl: "http://127.0.0.1:1",
      secretHeaders: { authorization: "DOES_NOT_EXIST_SECRET" },
    }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer secret",
    },
  });
  assert.equal(register.status, 201);
  const key = await control.createKey({ name: "missing-secret-test", allowedTools: ["missing-secret-api"] });

  const call = await app.request("/tools/missing-secret-api/call", {
    method: "POST",
    body: JSON.stringify({ ok: true }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(call.status, 502);
  const body = await call.json();
  assert.equal(body.error, "tool_call_failed");
  assert.equal(body.receipt.error, "missing_secret:DOES_NOT_EXIST_SECRET");
});

test("tool calls validate JSON and tool existence before auth-sensitive execution", async () => {
  const control = new MemoryControlPlane();
  const key = await control.createKey({ name: "json-test", allowedTools: ["echo"] });
  const app = createApp({ control });

  const invalidJson = await app.request("/tools/echo/call", {
    method: "POST",
    body: "{",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(invalidJson.status, 400);
  assert.deepEqual(await invalidJson.json(), { error: "invalid_json" });

  const missingTool = await app.request("/tools/nope/call", {
    method: "POST",
    body: JSON.stringify({ ok: true }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(missingTool.status, 404);
  assert.deepEqual(await missingTool.json(), { error: "tool_not_found" });
});

test("firewall blocks approval-required tools and records receipt", async () => {
  const control = new MemoryControlPlane();
  await control.registerTool({
    slug: "dangerous",
    name: "Dangerous",
    targetType: "echo",
    approvalRequired: true,
  });
  const key = await control.createKey({ name: "approval-test", allowedTools: ["dangerous"] });
  const app = createApp({ control });

  const response = await app.request("/tools/dangerous/call", {
    method: "POST",
    body: JSON.stringify({ mutate: true }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });

  assert.equal(response.status, 202);
  const body = await response.json();
  assert.equal(body.error, "approval_required");
  assert.equal(body.approval.status, "pending");
  assert.equal(body.receipt.status, "error");
  assert.equal(body.receipt.error, "approval_required");
});

test("firewall enforces key spend limits before upstream execution", async () => {
  const control = new MemoryControlPlane();
  await control.registerTool({
    slug: "priced",
    name: "Priced",
    targetType: "echo",
    priceMicros: 10,
  });
  const key = await control.createKey({
    name: "spend-test",
    allowedTools: ["priced"],
    spendLimitMicros: 10,
  });
  const app = createApp({ control });

  const first = await app.request("/tools/priced/call", {
    method: "POST",
    body: JSON.stringify({ n: 1 }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(first.status, 200);

  const second = await app.request("/tools/priced/call", {
    method: "POST",
    body: JSON.stringify({ n: 2 }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(second.status, 402);
  const body = await second.json();
  assert.equal(body.error, "spend_limit_exceeded");
  assert.equal(body.receipt.error, "spend_limit_exceeded");
});

test("firewall applies rolling key spend windows", async () => {
  const control = new MemoryControlPlane();
  await control.registerTool({
    slug: "windowed",
    name: "Windowed",
    targetType: "echo",
    priceMicros: 10,
  });
  const key = await control.createKey({
    name: "window-test",
    allowedTools: ["windowed"],
    spendLimitMicros: 10,
    spendWindowSeconds: 60,
  });
  await control.recordReceipt({
    id: "old-receipt",
    requestId: "old-request",
    toolId: "old-tool",
    toolSlug: "windowed",
    keyId: key.record.id,
    keyPrefix: key.record.prefix,
    status: "ok",
    startedAt: Date.now() - 120_000,
    durationMs: 1,
    inputHash: "old",
    priceMicros: 10,
  });
  const app = createApp({ control });

  const first = await app.request("/tools/windowed/call", {
    method: "POST",
    body: JSON.stringify({ n: 1 }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(first.status, 200);

  const second = await app.request("/tools/windowed/call", {
    method: "POST",
    body: JSON.stringify({ n: 2 }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(second.status, 402);
  const body = await second.json();
  assert.equal(body.error, "spend_limit_exceeded");
});

test("spend limits are enforced across concurrent calls", async () => {
  let hitCount = 0;
  const server = http.createServer((_request, response) => {
    hitCount += 1;
    setTimeout(() => {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ ok: true }));
    }, 20);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const control = new MemoryControlPlane();
    await control.registerTool({
      slug: "race-priced",
      name: "Race Priced",
      targetType: "http",
      targetUrl: `http://127.0.0.1:${port}`,
      priceMicros: 10,
    });
    const key = await control.createKey({
      name: "race-test",
      allowedTools: ["race-priced"],
      spendLimitMicros: 10,
    });
    const app = createApp({ control });
    const request = () => app.request("/tools/race-priced/call", {
      method: "POST",
      body: JSON.stringify({ ok: true }),
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${key.secret}`,
      },
    });

    const responses = await Promise.all([request(), request()]);
    const statuses = responses.map((response) => response.status).sort();
    assert.deepEqual(statuses, [200, 402]);
    assert.equal(hitCount, 1);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("per-key policy deny blocks before execution", async () => {
  const control = new MemoryControlPlane();
  const key = await control.createKey({
    name: "deny-test",
    allowedTools: ["echo"],
    policies: { echo: { mode: "deny" } },
  });
  const app = createApp({ control });

  const response = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify({ should: "not-run" }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });

  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "tool_not_allowed" });
});

test("per-key limited policy enforces per-tool spend", async () => {
  const control = new MemoryControlPlane();
  await control.registerTool({
    slug: "cheap",
    name: "Cheap",
    targetType: "echo",
    priceMicros: 6,
  });
  const key = await control.createKey({
    name: "limited-test",
    allowedTools: ["cheap"],
    policies: { cheap: { mode: "limited", spendLimitMicros: 6 } },
  });
  const app = createApp({ control });

  const first = await app.request("/tools/cheap/call", {
    method: "POST",
    body: JSON.stringify({ n: 1 }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(first.status, 200);

  const second = await app.request("/tools/cheap/call", {
    method: "POST",
    body: JSON.stringify({ n: 2 }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(second.status, 402);
  const body = await second.json();
  assert.equal(body.error, "spend_limit_exceeded");
});

test("limited policies must declare an explicit spend limit", async () => {
  const control = new MemoryControlPlane();
  const app = createApp({ control, adminToken: "admin" });

  const create = await app.request("/keys", {
    method: "POST",
    body: JSON.stringify({
      name: "invalid-limited",
      allowedTools: ["echo"],
      policies: { echo: { mode: "limited" } },
    }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(create.status, 400);
  assert.equal((await create.json()).reason, "echo: limited_policy_requires_spend_limit");

  const key = await control.createKey({ name: "valid", allowedTools: ["echo"] });
  const update = await app.request(`/keys/${key.record.id}/policies/echo`, {
    method: "PUT",
    body: JSON.stringify({ mode: "limited" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(update.status, 400);
  assert.equal((await update.json()).reason, "limited_policy_requires_spend_limit");
});

test("cli rejects limited policies without spend caps before network calls", async () => {
  const create = await execCliExpectFailure(["bin/echo-gate.js", "create-key", "--name", "bad", "--policy", "echo=limited"]);
  assert.match(create, /limited mode requires/);

  const access = await execCliExpectFailure(["bin/echo-gate.js", "access", "set", "--key", "key_1", "--tool", "echo", "--mode", "limited"]);
  assert.match(access, /limited mode requires/);
});

test("cli prints structured API error bodies for approval workflows", async () => {
  const control = new MemoryControlPlane();
  const key = await control.createKey({
    name: "cli-approval",
    allowedTools: ["echo"],
    policies: { echo: { mode: "approval" } },
  });
  const app = createApp({ control });
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const body = await readRequestBody(request);
    const honoResponse = await app.request(url.pathname + url.search, {
      method: request.method,
      headers: request.headers,
      body: body.length ? body : undefined,
    });
    response.statusCode = honoResponse.status;
    honoResponse.headers.forEach((value, header) => response.setHeader(header, value));
    response.end(Buffer.from(await honoResponse.arrayBuffer()));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const output = await execCli(["bin/echo-gate.js", "call", "echo", "--json", "{\"cli\":true}"], {
      ECHO_GATE_URL: `http://127.0.0.1:${port}`,
      ECHO_GATE_KEY: key.secret,
    });
    const body = JSON.parse(output);
    assert.equal(body.error, "approval_required");
    assert.equal(body.approval.status, "pending");
    assert.equal(body.receipt.error, "approval_required");
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("list endpoints clamp invalid limits", async () => {
  const control = new MemoryControlPlane();
  const app = createApp({ control, adminToken: "admin" });
  await control.recordReceipt({
    id: "receipt-1",
    requestId: "request-1",
    toolId: "tool-1",
    toolSlug: "echo",
    keyId: "key-1",
    keyPrefix: "egk_test",
    status: "ok",
    startedAt: Date.now(),
    durationMs: 1,
    inputHash: "hash-1",
  });
  await control.createApproval({
    requestId: "request-2",
    toolId: "tool-1",
    toolSlug: "echo",
    keyId: "key-1",
    keyPrefix: "egk_test",
    inputHash: "hash-2",
    payload: { ok: true },
  });

  const receipts = await app.request("/receipts?limit=-1", {
    headers: { authorization: "Bearer admin" },
  });
  assert.equal(receipts.status, 200);
  assert.equal((await receipts.json()).receipts.length, 1);

  const approvals = await app.request("/approvals?limit=-1", {
    headers: { authorization: "Bearer admin" },
  });
  assert.equal(approvals.status, 200);
  assert.equal((await approvals.json()).approvals.length, 1);
});

test("limited policy supports rolling per-tool spend windows", async () => {
  const control = new MemoryControlPlane();
  await control.registerTool({
    slug: "windowed-tool",
    name: "Windowed Tool",
    targetType: "echo",
    priceMicros: 4,
  });
  const key = await control.createKey({
    name: "policy-window-test",
    allowedTools: ["windowed-tool"],
    policies: { "windowed-tool": { mode: "limited", spendLimitMicros: 4, spendWindowSeconds: 60 } },
  });
  await control.recordReceipt({
    id: "old-policy-receipt",
    requestId: "old-policy-request",
    toolId: "old-policy-tool",
    toolSlug: "windowed-tool",
    keyId: key.record.id,
    keyPrefix: key.record.prefix,
    status: "ok",
    startedAt: Date.now() - 120_000,
    durationMs: 1,
    inputHash: "old-policy",
    priceMicros: 4,
  });
  const app = createApp({ control });

  const first = await app.request("/tools/windowed-tool/call", {
    method: "POST",
    body: JSON.stringify({ n: 1 }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(first.status, 200);

  const second = await app.request("/tools/windowed-tool/call", {
    method: "POST",
    body: JSON.stringify({ n: 2 }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(second.status, 402);
});

test("approval policy stores payload and executes when approved", async () => {
  const control = new MemoryControlPlane();
  const key = await control.createKey({
    name: "approval-policy",
    allowedTools: ["echo"],
    policies: { echo: { mode: "approval" } },
  });
  const app = createApp({ control, adminToken: "admin" });
  const payload = { needs: "review" };

  const pending = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify(payload),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(pending.status, 202);
  const pendingBody = await pending.json();
  assert.equal(pendingBody.approval.status, "pending");

  const approve = await app.request(`/approvals/${pendingBody.approval.id}/decision`, {
    method: "POST",
    body: JSON.stringify({ decision: "approved" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(approve.status, 200);
  const approved = await approve.json();
  assert.equal(approved.approval.status, "executed");
  assert.equal(approved.result.payload.needs, "review");
  assert.equal(approved.receipt.status, "ok");

  const getApproval = await app.request(`/approvals/${pendingBody.approval.id}`, {
    headers: { authorization: "Bearer admin" },
  });
  assert.equal(getApproval.status, 200);
  const stored = await getApproval.json();
  assert.equal(stored.approval.status, "executed");
  assert.equal(stored.approval.result.payload.needs, "review");
  assert.equal(stored.approval.payload.needs, "review");

  const agentStatus = await app.request(`/approvals/${pendingBody.approval.id}/status`, {
    headers: { authorization: `Bearer ${key.secret}` },
  });
  assert.equal(agentStatus.status, 200);
  const statusBody = await agentStatus.json();
  assert.equal(statusBody.approval.status, "executed");
  assert.equal("payload" in statusBody.approval, false);
  assert.equal(statusBody.approval.result.payload.needs, "review");

  const otherKey = await control.createKey({ name: "other-agent", allowedTools: ["echo"] });
  const wrongAgentStatus = await app.request(`/approvals/${pendingBody.approval.id}/status`, {
    headers: { authorization: `Bearer ${otherKey.secret}` },
  });
  assert.equal(wrongAgentStatus.status, 404);
  assert.deepEqual(await wrongAgentStatus.json(), { error: "approval_not_found" });

  const executedList = await app.request("/approvals?status=executed&limit=10", {
    headers: { authorization: "Bearer admin" },
  });
  assert.equal(executedList.status, 200);
  const executedBody = await executedList.json();
  assert.equal(executedBody.approvals.some((approval) => approval.id === pendingBody.approval.id), true);

  const reuse = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify(payload),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
      "x-echo-gate-approval-id": pendingBody.approval.id,
    },
  });
  assert.equal(reuse.status, 202);
});

test("approval decisions validate payload and cannot be replayed", async () => {
  const control = new MemoryControlPlane();
  const key = await control.createKey({
    name: "decision-validation",
    allowedTools: ["echo"],
    policies: { echo: { mode: "approval" } },
  });
  const app = createApp({ control, adminToken: "admin" });

  const pending = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify({ needs: "one-decision" }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(pending.status, 202);
  const pendingBody = await pending.json();

  const invalid = await app.request(`/approvals/${pendingBody.approval.id}/decision`, {
    method: "POST",
    body: JSON.stringify({ decision: "maybe" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error, "invalid_approval_decision");

  const deny = await app.request(`/approvals/${pendingBody.approval.id}/decision`, {
    method: "POST",
    body: JSON.stringify({ decision: "denied" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(deny.status, 200);

  const replay = await app.request(`/approvals/${pendingBody.approval.id}/decision`, {
    method: "POST",
    body: JSON.stringify({ decision: "approved" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(replay.status, 404);
  assert.deepEqual(await replay.json(), { error: "approval_not_found_or_not_pending" });
});

test("approval deny does not execute stored payload", async () => {
  const control = new MemoryControlPlane();
  const key = await control.createKey({
    name: "deny-approval",
    allowedTools: ["echo"],
    policies: { echo: { mode: "approval" } },
  });
  const app = createApp({ control, adminToken: "admin" });

  const pending = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify({ no: "run" }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(pending.status, 202);
  const pendingBody = await pending.json();

  const deny = await app.request(`/approvals/${pendingBody.approval.id}/decision`, {
    method: "POST",
    body: JSON.stringify({ decision: "denied" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(deny.status, 200);
  const denied = await deny.json();
  assert.equal(denied.approval.status, "denied");
  assert.equal(denied.receipt, undefined);
});

test("approval execution rechecks current deny policy", async () => {
  const control = new MemoryControlPlane();
  const key = await control.createKey({
    name: "approval-then-deny",
    allowedTools: ["echo"],
    policies: { echo: { mode: "approval" } },
  });
  const app = createApp({ control, adminToken: "admin" });

  const pending = await app.request("/tools/echo/call", {
    method: "POST",
    body: JSON.stringify({ should: "stay-blocked" }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(pending.status, 202);
  const pendingBody = await pending.json();

  const denyPolicy = await app.request(`/keys/${key.record.id}/policies/echo`, {
    method: "PUT",
    body: JSON.stringify({ mode: "deny" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(denyPolicy.status, 200);

  const approve = await app.request(`/approvals/${pendingBody.approval.id}/decision`, {
    method: "POST",
    body: JSON.stringify({ decision: "approved" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(approve.status, 200);
  const approved = await approve.json();
  assert.equal(approved.approval.status, "failed");
  assert.equal(approved.approval.error, "tool_not_allowed");
  assert.equal(approved.receipt.error, "tool_not_allowed");
  assert.equal(approved.result, undefined);
});

test("approved payloads still respect spend limits at execution time", async () => {
  const control = new MemoryControlPlane();
  await control.registerTool({
    slug: "approved-priced",
    name: "Approved Priced",
    targetType: "echo",
    priceMicros: 10,
  });
  const key = await control.createKey({
    name: "approval-spend",
    allowedTools: ["approved-priced"],
    policies: { "approved-priced": { mode: "approval" } },
    spendLimitMicros: 10,
  });
  const app = createApp({ control, adminToken: "admin" });

  const pending = await app.request("/tools/approved-priced/call", {
    method: "POST",
    body: JSON.stringify({ expensive: true }),
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key.secret}`,
    },
  });
  assert.equal(pending.status, 202);
  const pendingBody = await pending.json();

  await control.recordReceipt({
    id: "already-spent",
    requestId: "spent-request",
    toolId: "priced-tool",
    toolSlug: "approved-priced",
    keyId: key.record.id,
    keyPrefix: key.record.prefix,
    status: "ok",
    startedAt: Date.now(),
    durationMs: 1,
    inputHash: "spent",
    priceMicros: 10,
  });

  const approve = await app.request(`/approvals/${pendingBody.approval.id}/decision`, {
    method: "POST",
    body: JSON.stringify({ decision: "approved" }),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer admin",
    },
  });
  assert.equal(approve.status, 200);
  const approved = await approve.json();
  assert.equal(approved.approval.status, "failed");
  assert.equal(approved.approval.error, "spend_limit_exceeded");
  assert.equal(approved.receipt.error, "spend_limit_exceeded");
  assert.equal(approved.result, undefined);
});

test("http tools reject unsupported configured methods before upstream execution", async () => {
  let hitCount = 0;
  const server = http.createServer((_request, response) => {
    hitCount += 1;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ ok: true }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const control = new MemoryControlPlane();
    await control.registerTool({
      slug: "get-only",
      name: "GET Only",
      targetType: "http",
      targetUrl: `http://127.0.0.1:${port}`,
      allowedMethods: ["GET"],
    });
    const key = await control.createKey({ name: "method-test", allowedTools: ["get-only"] });
    const app = createApp({ control });

    const call = await app.request("/tools/get-only/call", {
      method: "POST",
      body: JSON.stringify({ ok: true }),
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${key.secret}`,
      },
    });
    assert.equal(call.status, 502);
    const body = await call.json();
    assert.equal(body.receipt.error, "unsupported_http_method:GET");
    assert.equal(hitCount, 0);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("http tools time out stalled upstream requests", async () => {
  const previousTimeout = process.env.ECHO_GATE_HTTP_TIMEOUT_MS;
  process.env.ECHO_GATE_HTTP_TIMEOUT_MS = "10";
  const server = http.createServer((_request, _response) => {
    // Intentionally leave the response open so Echo Gate's upstream timeout fires.
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const control = new MemoryControlPlane();
    await control.registerTool({
      slug: "slow-api",
      name: "Slow API",
      targetType: "http",
      targetUrl: `http://127.0.0.1:${port}`,
    });
    const key = await control.createKey({ name: "timeout-test", allowedTools: ["slow-api"] });
    const app = createApp({ control });

    const call = await app.request("/tools/slow-api/call", {
      method: "POST",
      body: JSON.stringify({ ok: true }),
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${key.secret}`,
      },
    });
    assert.equal(call.status, 502);
    const body = await call.json();
    assert.match(body.receipt.error, /aborted|timeout|operation/i);
  } finally {
    if (previousTimeout === undefined) delete process.env.ECHO_GATE_HTTP_TIMEOUT_MS;
    else process.env.ECHO_GATE_HTTP_TIMEOUT_MS = previousTimeout;
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("local control plane persists tools keys policies and approvals", async () => {
  const dir = await mkdtemp(join(tmpdir(), "echo-gate-local-"));
  try {
    const first = new LocalControlPlane(dir);
    await first.registerTool({ slug: "local-tool", name: "Local Tool", targetType: "echo" });
    const key = await first.createKey({
      name: "local-agent",
      allowedTools: ["local-tool"],
      policies: { "local-tool": { mode: "approval" } },
    });
    await first.createApproval({
      requestId: "req_1",
      toolId: "tool_1",
      toolSlug: "local-tool",
      keyId: key.record.id,
      keyPrefix: key.record.prefix,
      inputHash: "hash_1",
      payload: { ok: true },
    });

    const second = new LocalControlPlane(dir);
    assert.equal((await second.getToolBySlug("local-tool")).name, "Local Tool");
    const keys = await second.listKeys();
    assert.equal(keys[0].policies["local-tool"].mode, "approval");
    const approvals = await second.listApprovals("pending");
    assert.equal(approvals.length, 1);
    assert.equal(approvals[0].toolSlug, "local-tool");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("local control plane serializes first load across concurrent reads", async () => {
  const dir = await mkdtemp(join(tmpdir(), "echo-gate-local-race-"));
  try {
    const control = new LocalControlPlane(dir);
    const [tools, keys, receipts, approvals] = await Promise.all([
      control.listTools(),
      control.listKeys(),
      control.listReceipts(5),
      control.listApprovals(),
    ]);
    assert.equal(tools.length, 1);
    assert.equal(tools[0].slug, "echo");
    assert.deepEqual(keys, []);
    assert.deepEqual(receipts, []);
    assert.deepEqual(approvals, []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("local control plane preserves concurrent writes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "echo-gate-local-writes-"));
  try {
    const control = new LocalControlPlane(dir);
    await Promise.all(Array.from({ length: 12 }, (_, index) => (
      control.createKey({ name: `writer-${index}`, allowedTools: ["echo"] })
    )));

    const reloaded = new LocalControlPlane(dir);
    const keys = await reloaded.listKeys();
    assert.equal(keys.length, 12);
    assert.equal(new Set(keys.map((key) => key.name)).size, 12);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("local state and file secrets are written with private permissions", async () => {
  const dir = await mkdtemp(join(tmpdir(), "echo-gate-local-perms-"));
  const previousStateDir = process.env.ECHO_GATE_STATE_DIR;
  const previousSecretBackend = process.env.ECHO_GATE_SECRET_BACKEND;
  process.env.ECHO_GATE_STATE_DIR = dir;
  process.env.ECHO_GATE_SECRET_BACKEND = "file";

  try {
    const control = new LocalControlPlane(dir);
    await control.createKey({ name: "private-key", allowedTools: ["echo"] });
    await setLocalSecret("PRIVATE_TOKEN", "secret-value");

    const stateMode = (await stat(join(dir, "state.json"))).mode & 0o777;
    const secretMode = (await stat(localSecretPath())).mode & 0o777;
    if (process.platform === "win32") {
      // Windows does not expose POSIX private-file modes consistently through stat().
      // The implementation still uses 0600/chmod best-effort; verify the files exist.
      assert.ok(stateMode > 0);
      assert.ok(secretMode > 0);
    } else {
      assert.equal(stateMode, 0o600);
      assert.equal(secretMode, 0o600);
    }
  } finally {
    if (previousStateDir === undefined) delete process.env.ECHO_GATE_STATE_DIR;
    else process.env.ECHO_GATE_STATE_DIR = previousStateDir;
    if (previousSecretBackend === undefined) delete process.env.ECHO_GATE_SECRET_BACKEND;
    else process.env.ECHO_GATE_SECRET_BACKEND = previousSecretBackend;
    await rm(dir, { recursive: true, force: true });
  }
});

test("http tools can resolve locally stored secrets without exposing values", async () => {
  const dir = await mkdtemp(join(tmpdir(), "echo-gate-secrets-"));
  const previousStateDir = process.env.ECHO_GATE_STATE_DIR;
  const previousSecretBackend = process.env.ECHO_GATE_SECRET_BACKEND;
  process.env.ECHO_GATE_STATE_DIR = dir;
  process.env.ECHO_GATE_SECRET_BACKEND = "file";
  const server = http.createServer((request, response) => {
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ authorization: request.headers.authorization }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  try {
    await setLocalSecret("LOCAL_API_TOKEN", "Bearer local-secret");
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const control = new MemoryControlPlane();
    const app = createApp({ control, adminToken: "secret" });
    const register = await app.request("/tools", {
      method: "POST",
      body: JSON.stringify({
        slug: "local-secret-api",
        name: "Local Secret API",
        targetType: "http",
        targetUrl: `http://127.0.0.1:${port}`,
        secretHeaders: { authorization: "LOCAL_API_TOKEN" },
      }),
      headers: {
        "content-type": "application/json",
        authorization: "Bearer secret",
      },
    });
    assert.equal(register.status, 201);
    const registered = await register.json();
    assert.equal("secretHeaders" in registered.tool, false);

    const key = await control.createKey({ name: "local-secret-test", allowedTools: ["local-secret-api"] });
    const call = await app.request("/tools/local-secret-api/call", {
      method: "POST",
      body: JSON.stringify({ ok: true }),
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${key.secret}`,
      },
    });
    assert.equal(call.status, 200);
    const body = await call.json();
    assert.equal(body.result.authorization, "Bearer local-secret");
  } finally {
    if (previousStateDir === undefined) delete process.env.ECHO_GATE_STATE_DIR;
    else process.env.ECHO_GATE_STATE_DIR = previousStateDir;
    if (previousSecretBackend === undefined) delete process.env.ECHO_GATE_SECRET_BACKEND;
    else process.env.ECHO_GATE_SECRET_BACKEND = previousSecretBackend;
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});

function expectedReceiptSignature(receipt, signingKey) {
  const { signature: _signature, ...unsignedReceipt } = receipt;
  return hmacSha256(stableStringify(withoutUndefined(unsignedReceipt)), signingKey);
}

async function execCliExpectFailure(args, env = {}) {
  try {
    await execFileAsync(process.execPath, args, {
      cwd: process.cwd(),
      env: { ...process.env, ECHO_GATE_URL: "http://127.0.0.1:9", ...env },
    });
    assert.fail("expected cli command to fail");
  } catch (error) {
    assert.notEqual(error.code, 0);
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
}

async function execCli(args, env = {}) {
  const { stdout } = await execFileAsync(process.execPath, args, {
    cwd: process.cwd(),
    env: { ...process.env, ...env },
  });
  return stdout;
}

async function readRequestBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function withoutUndefined(value) {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}
