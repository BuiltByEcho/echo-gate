import { Hono } from "hono";
import { nanoid } from "nanoid";
import { z } from "zod";
import { callTool } from "./adapters/index.js";
import { hmacSha256, sha256Json, stableStringify } from "./crypto.js";
import type { AccessMode, ApiKeyRecord, ApprovalRecord, ControlPlane, KeyToolPolicy, ReceiptRecord, ToolRecord } from "./types.js";

const registerToolSchema = z.object({
  slug: z.string().min(1).regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
  name: z.string().min(1),
  description: z.string().optional(),
  targetType: z.enum(["echo", "http"]),
  targetUrl: z.string().url().optional(),
  allowedMethods: z.array(z.string()).optional(),
  priceMicros: z.number().int().nonnegative().optional(),
  secretHeaders: z.record(z.string().min(1), z.string().min(1)).optional(),
  approvalRequired: z.boolean().optional(),
});

const createKeySchema = z.object({
  name: z.string().min(1),
  allowedTools: z.array(z.string()).optional(),
  policies: z.record(z.string().min(1), z.object({
    mode: z.enum(["deny", "auto", "approval", "limited"]),
    spendLimitMicros: z.number().int().nonnegative().optional(),
    spendWindowSeconds: z.number().int().positive().optional(),
  })).optional(),
  spendLimitMicros: z.number().int().nonnegative().optional(),
  spendWindowSeconds: z.number().int().positive().optional(),
});

const setPolicySchema = z.object({
  mode: z.enum(["deny", "auto", "approval", "limited"]),
  spendLimitMicros: z.number().int().nonnegative().optional(),
  spendWindowSeconds: z.number().int().positive().optional(),
});

const approvalDecisionSchema = z.object({
  decision: z.enum(["approved", "denied"]),
});

type CreateAppOptions = {
  control: ControlPlane;
  adminToken?: string;
  receiptSigningKey?: string;
};

export function createApp(options: CreateAppOptions): Hono {
  const app = new Hono();
  const executionLocks = new Map<string, Promise<void>>();

  app.get("/health", (c) => c.json({
    ok: true,
    service: "echo-gate",
    mode: options.adminToken ? "admin-protected" : "open-admin-dev",
  }));

  app.get("/tools", async (c) => {
    const tools = await options.control.listTools();
    return c.json({ tools: tools.map(sanitizeTool) });
  });

  app.post("/tools", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const body = await c.req.json().catch(() => null);
    const parsed = registerToolSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "invalid_tool", details: parsed.error.flatten() }, 400);
    }

    if (parsed.data.targetType === "http" && !parsed.data.targetUrl) {
      return c.json({ error: "http_tool_requires_target_url" }, 400);
    }

    const tool = await options.control.registerTool(parsed.data);
    return c.json({ tool: sanitizeTool(tool) }, 201);
  });

  app.post("/keys", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const body = await c.req.json().catch(() => null);
    const parsed = createKeySchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "invalid_key_request", details: parsed.error.flatten() }, 400);
    }
    const policyError = validatePolicies(parsed.data.policies);
    if (policyError) {
      return c.json({ error: "invalid_policy", reason: policyError }, 400);
    }

    const created = await options.control.createKey(parsed.data);
    return c.json({
      key: {
        ...created.record,
        hash: undefined,
      },
      secret: created.secret,
    }, 201);
  });

  app.get("/keys", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const keys = await options.control.listKeys();
    return c.json({
      keys: keys.map((key) => ({
        ...key,
        hash: undefined,
      })),
    });
  });

  app.delete("/keys/:id", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const key = await options.control.revokeKey(c.req.param("id"));
    if (!key) return c.json({ error: "key_not_found" }, 404);
    return c.json({
      key: {
        ...key,
        hash: undefined,
      },
    });
  });

  app.put("/keys/:id/policies/:slug", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const body = await c.req.json().catch(() => null);
    const parsed = setPolicySchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "invalid_policy", details: parsed.error.flatten() }, 400);
    }
    const policyError = validatePolicy(parsed.data);
    if (policyError) {
      return c.json({ error: "invalid_policy", reason: policyError }, 400);
    }

    const key = await options.control.setKeyPolicy(c.req.param("id"), c.req.param("slug"), parsed.data);
    if (!key) return c.json({ error: "key_not_found" }, 404);
    return c.json({ key: sanitizeKey(key) });
  });

  app.post("/tools/:slug/call", async (c) => {
    const slug = c.req.param("slug");
    const startedAt = Date.now();
    const requestId = c.req.header("x-request-id") ?? nanoid();
    const payload = await c.req.json().catch(() => null);

    if (payload === null) {
      return c.json({ error: "invalid_json" }, 400);
    }

    const tool = await options.control.getToolBySlug(slug);
    if (!tool || tool.status !== "active") {
      return c.json({ error: "tool_not_found" }, 404);
    }

    const auth = await options.control.authenticate(extractBearer(c.req.header("authorization")), slug);
    if (!auth.ok) {
      return c.json({ error: auth.reason }, 401);
    }

    const inputHash = sha256Json(payload);
    return withExecutionLock(executionLocks, auth.key.id, async () => {
      let receipt: ReceiptRecord;

      const approvalId = c.req.header("x-echo-gate-approval-id");
      const policy = await evaluateFirewallPolicy(options.control, tool, auth.key, payload, inputHash, requestId, approvalId);
      if (!policy.ok) {
        receipt = {
          id: nanoid(),
          requestId,
          toolId: tool.id,
          toolSlug: tool.slug,
          keyId: auth.key.id,
          keyPrefix: auth.key.prefix,
          status: "error",
          startedAt,
          durationMs: Date.now() - startedAt,
          inputHash,
          httpStatus: policy.status,
          priceMicros: tool.priceMicros,
          error: policy.reason,
        };
        receipt = signReceipt(receipt, options.receiptSigningKey);
        await options.control.recordReceipt(receipt);
        const responseBody = policy.approval
          ? { error: policy.reason, approval: policy.approval, receipt }
          : { error: policy.reason, receipt };
        return c.json(responseBody, policy.status as never);
      }

      try {
        const executed = await executeToolCall(options.control, tool, auth.key, payload, c.req.raw.headers, requestId, startedAt, inputHash, options.receiptSigningKey);
        receipt = executed.receipt;
        return c.json({ result: executed.result.body, receipt }, executed.result.status as never);
      } catch (error) {
        receipt = {
          id: nanoid(),
          requestId,
          toolId: tool.id,
          toolSlug: tool.slug,
          keyId: auth.key.id,
          keyPrefix: auth.key.prefix,
          status: "error",
          startedAt,
          durationMs: Date.now() - startedAt,
          inputHash,
          httpStatus: 502,
          priceMicros: tool.priceMicros,
          error: error instanceof Error ? error.message : "tool_call_failed",
        };
        receipt = signReceipt(receipt, options.receiptSigningKey);
        await options.control.recordReceipt(receipt);
        return c.json({ error: "tool_call_failed", receipt }, 502);
      }
    });
  });

  app.get("/receipts", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const receipts = await options.control.listReceipts(parseListLimit(c.req.query("limit")));
    return c.json({ receipts });
  });

  app.get("/approvals", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const status = c.req.query("status");
    const parsedStatus = status === "pending" || status === "approved" || status === "denied" || status === "consumed" || status === "executed" || status === "failed"
      ? status
      : undefined;
    const approvals = await options.control.listApprovals(parsedStatus, parseListLimit(c.req.query("limit")));
    return c.json({ approvals });
  });

  app.get("/approvals/:id/status", async (c) => {
    const approval = await options.control.getApproval(c.req.param("id"));
    if (!approval) return c.json({ error: "approval_not_found" }, 404);

    const auth = await options.control.authenticate(extractBearer(c.req.header("authorization")), approval.toolSlug);
    if (!auth.ok) return c.json({ error: auth.reason }, 401);
    if (auth.key.id !== approval.keyId) return c.json({ error: "approval_not_found" }, 404);

    return c.json({ approval: sanitizeApprovalForAgent(approval) });
  });

  app.get("/approvals/:id", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const approval = await options.control.getApproval(c.req.param("id"));
    if (!approval) return c.json({ error: "approval_not_found" }, 404);
    return c.json({ approval });
  });

  app.post("/approvals/:id/decision", async (c) => {
    const admin = requireAdmin(c.req.header("authorization"), options.adminToken);
    if (!admin.ok) return c.json({ error: admin.error }, 401);

    const body = await c.req.json().catch(() => null);
    const parsed = approvalDecisionSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "invalid_approval_decision", details: parsed.error.flatten() }, 400);
    }

    const approval = await options.control.decideApproval(c.req.param("id"), parsed.data.decision);
    if (!approval) return c.json({ error: "approval_not_found_or_not_pending" }, 404);
    if (parsed.data.decision === "denied") return c.json({ approval });

    const executed = await executeApprovedApproval(options.control, approval, options.receiptSigningKey);
    return c.json({ approval: executed.approval, result: executed.result, receipt: executed.receipt });
  });

  return app;
}

async function withExecutionLock<T>(locks: Map<string, Promise<void>>, key: string, action: () => Promise<T>): Promise<T> {
  const previous = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const ready = previous.catch(() => undefined);
  const current = ready.then(() => new Promise<void>((resolve) => {
    release = resolve;
  }));
  locks.set(key, current);
  await ready;
  try {
    return await action();
  } finally {
    release();
    if (locks.get(key) === current) {
      locks.delete(key);
    }
  }
}

function extractBearer(header: string | undefined): string {
  if (!header) return "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() ?? "";
}

function requireAdmin(header: string | undefined, adminToken: string | undefined): { ok: true } | { ok: false; error: string } {
  if (!adminToken) return { ok: true };
  const token = extractBearer(header);
  if (token !== adminToken) return { ok: false, error: "admin_required" };
  return { ok: true };
}

async function executeApprovedApproval(control: ControlPlane, approval: any, receiptSigningKey?: string): Promise<{ approval: unknown; result?: unknown; receipt?: ReceiptRecord }> {
  const tool = await control.getToolBySlug(approval.toolSlug);
  if (!tool || tool.status !== "active") {
    const failed = await control.completeApproval(approval.id, { status: "failed", error: "tool_not_found" });
    return { approval: failed ?? approval };
  }

  const key = await control.getKeyById(approval.keyId);
  if (!key || key.status !== "active") {
    const failed = await control.completeApproval(approval.id, { status: "failed", error: "key_not_active" });
    return { approval: failed ?? approval };
  }

  const accessPolicy = evaluateCurrentAccess(tool, key);
  if (!accessPolicy.ok) {
    const receipt = await recordBlockedReceipt(
      control,
      tool,
      key,
      approval.payload,
      approval.requestId,
      Date.now(),
      approval.inputHash,
      accessPolicy.reason,
      accessPolicy.status,
      receiptSigningKey,
    );
    const failed = await control.completeApproval(approval.id, {
      status: "failed",
      receiptId: receipt.id,
      error: accessPolicy.reason,
    });
    return { approval: failed ?? approval, receipt };
  }

  const spendPolicy = await evaluateSpendPolicy(control, tool, key);
  if (!spendPolicy.ok) {
    const receipt = await recordBlockedReceipt(
      control,
      tool,
      key,
      approval.payload,
      approval.requestId,
      Date.now(),
      approval.inputHash,
      spendPolicy.reason,
      spendPolicy.status,
      receiptSigningKey,
    );
    const failed = await control.completeApproval(approval.id, {
      status: "failed",
      receiptId: receipt.id,
      error: spendPolicy.reason,
    });
    return { approval: failed ?? approval, receipt };
  }

  try {
    const executed = await executeToolCall(control, tool, key, approval.payload, new Headers(), approval.requestId, Date.now(), approval.inputHash, receiptSigningKey);
    const completed = await control.completeApproval(approval.id, {
      status: executed.receipt.status === "ok" ? "executed" : "failed",
      result: executed.result.body,
      receiptId: executed.receipt.id,
      error: executed.receipt.error,
    });
    return { approval: completed ?? approval, result: executed.result.body, receipt: executed.receipt };
  } catch (error) {
    const failed = await control.completeApproval(approval.id, {
      status: "failed",
      error: error instanceof Error ? error.message : "tool_call_failed",
    });
    return { approval: failed ?? approval };
  }
}

async function recordBlockedReceipt(
  control: ControlPlane,
  tool: ToolRecord,
  key: ApiKeyRecord,
  payload: unknown,
  requestId: string,
  startedAt: number,
  inputHash: string,
  reason: string,
  httpStatus: number,
  receiptSigningKey?: string,
): Promise<ReceiptRecord> {
  const receipt = signReceipt({
    id: nanoid(),
    requestId,
    toolId: tool.id,
    toolSlug: tool.slug,
    keyId: key.id,
    keyPrefix: key.prefix,
    status: "error",
    startedAt,
    durationMs: Date.now() - startedAt,
    inputHash: inputHash || sha256Json(payload),
    httpStatus,
    priceMicros: tool.priceMicros,
    error: reason,
  }, receiptSigningKey);
  await control.recordReceipt(receipt);
  return receipt;
}

async function executeToolCall(
  control: ControlPlane,
  tool: ToolRecord,
  key: ApiKeyRecord,
  payload: unknown,
  headers: Headers,
  requestId: string,
  startedAt: number,
  inputHash = sha256Json(payload),
  receiptSigningKey?: string,
): Promise<{ result: { status: number; body: unknown }; receipt: ReceiptRecord }> {
  const result = await callTool({ tool, payload, headers });
  const receipt: ReceiptRecord = {
    id: nanoid(),
    requestId,
    toolId: tool.id,
    toolSlug: tool.slug,
    keyId: key.id,
    keyPrefix: key.prefix,
    status: result.status >= 400 ? "error" : "ok",
    startedAt,
    durationMs: Date.now() - startedAt,
    inputHash,
    outputHash: sha256Json(result.body),
    httpStatus: result.status,
    priceMicros: tool.priceMicros,
    error: result.status >= 400 ? "upstream_error" : undefined,
  };
  const signed = signReceipt(receipt, receiptSigningKey);
  await control.recordReceipt(signed);
  return { result, receipt: signed };
}

function signReceipt(receipt: ReceiptRecord, signingKey: string | undefined): ReceiptRecord {
  if (!signingKey) return receipt;
  const signedAt = Date.now();
  const { signature: _signature, ...unsignedReceipt } = receipt;
  const body = withoutUndefined({ ...unsignedReceipt, signedAt });
  return {
    ...receipt,
    signedAt,
    signature: hmacSha256(stableStringify(body), signingKey),
  };
}

function withoutUndefined<T extends Record<string, unknown>>(value: T): Partial<T> {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as Partial<T>;
}

async function evaluateFirewallPolicy(
  control: ControlPlane,
  tool: ToolRecord,
  key: ApiKeyRecord,
  payload: unknown,
  inputHash: string,
  requestId: string,
  approvalId?: string,
): Promise<
  { ok: true }
  | { ok: false; reason: "tool_not_allowed" | "approval_required" | "spend_limit_exceeded"; status: 402 | 403 | 202; approval?: unknown }
> {
  const policy = resolveKeyToolPolicy(key, tool);
  if (policy.mode === "deny") {
    return { ok: false, reason: "tool_not_allowed", status: 403 };
  }

  if (policy.mode === "approval") {
    if (approvalId) {
      const consumed = await control.consumeApproval(approvalId, key.id, tool.slug, inputHash);
      if (consumed) return evaluateSpendPolicy(control, tool, key);
    }
    const approval = await control.createApproval({
      requestId,
      toolId: tool.id,
      toolSlug: tool.slug,
      keyId: key.id,
      keyPrefix: key.prefix,
      inputHash,
      payload,
    });
    return { ok: false, reason: "approval_required", status: 202, approval };
  }

  const spendPolicy = await evaluateSpendPolicy(control, tool, key);
  if (!spendPolicy.ok) return spendPolicy;

  return { ok: true };
}

function evaluateCurrentAccess(
  tool: ToolRecord,
  key: ApiKeyRecord,
): { ok: true } | { ok: false; reason: "tool_not_allowed"; status: 403 } {
  const policy = resolveKeyToolPolicy(key, tool);
  if (policy.mode === "deny" || (key.allowedTools?.length && !key.allowedTools.includes(tool.slug))) {
    return { ok: false, reason: "tool_not_allowed", status: 403 };
  }
  return { ok: true };
}

async function evaluateSpendPolicy(
  control: ControlPlane,
  tool: ToolRecord,
  key: ApiKeyRecord,
): Promise<{ ok: true } | { ok: false; reason: "spend_limit_exceeded"; status: 402 }> {
  const policy = resolveKeyToolPolicy(key, tool);
  const price = tool.priceMicros ?? 0;
  if (key.spendLimitMicros !== undefined && price > 0) {
    const spent = await control.getSpendForKey(key.id, spendSince(key.spendWindowSeconds));
    if (spent + price > key.spendLimitMicros) {
      return { ok: false, reason: "spend_limit_exceeded", status: 402 };
    }
  }

  if (policy.mode === "limited" && policy.spendLimitMicros !== undefined && price > 0) {
    const spent = await control.getSpendForKeyTool(key.id, tool.slug, spendSince(policy.spendWindowSeconds));
    if (spent + price > policy.spendLimitMicros) {
      return { ok: false, reason: "spend_limit_exceeded", status: 402 };
    }
  }

  return { ok: true };
}

function validatePolicies(policies: Record<string, KeyToolPolicy> | undefined): string | undefined {
  if (!policies) return undefined;
  for (const [slug, policy] of Object.entries(policies)) {
    const error = validatePolicy(policy);
    if (error) return `${slug}: ${error}`;
  }
  return undefined;
}

function validatePolicy(policy: KeyToolPolicy): string | undefined {
  if (policy.mode === "limited" && policy.spendLimitMicros === undefined) {
    return "limited_policy_requires_spend_limit";
  }
  if (policy.mode !== "limited" && policy.spendWindowSeconds !== undefined && policy.spendLimitMicros === undefined) {
    return "spend_window_requires_spend_limit";
  }
  return undefined;
}

function parseListLimit(value: string | undefined): number {
  const parsed = Number(value ?? "50");
  if (!Number.isInteger(parsed)) return 50;
  return Math.max(1, Math.min(parsed, 200));
}

function resolveKeyToolPolicy(key: ApiKeyRecord, tool: ToolRecord): KeyToolPolicy {
  const policy = key.policies?.[tool.slug];
  if (policy) return policy;
  if (tool.approvalRequired) return { mode: "approval" };
  return { mode: "auto" };
}

function spendSince(windowSeconds: number | undefined): number | undefined {
  return windowSeconds === undefined ? undefined : Date.now() - windowSeconds * 1000;
}

function sanitizeKey(key: ApiKeyRecord): Omit<ApiKeyRecord, "hash"> & { hash?: undefined } {
  const { hash, ...safeKey } = key;
  return safeKey;
}

function sanitizeApprovalForAgent(approval: ApprovalRecord): Omit<ApprovalRecord, "payload"> & { payload?: undefined } {
  const { payload, ...safeApproval } = approval;
  return safeApproval;
}

function sanitizeTool<T extends { secretHeaders?: Record<string, string> }>(tool: T): Omit<T, "secretHeaders"> & { secretHeaderNames?: string[] } {
  const { secretHeaders, ...safeTool } = tool;
  return {
    ...safeTool,
    secretHeaderNames: secretHeaders ? Object.keys(secretHeaders) : undefined,
  };
}
