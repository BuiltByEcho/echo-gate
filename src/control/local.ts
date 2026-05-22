import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { nanoid } from "nanoid";
import { createApiKey, sha256 } from "../crypto.js";
import type {
  ApprovalRecord,
  ApprovalStatus,
  AuthResult,
  ControlPlane,
  CreateKeyInput,
  CreatedKey,
  KeyToolPolicy,
  ReceiptRecord,
  RegisterToolInput,
  ToolRecord,
} from "../types.js";

type LocalState = {
  tools: ToolRecord[];
  keys: CreatedKey["record"][];
  approvals: ApprovalRecord[];
  receipts: ReceiptRecord[];
};

const DEFAULT_STATE: LocalState = {
  tools: [],
  keys: [],
  approvals: [],
  receipts: [],
};

export class LocalControlPlane implements ControlPlane {
  private statePath: string;
  private state: LocalState | null = null;
  private loading: Promise<LocalState> | null = null;
  private saving: Promise<void> = Promise.resolve();

  constructor(stateDir = process.env.ECHO_GATE_STATE_DIR ?? join(homedir(), ".config", "echo-gate")) {
    this.statePath = join(stateDir, "state.json");
  }

  async listTools(): Promise<ToolRecord[]> {
    const state = await this.load();
    return [...state.tools].filter((tool) => tool.status === "active").sort((a, b) => a.slug.localeCompare(b.slug));
  }

  async getToolBySlug(slug: string): Promise<ToolRecord | null> {
    const state = await this.load();
    return state.tools.find((tool) => tool.slug === slug) ?? null;
  }

  async registerTool(input: RegisterToolInput): Promise<ToolRecord> {
    const state = await this.load();
    const now = Date.now();
    const existing = state.tools.find((tool) => tool.slug === input.slug);
    const record: ToolRecord = {
      id: existing?.id ?? nanoid(),
      slug: input.slug,
      name: input.name,
      description: input.description,
      status: "active",
      targetType: input.targetType,
      targetUrl: input.targetUrl,
      allowedMethods: input.allowedMethods ?? ["POST"],
      priceMicros: input.priceMicros,
      secretHeaders: input.secretHeaders,
      approvalRequired: input.approvalRequired,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    state.tools = existing
      ? state.tools.map((tool) => tool.slug === input.slug ? record : tool)
      : [...state.tools, record];
    await this.save();
    return record;
  }

  async listKeys(): Promise<CreatedKey["record"][]> {
    const state = await this.load();
    return [...state.keys].sort((a, b) => b.createdAt - a.createdAt);
  }

  async getKeyById(id: string): Promise<CreatedKey["record"] | null> {
    const state = await this.load();
    return state.keys.find((record) => record.id === id) ?? null;
  }

  async createKey(input: CreateKeyInput): Promise<CreatedKey> {
    const state = await this.load();
    const key = createApiKey();
    const record: CreatedKey["record"] = {
      id: nanoid(),
      name: input.name,
      prefix: key.prefix,
      hash: key.hash,
      status: "active",
      allowedTools: input.allowedTools,
      policies: input.policies,
      spendLimitMicros: input.spendLimitMicros,
      spendWindowSeconds: input.spendWindowSeconds,
      createdAt: Date.now(),
    };
    state.keys.push(record);
    await this.save();
    return { record, secret: key.secret };
  }

  async setKeyPolicy(keyId: string, toolSlug: string, policy: KeyToolPolicy): Promise<CreatedKey["record"] | null> {
    const state = await this.load();
    const key = state.keys.find((record) => record.id === keyId);
    if (!key) return null;
    key.policies = { ...(key.policies ?? {}), [toolSlug]: policy };
    if (policy.mode === "deny") {
      key.allowedTools = key.allowedTools?.filter((slug) => slug !== toolSlug);
    } else if (key.allowedTools?.length && !key.allowedTools.includes(toolSlug)) {
      key.allowedTools.push(toolSlug);
    }
    await this.save();
    return key;
  }

  async revokeKey(id: string): Promise<CreatedKey["record"] | null> {
    const state = await this.load();
    const key = state.keys.find((record) => record.id === id);
    if (!key) return null;
    key.status = "revoked";
    await this.save();
    return key;
  }

  async authenticate(rawKey: string, toolSlug: string): Promise<AuthResult> {
    const state = await this.load();
    if (!rawKey) return { ok: false, reason: "missing_key" };
    const record = state.keys.find((key) => key.hash === sha256(rawKey));
    if (!record) return { ok: false, reason: "invalid_key" };
    if (record.status !== "active") return { ok: false, reason: "revoked_key" };
    if (record.policies?.[toolSlug]?.mode === "deny" || (record.allowedTools?.length && !record.allowedTools.includes(toolSlug))) {
      return { ok: false, reason: "tool_not_allowed" };
    }
    record.lastUsedAt = Date.now();
    await this.save();
    return { ok: true, key: record };
  }

  async getSpendForKey(keyId: string, since?: number): Promise<number> {
    const state = await this.load();
    return state.receipts
      .filter((receipt) => receipt.keyId === keyId && receipt.status === "ok" && inWindow(receipt, since))
      .reduce((total, receipt) => total + (receipt.priceMicros ?? 0), 0);
  }

  async getSpendForKeyTool(keyId: string, toolSlug: string, since?: number): Promise<number> {
    const state = await this.load();
    return state.receipts
      .filter((receipt) => receipt.keyId === keyId && receipt.toolSlug === toolSlug && receipt.status === "ok" && inWindow(receipt, since))
      .reduce((total, receipt) => total + (receipt.priceMicros ?? 0), 0);
  }

  async createApproval(input: Omit<ApprovalRecord, "id" | "status" | "createdAt">): Promise<ApprovalRecord> {
    const state = await this.load();
    const approval: ApprovalRecord = {
      ...input,
      id: nanoid(),
      status: "pending",
      createdAt: Date.now(),
    };
    state.approvals.unshift(approval);
    await this.save();
    return approval;
  }

  async listApprovals(status?: ApprovalStatus, limit = 50): Promise<ApprovalRecord[]> {
    const state = await this.load();
    return state.approvals
      .filter((approval) => status ? approval.status === status : true)
      .slice(0, limit);
  }

  async getApproval(id: string): Promise<ApprovalRecord | null> {
    const state = await this.load();
    return state.approvals.find((item) => item.id === id) ?? null;
  }

  async decideApproval(id: string, decision: "approved" | "denied"): Promise<ApprovalRecord | null> {
    const state = await this.load();
    const approval = state.approvals.find((item) => item.id === id);
    if (!approval || approval.status !== "pending") return null;
    approval.status = decision;
    approval.decidedAt = Date.now();
    await this.save();
    return approval;
  }

  async consumeApproval(id: string, keyId: string, toolSlug: string, inputHash: string): Promise<ApprovalRecord | null> {
    const state = await this.load();
    const approval = state.approvals.find((item) => item.id === id);
    if (!approval || approval.status !== "approved") return null;
    if (approval.keyId !== keyId || approval.toolSlug !== toolSlug || approval.inputHash !== inputHash) return null;
    approval.status = "consumed";
    approval.consumedAt = Date.now();
    await this.save();
    return approval;
  }

  async completeApproval(id: string, result: { status: "executed" | "failed"; result?: unknown; receiptId?: string; error?: string }): Promise<ApprovalRecord | null> {
    const state = await this.load();
    const approval = state.approvals.find((item) => item.id === id);
    if (!approval || (approval.status !== "approved" && approval.status !== "consumed")) return null;
    approval.status = result.status;
    approval.executedAt = Date.now();
    approval.result = result.result;
    approval.receiptId = result.receiptId;
    approval.error = result.error;
    await this.save();
    return approval;
  }

  async recordReceipt(receipt: ReceiptRecord): Promise<ReceiptRecord> {
    const state = await this.load();
    state.receipts.unshift(receipt);
    await this.save();
    return receipt;
  }

  async listReceipts(limit: number): Promise<ReceiptRecord[]> {
    const state = await this.load();
    return state.receipts.slice(0, limit);
  }

  private async load(): Promise<LocalState> {
    if (this.state) return this.state;
    if (this.loading) return this.loading;
    this.loading = this.loadState();
    try {
      return await this.loading;
    } finally {
      this.loading = null;
    }
  }

  private async loadState(): Promise<LocalState> {
    await mkdir(dirname(this.statePath), { recursive: true, mode: 0o700 });
    try {
      this.state = normalizeState(JSON.parse(await readFile(this.statePath, "utf8")));
    } catch (error: any) {
      if (error?.code !== "ENOENT") throw error;
      this.state = structuredClone(DEFAULT_STATE);
      await this.seed();
      await this.save();
    }
    return this.state;
  }

  private async seed(): Promise<void> {
    const state = this.state!;
    const now = Date.now();
    state.tools.push({
      id: nanoid(),
      slug: "echo",
      name: "Echo Test Tool",
      description: "Returns the input payload and proves the gateway path works.",
      status: "active",
      targetType: "echo",
      allowedMethods: ["POST"],
      createdAt: now,
      updatedAt: now,
    });
  }

  private async save(): Promise<void> {
    this.saving = this.saving.catch(() => undefined).then(() => this.writeState());
    return this.saving;
  }

  private async writeState(): Promise<void> {
    const tmp = `${this.statePath}.${process.pid}.${Date.now()}.${nanoid()}.tmp`;
    await mkdir(dirname(this.statePath), { recursive: true, mode: 0o700 });
    await writeFile(tmp, `${JSON.stringify(this.state, null, 2)}\n`, { mode: 0o600 });
    await rename(tmp, this.statePath);
  }
}

function inWindow(receipt: ReceiptRecord, since: number | undefined): boolean {
  return since === undefined || receipt.startedAt >= since;
}

function normalizeState(value: any): LocalState {
  return {
    tools: Array.isArray(value?.tools) ? value.tools : [],
    keys: Array.isArray(value?.keys) ? value.keys : [],
    approvals: Array.isArray(value?.approvals) ? value.approvals : [],
    receipts: Array.isArray(value?.receipts) ? value.receipts : [],
  };
}
