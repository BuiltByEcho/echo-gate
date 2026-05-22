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

export class MemoryControlPlane implements ControlPlane {
  private tools = new Map<string, ToolRecord>();
  private keys = new Map<string, CreatedKey["record"]>();
  private receipts: ReceiptRecord[] = [];
  private approvals: ApprovalRecord[] = [];

  constructor() {
    void this.registerTool({
      slug: "echo",
      name: "Echo Test Tool",
      description: "Returns the input payload and proves the gateway path works.",
      targetType: "echo",
      allowedMethods: ["POST"],
    });
    void this.createKey({ name: "dev", allowedTools: ["echo"] });
  }

  async listTools(): Promise<ToolRecord[]> {
    return [...this.tools.values()].sort((a, b) => a.slug.localeCompare(b.slug));
  }

  async getToolBySlug(slug: string): Promise<ToolRecord | null> {
    return this.tools.get(slug) ?? null;
  }

  async registerTool(input: RegisterToolInput): Promise<ToolRecord> {
    const now = Date.now();
    const existing = this.tools.get(input.slug);
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
    this.tools.set(input.slug, record);
    return record;
  }

  async createKey(input: CreateKeyInput): Promise<CreatedKey> {
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
    this.keys.set(record.hash, record);
    return { record, secret: key.secret };
  }

  async setKeyPolicy(keyId: string, toolSlug: string, policy: KeyToolPolicy): Promise<CreatedKey["record"] | null> {
    for (const record of this.keys.values()) {
      if (record.id === keyId) {
        record.policies = {
          ...(record.policies ?? {}),
          [toolSlug]: policy,
        };
        if (policy.mode === "deny") {
          record.allowedTools = record.allowedTools?.filter((slug) => slug !== toolSlug);
        } else if (record.allowedTools?.length && !record.allowedTools.includes(toolSlug)) {
          record.allowedTools = [...record.allowedTools, toolSlug];
        }
        return record;
      }
    }
    return null;
  }

  async listKeys(): Promise<CreatedKey["record"][]> {
    return [...this.keys.values()].sort((a, b) => b.createdAt - a.createdAt);
  }

  async getKeyById(id: string): Promise<CreatedKey["record"] | null> {
    return [...this.keys.values()].find((record) => record.id === id) ?? null;
  }

  async revokeKey(id: string): Promise<CreatedKey["record"] | null> {
    for (const record of this.keys.values()) {
      if (record.id === id) {
        record.status = "revoked";
        return record;
      }
    }
    return null;
  }

  async authenticate(rawKey: string, toolSlug: string): Promise<AuthResult> {
    if (!rawKey) return { ok: false, reason: "missing_key" };
    const record = this.keys.get(sha256(rawKey));
    if (!record) return { ok: false, reason: "invalid_key" };
    if (record.status !== "active") return { ok: false, reason: "revoked_key" };
    const policy = record.policies?.[toolSlug];
    if (policy?.mode === "deny" || (record.allowedTools?.length && !record.allowedTools.includes(toolSlug))) {
      return { ok: false, reason: "tool_not_allowed" };
    }
    record.lastUsedAt = Date.now();
    return { ok: true, key: record };
  }

  async recordReceipt(receipt: ReceiptRecord): Promise<ReceiptRecord> {
    this.receipts.unshift(receipt);
    return receipt;
  }

  async getSpendForKey(keyId: string, since?: number): Promise<number> {
    return this.receipts
      .filter((receipt) => receipt.keyId === keyId && receipt.status === "ok" && inWindow(receipt, since))
      .reduce((total, receipt) => total + (receipt.priceMicros ?? 0), 0);
  }

  async getSpendForKeyTool(keyId: string, toolSlug: string, since?: number): Promise<number> {
    return this.receipts
      .filter((receipt) => receipt.keyId === keyId && receipt.toolSlug === toolSlug && receipt.status === "ok" && inWindow(receipt, since))
      .reduce((total, receipt) => total + (receipt.priceMicros ?? 0), 0);
  }

  async createApproval(input: Omit<ApprovalRecord, "id" | "status" | "createdAt">): Promise<ApprovalRecord> {
    const approval: ApprovalRecord = {
      ...input,
      id: nanoid(),
      status: "pending",
      createdAt: Date.now(),
    };
    this.approvals.unshift(approval);
    return approval;
  }

  async listApprovals(status?: ApprovalStatus, limit = 50): Promise<ApprovalRecord[]> {
    return this.approvals
      .filter((approval) => status ? approval.status === status : true)
      .slice(0, limit);
  }

  async getApproval(id: string): Promise<ApprovalRecord | null> {
    return this.approvals.find((item) => item.id === id) ?? null;
  }

  async decideApproval(id: string, decision: "approved" | "denied"): Promise<ApprovalRecord | null> {
    const approval = this.approvals.find((item) => item.id === id);
    if (!approval || approval.status !== "pending") return null;
    approval.status = decision;
    approval.decidedAt = Date.now();
    return approval;
  }

  async consumeApproval(id: string, keyId: string, toolSlug: string, inputHash: string): Promise<ApprovalRecord | null> {
    const approval = this.approvals.find((item) => item.id === id);
    if (!approval || approval.status !== "approved") return null;
    if (approval.keyId !== keyId || approval.toolSlug !== toolSlug || approval.inputHash !== inputHash) return null;
    approval.status = "consumed";
    approval.consumedAt = Date.now();
    return approval;
  }

  async completeApproval(id: string, result: { status: "executed" | "failed"; result?: unknown; receiptId?: string; error?: string }): Promise<ApprovalRecord | null> {
    const approval = this.approvals.find((item) => item.id === id);
    if (!approval || (approval.status !== "approved" && approval.status !== "consumed")) return null;
    approval.status = result.status;
    approval.executedAt = Date.now();
    approval.result = result.result;
    approval.receiptId = result.receiptId;
    approval.error = result.error;
    return approval;
  }

  async listReceipts(limit: number): Promise<ReceiptRecord[]> {
    return this.receipts.slice(0, limit);
  }
}

function inWindow(receipt: ReceiptRecord, since: number | undefined): boolean {
  return since === undefined || receipt.startedAt >= since;
}
