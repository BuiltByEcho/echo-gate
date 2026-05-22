import { ConvexHttpClient } from "convex/browser";
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

export class ConvexControlPlane implements ControlPlane {
  private client: any;

  constructor(url: string) {
    this.client = new ConvexHttpClient(url);
  }

  async listTools(): Promise<ToolRecord[]> {
    return await this.client.query("tools:list", {});
  }

  async getToolBySlug(slug: string): Promise<ToolRecord | null> {
    return await this.client.query("tools:getBySlug", { slug });
  }

  async registerTool(input: RegisterToolInput): Promise<ToolRecord> {
    return await this.client.mutation("tools:register", input);
  }

  async listKeys(): Promise<CreatedKey["record"][]> {
    return await this.client.query("keys:list", {});
  }

  async getKeyById(id: string): Promise<CreatedKey["record"] | null> {
    return await this.client.query("keys:getById", { id });
  }

  async createKey(input: CreateKeyInput): Promise<CreatedKey> {
    const key = createApiKey();
    const record = await this.client.mutation("keys:create", {
      ...input,
      prefix: key.prefix,
      hash: key.hash,
    });
    return { record, secret: key.secret };
  }

  async setKeyPolicy(keyId: string, toolSlug: string, policy: KeyToolPolicy): Promise<CreatedKey["record"] | null> {
    return await this.client.mutation("keys:setPolicy", { id: keyId, toolSlug, policy });
  }

  async revokeKey(id: string): Promise<CreatedKey["record"] | null> {
    return await this.client.mutation("keys:revoke", { id });
  }

  async authenticate(rawKey: string, toolSlug: string): Promise<AuthResult> {
    if (!rawKey) return { ok: false, reason: "missing_key" };
    const record = await this.client.query("keys:getActiveByHash", {
      hash: sha256(rawKey),
    });
    if (!record) return { ok: false, reason: "invalid_key" };
    if (record.status !== "active") return { ok: false, reason: "revoked_key" };
    if (record.allowedTools?.length && !record.allowedTools.includes(toolSlug)) {
      return { ok: false, reason: "tool_not_allowed" };
    }
    await this.client.mutation("keys:markUsed", { id: record.id });
    return { ok: true, key: record };
  }

  async recordReceipt(receipt: ReceiptRecord): Promise<ReceiptRecord> {
    return await this.client.mutation("receipts:record", receipt);
  }

  async getSpendForKey(keyId: string, since?: number): Promise<number> {
    return await this.client.query("receipts:spendForKey", { keyId, since });
  }

  async getSpendForKeyTool(keyId: string, toolSlug: string, since?: number): Promise<number> {
    return await this.client.query("receipts:spendForKeyTool", { keyId, toolSlug, since });
  }

  async createApproval(input: Omit<ApprovalRecord, "id" | "status" | "createdAt">): Promise<ApprovalRecord> {
    return await this.client.mutation("approvals:create", input);
  }

  async listApprovals(status?: ApprovalStatus, limit = 50): Promise<ApprovalRecord[]> {
    return await this.client.query("approvals:list", { status, limit });
  }

  async getApproval(id: string): Promise<ApprovalRecord | null> {
    return await this.client.query("approvals:get", { id });
  }

  async decideApproval(id: string, decision: "approved" | "denied"): Promise<ApprovalRecord | null> {
    return await this.client.mutation("approvals:decide", { id, decision });
  }

  async consumeApproval(id: string, keyId: string, toolSlug: string, inputHash: string): Promise<ApprovalRecord | null> {
    return await this.client.mutation("approvals:consume", { id, keyId, toolSlug, inputHash });
  }

  async completeApproval(id: string, result: { status: "executed" | "failed"; result?: unknown; receiptId?: string; error?: string }): Promise<ApprovalRecord | null> {
    return await this.client.mutation("approvals:complete", { id, ...result });
  }

  async listReceipts(limit: number): Promise<ReceiptRecord[]> {
    return await this.client.query("receipts:list", { limit });
  }
}
