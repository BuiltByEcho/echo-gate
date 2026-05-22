export type ToolStatus = "active" | "paused";

export type ToolTargetType = "echo" | "http";

export type AccessMode = "deny" | "auto" | "approval" | "limited";

export type KeyToolPolicy = {
  mode: AccessMode;
  spendLimitMicros?: number;
  spendWindowSeconds?: number;
};

export type ToolRecord = {
  id: string;
  slug: string;
  name: string;
  description?: string;
  status: ToolStatus;
  targetType: ToolTargetType;
  targetUrl?: string;
  allowedMethods: string[];
  priceMicros?: number;
  secretHeaders?: Record<string, string>;
  approvalRequired?: boolean;
  createdAt: number;
  updatedAt: number;
};

export type ApiKeyRecord = {
  id: string;
  name: string;
  prefix: string;
  hash: string;
  status: "active" | "revoked";
  allowedTools?: string[];
  policies?: Record<string, KeyToolPolicy>;
  spendLimitMicros?: number;
  spendWindowSeconds?: number;
  createdAt: number;
  lastUsedAt?: number;
};

export type AuthResult = {
  ok: true;
  key: ApiKeyRecord;
} | {
  ok: false;
  reason: "missing_key" | "invalid_key" | "revoked_key" | "tool_not_allowed";
};

export type ReceiptRecord = {
  id: string;
  requestId: string;
  toolId: string;
  toolSlug: string;
  keyId?: string;
  keyPrefix?: string;
  status: "ok" | "error";
  startedAt: number;
  durationMs: number;
  inputHash: string;
  outputHash?: string;
  httpStatus?: number;
  priceMicros?: number;
  error?: string;
  signature?: string;
  signedAt?: number;
};

export type ApprovalStatus = "pending" | "approved" | "denied" | "consumed" | "executed" | "failed";

export type ApprovalRecord = {
  id: string;
  requestId: string;
  toolId: string;
  toolSlug: string;
  keyId: string;
  keyPrefix: string;
  inputHash: string;
  payload: unknown;
  status: ApprovalStatus;
  createdAt: number;
  decidedAt?: number;
  consumedAt?: number;
  executedAt?: number;
  result?: unknown;
  receiptId?: string;
  error?: string;
};

export type RegisterToolInput = {
  slug: string;
  name: string;
  description?: string;
  targetType: ToolTargetType;
  targetUrl?: string;
  allowedMethods?: string[];
  priceMicros?: number;
  secretHeaders?: Record<string, string>;
  approvalRequired?: boolean;
};

export type CreateKeyInput = {
  name: string;
  allowedTools?: string[];
  policies?: Record<string, KeyToolPolicy>;
  spendLimitMicros?: number;
  spendWindowSeconds?: number;
};

export type CreatedKey = {
  record: ApiKeyRecord;
  secret: string;
};

export interface ControlPlane {
  listTools(): Promise<ToolRecord[]>;
  getToolBySlug(slug: string): Promise<ToolRecord | null>;
  registerTool(input: RegisterToolInput): Promise<ToolRecord>;
  listKeys(): Promise<ApiKeyRecord[]>;
  getKeyById(id: string): Promise<ApiKeyRecord | null>;
  createKey(input: CreateKeyInput): Promise<CreatedKey>;
  setKeyPolicy(keyId: string, toolSlug: string, policy: KeyToolPolicy): Promise<ApiKeyRecord | null>;
  revokeKey(id: string): Promise<ApiKeyRecord | null>;
  authenticate(rawKey: string, toolSlug: string): Promise<AuthResult>;
  getSpendForKey(keyId: string, since?: number): Promise<number>;
  getSpendForKeyTool(keyId: string, toolSlug: string, since?: number): Promise<number>;
  createApproval(input: Omit<ApprovalRecord, "id" | "status" | "createdAt">): Promise<ApprovalRecord>;
  listApprovals(status?: ApprovalStatus, limit?: number): Promise<ApprovalRecord[]>;
  getApproval(id: string): Promise<ApprovalRecord | null>;
  decideApproval(id: string, decision: "approved" | "denied"): Promise<ApprovalRecord | null>;
  consumeApproval(id: string, keyId: string, toolSlug: string, inputHash: string): Promise<ApprovalRecord | null>;
  completeApproval(id: string, result: { status: "executed" | "failed"; result?: unknown; receiptId?: string; error?: string }): Promise<ApprovalRecord | null>;
  recordReceipt(receipt: ReceiptRecord): Promise<ReceiptRecord>;
  listReceipts(limit: number): Promise<ReceiptRecord[]>;
}
