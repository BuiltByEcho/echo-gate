import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  tools: defineTable({
    publicId: v.string(),
    slug: v.string(),
    name: v.string(),
    description: v.optional(v.string()),
    status: v.union(v.literal("active"), v.literal("paused")),
    targetType: v.union(v.literal("echo"), v.literal("http")),
    targetUrl: v.optional(v.string()),
    allowedMethods: v.array(v.string()),
    priceMicros: v.optional(v.number()),
    secretHeaders: v.optional(v.record(v.string(), v.string())),
    approvalRequired: v.optional(v.boolean()),
    createdAt: v.number(),
    updatedAt: v.number(),
  })
    .index("by_slug", ["slug"])
    .index("by_status", ["status"]),

  apiKeys: defineTable({
    publicId: v.string(),
    name: v.string(),
    prefix: v.string(),
    hash: v.string(),
    status: v.union(v.literal("active"), v.literal("revoked")),
    allowedTools: v.optional(v.array(v.string())),
    policies: v.optional(v.record(v.string(), v.object({
      mode: v.union(v.literal("deny"), v.literal("auto"), v.literal("approval"), v.literal("limited")),
      spendLimitMicros: v.optional(v.number()),
      spendWindowSeconds: v.optional(v.number()),
    }))),
    spendLimitMicros: v.optional(v.number()),
    spendWindowSeconds: v.optional(v.number()),
    createdAt: v.number(),
    lastUsedAt: v.optional(v.number()),
  })
    .index("by_hash", ["hash"])
    .index("by_status", ["status"]),

  receipts: defineTable({
    publicId: v.string(),
    requestId: v.string(),
    toolId: v.string(),
    toolSlug: v.string(),
    keyId: v.optional(v.string()),
    keyPrefix: v.optional(v.string()),
    status: v.union(v.literal("ok"), v.literal("error")),
    startedAt: v.number(),
    durationMs: v.number(),
    inputHash: v.string(),
    outputHash: v.optional(v.string()),
    httpStatus: v.optional(v.number()),
    priceMicros: v.optional(v.number()),
    error: v.optional(v.string()),
    signature: v.optional(v.string()),
    signedAt: v.optional(v.number()),
  })
    .index("by_tool", ["toolSlug"])
    .index("by_key", ["keyId"])
    .index("by_started", ["startedAt"]),

  approvals: defineTable({
    publicId: v.string(),
    requestId: v.string(),
    toolId: v.string(),
    toolSlug: v.string(),
    keyId: v.string(),
    keyPrefix: v.string(),
    inputHash: v.string(),
    payload: v.any(),
    status: v.union(v.literal("pending"), v.literal("approved"), v.literal("denied"), v.literal("consumed"), v.literal("executed"), v.literal("failed")),
    createdAt: v.number(),
    decidedAt: v.optional(v.number()),
    consumedAt: v.optional(v.number()),
    executedAt: v.optional(v.number()),
    result: v.optional(v.any()),
    receiptId: v.optional(v.string()),
    error: v.optional(v.string()),
  })
    .index("by_status", ["status"])
    .index("by_key", ["keyId"])
    .index("by_created", ["createdAt"]),
});
