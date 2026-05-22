import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { nanoid } from "nanoid";

const approvalStatus = v.union(v.literal("pending"), v.literal("approved"), v.literal("denied"), v.literal("consumed"), v.literal("executed"), v.literal("failed"));

export const create = mutation({
  args: {
    requestId: v.string(),
    toolId: v.string(),
    toolSlug: v.string(),
    keyId: v.string(),
    keyPrefix: v.string(),
    inputHash: v.string(),
    payload: v.any(),
  },
  handler: async (ctx, args) => {
    const id = await ctx.db.insert("approvals", {
      publicId: nanoid(),
      ...args,
      status: "pending",
      createdAt: Date.now(),
    });
    return toApprovalRecord((await ctx.db.get(id))!);
  },
});

export const get = query({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("approvals").filter((q) => q.eq(q.field("publicId"), args.id)).first();
    return row ? toApprovalRecord(row) : null;
  },
});

export const list = query({
  args: {
    status: v.optional(approvalStatus),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = Math.min(args.limit ?? 50, 200);
    const rows = args.status
      ? await ctx.db.query("approvals").withIndex("by_status", (q) => q.eq("status", args.status!)).order("desc").take(limit)
      : await ctx.db.query("approvals").withIndex("by_created").order("desc").take(limit);
    return rows.map(toApprovalRecord);
  },
});

export const complete = mutation({
  args: {
    id: v.string(),
    status: v.union(v.literal("executed"), v.literal("failed")),
    result: v.optional(v.any()),
    receiptId: v.optional(v.string()),
    error: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("approvals").filter((q) => q.eq(q.field("publicId"), args.id)).first();
    if (!row || (row.status !== "approved" && row.status !== "consumed")) return null;
    await ctx.db.patch(row._id, {
      status: args.status,
      executedAt: Date.now(),
      result: args.result,
      receiptId: args.receiptId,
      error: args.error,
    });
    return toApprovalRecord((await ctx.db.get(row._id))!);
  },
});

export const decide = mutation({
  args: {
    id: v.string(),
    decision: v.union(v.literal("approved"), v.literal("denied")),
  },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("approvals").filter((q) => q.eq(q.field("publicId"), args.id)).first();
    if (!row || row.status !== "pending") return null;
    await ctx.db.patch(row._id, {
      status: args.decision,
      decidedAt: Date.now(),
    });
    return toApprovalRecord((await ctx.db.get(row._id))!);
  },
});

export const consume = mutation({
  args: {
    id: v.string(),
    keyId: v.string(),
    toolSlug: v.string(),
    inputHash: v.string(),
  },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("approvals").filter((q) => q.eq(q.field("publicId"), args.id)).first();
    if (!row || row.status !== "approved") return null;
    if (row.keyId !== args.keyId || row.toolSlug !== args.toolSlug || row.inputHash !== args.inputHash) return null;
    await ctx.db.patch(row._id, {
      status: "consumed",
      consumedAt: Date.now(),
    });
    return toApprovalRecord((await ctx.db.get(row._id))!);
  },
});

function toApprovalRecord(row: any) {
  return {
    id: row.publicId,
    requestId: row.requestId,
    toolId: row.toolId,
    toolSlug: row.toolSlug,
    keyId: row.keyId,
    keyPrefix: row.keyPrefix,
    inputHash: row.inputHash,
    payload: row.payload,
    status: row.status,
    createdAt: row.createdAt,
    decidedAt: row.decidedAt,
    consumedAt: row.consumedAt,
    executedAt: row.executedAt,
    result: row.result,
    receiptId: row.receiptId,
    error: row.error,
  };
}
