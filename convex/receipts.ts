import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const record = mutation({
  args: {
    id: v.string(),
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
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("receipts", {
      publicId: args.id,
      requestId: args.requestId,
      toolId: args.toolId,
      toolSlug: args.toolSlug,
      keyId: args.keyId,
      keyPrefix: args.keyPrefix,
      status: args.status,
      startedAt: args.startedAt,
      durationMs: args.durationMs,
      inputHash: args.inputHash,
      outputHash: args.outputHash,
      httpStatus: args.httpStatus,
      priceMicros: args.priceMicros,
      error: args.error,
      signature: args.signature,
      signedAt: args.signedAt,
    });
    return args;
  },
});

export const list = query({
  args: { limit: v.number() },
  handler: async (ctx, args) => {
    const rows = await ctx.db.query("receipts").withIndex("by_started").order("desc").take(Math.min(args.limit, 200));
    return rows.map((row) => ({
      id: row.publicId,
      requestId: row.requestId,
      toolId: row.toolId,
      toolSlug: row.toolSlug,
      keyId: row.keyId,
      keyPrefix: row.keyPrefix,
      status: row.status,
      startedAt: row.startedAt,
      durationMs: row.durationMs,
      inputHash: row.inputHash,
      outputHash: row.outputHash,
      httpStatus: row.httpStatus,
      priceMicros: row.priceMicros,
      error: row.error,
      signature: row.signature,
      signedAt: row.signedAt,
    }));
  },
});

export const spendForKey = query({
  args: { keyId: v.string(), since: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const rows = await ctx.db.query("receipts").withIndex("by_key", (q) => q.eq("keyId", args.keyId)).collect();
    return rows
      .filter((row) => row.status === "ok" && inWindow(row, args.since))
      .reduce((total, row) => total + (row.priceMicros ?? 0), 0);
  },
});

export const spendForKeyTool = query({
  args: { keyId: v.string(), toolSlug: v.string(), since: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const rows = await ctx.db.query("receipts").withIndex("by_key", (q) => q.eq("keyId", args.keyId)).collect();
    return rows
      .filter((row) => row.toolSlug === args.toolSlug && row.status === "ok" && inWindow(row, args.since))
      .reduce((total, row) => total + (row.priceMicros ?? 0), 0);
  },
});

function inWindow(row: { startedAt: number }, since: number | undefined): boolean {
  return since === undefined || row.startedAt >= since;
}
