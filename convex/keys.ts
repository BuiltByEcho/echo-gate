import { nanoid } from "nanoid";
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const create = mutation({
  args: {
    name: v.string(),
    prefix: v.string(),
    hash: v.string(),
    allowedTools: v.optional(v.array(v.string())),
    policies: v.optional(v.record(v.string(), v.object({
      mode: v.union(v.literal("deny"), v.literal("auto"), v.literal("approval"), v.literal("limited")),
      spendLimitMicros: v.optional(v.number()),
      spendWindowSeconds: v.optional(v.number()),
    }))),
    spendLimitMicros: v.optional(v.number()),
    spendWindowSeconds: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const id = await ctx.db.insert("apiKeys", {
      publicId: nanoid(),
      name: args.name,
      prefix: args.prefix,
      hash: args.hash,
      status: "active",
      allowedTools: args.allowedTools,
      policies: args.policies,
      spendLimitMicros: args.spendLimitMicros,
      spendWindowSeconds: args.spendWindowSeconds,
      createdAt: Date.now(),
    });
    return toKeyRecord((await ctx.db.get(id))!);
  },
});

export const setPolicy = mutation({
  args: {
    id: v.string(),
    toolSlug: v.string(),
    policy: v.object({
      mode: v.union(v.literal("deny"), v.literal("auto"), v.literal("approval"), v.literal("limited")),
      spendLimitMicros: v.optional(v.number()),
      spendWindowSeconds: v.optional(v.number()),
    }),
  },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("apiKeys").filter((q) => q.eq(q.field("publicId"), args.id)).first();
    if (!row) return null;
    const policies = {
      ...(row.policies ?? {}),
      [args.toolSlug]: args.policy,
    };
    let allowedTools = row.allowedTools;
    if (args.policy.mode === "deny") {
      allowedTools = allowedTools?.filter((slug) => slug !== args.toolSlug);
    } else if (allowedTools?.length && !allowedTools.includes(args.toolSlug)) {
      allowedTools = [...allowedTools, args.toolSlug];
    }
    await ctx.db.patch(row._id, { policies, allowedTools });
    return toKeyRecord((await ctx.db.get(row._id))!);
  },
});

export const list = query({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query("apiKeys").collect();
    return rows.map(toKeyRecord).sort((a, b) => b.createdAt - a.createdAt);
  },
});

export const getActiveByHash = query({
  args: { hash: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("apiKeys").withIndex("by_hash", (q) => q.eq("hash", args.hash)).first();
    if (!row || row.status !== "active") return null;
    return toKeyRecord(row);
  },
});

export const getById = query({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("apiKeys").filter((q) => q.eq(q.field("publicId"), args.id)).first();
    return row ? toKeyRecord(row) : null;
  },
});

export const markUsed = mutation({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("apiKeys").filter((q) => q.eq(q.field("publicId"), args.id)).first();
    if (!row) return null;
    await ctx.db.patch(row._id, { lastUsedAt: Date.now() });
    return true;
  },
});

export const revoke = mutation({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("apiKeys").filter((q) => q.eq(q.field("publicId"), args.id)).first();
    if (!row) return null;
    await ctx.db.patch(row._id, { status: "revoked" });
    const updated = await ctx.db.get(row._id);
    return toKeyRecord(updated!);
  },
});

function toKeyRecord(row: any) {
  return {
    id: row.publicId,
    name: row.name,
    prefix: row.prefix,
    hash: row.hash,
    status: row.status,
    allowedTools: row.allowedTools,
    policies: row.policies,
    spendLimitMicros: row.spendLimitMicros,
    spendWindowSeconds: row.spendWindowSeconds,
    createdAt: row.createdAt,
    lastUsedAt: row.lastUsedAt,
  };
}
