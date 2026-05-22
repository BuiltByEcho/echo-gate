import { nanoid } from "nanoid";
import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

const toolFields = {
  slug: v.string(),
  name: v.string(),
  description: v.optional(v.string()),
  targetType: v.union(v.literal("echo"), v.literal("http")),
  targetUrl: v.optional(v.string()),
  allowedMethods: v.optional(v.array(v.string())),
  priceMicros: v.optional(v.number()),
  secretHeaders: v.optional(v.record(v.string(), v.string())),
  approvalRequired: v.optional(v.boolean()),
};

export const list = query({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query("tools").withIndex("by_status", (q) => q.eq("status", "active")).collect();
    return rows.map(toToolRecord).sort((a, b) => a.slug.localeCompare(b.slug));
  },
});

export const getBySlug = query({
  args: { slug: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db.query("tools").withIndex("by_slug", (q) => q.eq("slug", args.slug)).first();
    return row ? toToolRecord(row) : null;
  },
});

export const register = mutation({
  args: toolFields,
  handler: async (ctx, args) => {
    const now = Date.now();
    const existing = await ctx.db.query("tools").withIndex("by_slug", (q) => q.eq("slug", args.slug)).first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        name: args.name,
        description: args.description,
        status: "active",
        targetType: args.targetType,
        targetUrl: args.targetUrl,
        allowedMethods: args.allowedMethods ?? ["POST"],
        priceMicros: args.priceMicros,
        secretHeaders: args.secretHeaders,
        approvalRequired: args.approvalRequired,
        updatedAt: now,
      });
      const updated = await ctx.db.get(existing._id);
      return toToolRecord(updated!);
    }

    const id = await ctx.db.insert("tools", {
      publicId: nanoid(),
      slug: args.slug,
      name: args.name,
      description: args.description,
      status: "active",
      targetType: args.targetType,
      targetUrl: args.targetUrl,
      allowedMethods: args.allowedMethods ?? ["POST"],
      priceMicros: args.priceMicros,
      secretHeaders: args.secretHeaders,
      approvalRequired: args.approvalRequired,
      createdAt: now,
      updatedAt: now,
    });

    return toToolRecord((await ctx.db.get(id))!);
  },
});

function toToolRecord(row: any) {
  return {
    id: row.publicId,
    slug: row.slug,
    name: row.name,
    description: row.description,
    status: row.status,
    targetType: row.targetType,
    targetUrl: row.targetUrl,
    allowedMethods: row.allowedMethods,
    priceMicros: row.priceMicros,
    secretHeaders: row.secretHeaders,
    approvalRequired: row.approvalRequired,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}
