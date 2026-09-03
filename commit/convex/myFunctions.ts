import { query, mutation, action } from "./_generated/server";
import { v } from "convex/values";

// Generic query — shows how Convex dashboard tests functions
export const listSessions = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("sessions").collect();
  },
});

// Generic mutation — create a session for YOUR app (not libloader)
export const createSession = mutation({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db.insert("sessions", {
      userId: args.userId,
      createdAt: Date.now(),
      status: "active",
    });
  },
});

// Generic action — example of an HTTP-style handler you own
// For real HTTP routes, use convex/http.ts with httpAction
export const hello = action({
  args: {},
  handler: async () => {
    return { message: "Hello from your own Convex backend — not a libloader clone" };
  },
});
