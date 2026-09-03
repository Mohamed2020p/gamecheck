// Generic Convex schema — educational example
// Replace with your own tables. This is NOT the libloader schema.
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  // Example: store your own app's sessions, not lynx.cloud.accounts
  sessions: defineTable({
    userId: v.string(),
    createdAt: v.number(),
    status: v.string(), // e.g. "active"
  }),
});
