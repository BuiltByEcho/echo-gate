import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { ConvexControlPlane } from "./control/convex.js";
import { LocalControlPlane } from "./control/local.js";
import { MemoryControlPlane } from "./control/memory.js";

const port = Number(process.env.ECHO_GATE_PORT ?? "8787");
const hostname = process.env.ECHO_GATE_BIND ?? "127.0.0.1";
const store = process.env.ECHO_GATE_STORE ?? (process.env.ECHO_GATE_MEMORY === "1" ? "memory" : "local");

if (process.env.NODE_ENV === "production" && !process.env.ECHO_GATE_ADMIN_TOKEN) {
  throw new Error("ECHO_GATE_ADMIN_TOKEN is required when NODE_ENV=production");
}

if (store === "convex" && !process.env.CONVEX_URL) {
  throw new Error("CONVEX_URL is required when ECHO_GATE_STORE=convex");
}

if (store === "convex" && process.env.ECHO_GATE_ENABLE_EXPERIMENTAL_CONVEX !== "1") {
  throw new Error("Convex mode is experimental. Set ECHO_GATE_ENABLE_EXPERIMENTAL_CONVEX=1 only for development.");
}

const control = store === "memory"
  ? new MemoryControlPlane()
  : store === "convex"
    ? new ConvexControlPlane(process.env.CONVEX_URL!)
    : new LocalControlPlane();

const app = createApp({
  control,
  adminToken: process.env.ECHO_GATE_ADMIN_TOKEN,
  receiptSigningKey: process.env.ECHO_GATE_RECEIPT_SIGNING_KEY,
});

serve({
  fetch: app.fetch,
  port,
  hostname,
}, (info) => {
  console.log(`echo-gate listening on http://${info.address}:${info.port} (${store})`);
});
