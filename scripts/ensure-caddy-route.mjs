#!/usr/bin/env node

import http from "node:http";

const adminUrl = new URL(process.env.CADDY_ADMIN_URL ?? "http://127.0.0.1:2019");
const host = process.env.ECHO_GATE_PUBLIC_HOST ?? "storage.builtbyecho.xyz";
const echoGatePort = process.env.ECHO_GATE_PORT ?? "8792";
const agentWormholePort = process.env.AGENT_WORMHOLE_PORT ?? "8791";
const vaultlinePort = process.env.VAULTLINE_PORT ?? "3002";
const intervalMs = Number(process.argv.includes("--once") ? 0 : process.env.ECHO_GATE_CADDY_INTERVAL_MS ?? "60000");

async function ensure() {
  const config = await requestJson("GET", "/config/");
  const routes = config.apps?.http?.servers?.srv0?.routes;
  if (!Array.isArray(routes)) {
    throw new Error("could not find Caddy srv0 routes");
  }

  const desired = buildRoutes();
  const filtered = routes.filter((route) => {
    return !(route.match || []).some((match) => (match.host || []).includes(host));
  });
  const nextRoutes = [...desired, ...filtered];
  const changed = JSON.stringify(routes) !== JSON.stringify(nextRoutes);

  if (!changed) {
    console.log(JSON.stringify({ ok: true, changed: false, host, at: new Date().toISOString() }));
    return;
  }

  config.apps.http.servers.srv0.routes = nextRoutes;
  await requestJson("POST", "/load", config);
  console.log(JSON.stringify({ ok: true, changed: true, host, at: new Date().toISOString() }));
}

async function requestJson(method, path, body) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const response = await new Promise((resolve, reject) => {
    const request = http.request({
      hostname: adminUrl.hostname,
      port: adminUrl.port || 80,
      path,
      method,
      headers: {
        accept: "application/json",
        ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({
        statusCode: res.statusCode ?? 0,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.on("error", reject);
    if (payload) request.write(payload);
    request.end();
  });

  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`caddy ${method} ${path} failed: ${response.statusCode} ${response.body}`);
  }
  if (!response.body) return null;
  return JSON.parse(response.body);
}

function buildRoutes() {
  return [
    {
      match: [{ host: [host], path: ["/echo-gate", "/echo-gate/*"] }],
      handle: [{ handler: "subroute", routes: [{ handle: [
        securityHeaders(),
        { handler: "rewrite", strip_path_prefix: "/echo-gate" },
        encode(),
        proxy(`127.0.0.1:${echoGatePort}`),
      ] }] }],
      terminal: true,
    },
    {
      match: [{ host: [host], path: ["/agent-wormhole", "/agent-wormhole/*"] }],
      handle: [{ handler: "subroute", routes: [{ handle: [
        securityHeaders(),
        encode(),
        proxy(`127.0.0.1:${agentWormholePort}`),
      ] }] }],
      terminal: true,
    },
    {
      match: [{ host: [host] }],
      handle: [{ handler: "subroute", routes: [{ handle: [
        securityHeaders(),
        encode(),
        proxy(`127.0.0.1:${vaultlinePort}`),
      ] }] }],
      terminal: true,
    },
  ];
}

function securityHeaders() {
  return {
    handler: "headers",
    response: {
      deferred: true,
      delete: ["Server"],
      set: {
        "Strict-Transport-Security": ["max-age=31536000; includeSubDomains; preload"],
        "X-Frame-Options": ["DENY"],
        "X-Content-Type-Options": ["nosniff"],
        "Referrer-Policy": ["strict-origin-when-cross-origin"],
        "Permissions-Policy": ["accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"],
      },
    },
  };
}

function encode() {
  return {
    handler: "encode",
    encodings: { zstd: {}, gzip: {} },
    prefer: ["zstd", "gzip"],
  };
}

function proxy(dial) {
  return {
    handler: "reverse_proxy",
    headers: {
      request: {
        set: {
          "X-Forwarded-Host": ["{http.request.host}"],
          "X-Forwarded-Proto": ["https"],
        },
      },
    },
    upstreams: [{ dial }],
  };
}

try {
  await ensure();
  if (intervalMs > 0) {
    setInterval(() => {
      ensure().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    }, intervalMs);
  }
} catch (error) {
  console.error(error);
  process.exit(1);
}
