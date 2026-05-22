import type { ToolRecord } from "../types.js";
import { readLocalSecretValue } from "../secrets/local.js";

export type ToolCallInput = {
  tool: ToolRecord;
  payload: unknown;
  headers: Headers;
};

export type ToolCallOutput = {
  status: number;
  body: unknown;
};

const DEFAULT_HTTP_TIMEOUT_MS = 30_000;

export async function callTool(input: ToolCallInput): Promise<ToolCallOutput> {
  switch (input.tool.targetType) {
    case "echo":
      return {
        status: 200,
        body: {
          ok: true,
          tool: input.tool.slug,
          payload: input.payload,
        },
      };
    case "http":
      return callHttpTool(input);
    default:
      return {
        status: 500,
        body: { error: "unsupported_target" },
      };
  }
}

async function callHttpTool(input: ToolCallInput): Promise<ToolCallOutput> {
  if (!input.tool.targetUrl) {
    return { status: 500, body: { error: "missing_target_url" } };
  }

  const method = resolveHttpMethod(input.tool.allowedMethods);
  const timeoutMs = httpTimeoutMs();
  const response = await fetch(input.tool.targetUrl, {
    method,
    headers: {
      "content-type": "application/json",
      "user-agent": "echo-gate/0.1",
      ...await resolveSecretHeaders(input.tool.secretHeaders),
    },
    body: JSON.stringify(input.payload),
    signal: AbortSignal.timeout(timeoutMs),
  });

  const contentType = response.headers.get("content-type") ?? "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  return {
    status: response.status,
    body,
  };
}

function resolveHttpMethod(allowedMethods: string[] | undefined): string {
  const method = allowedMethods?.[0]?.toUpperCase() ?? "POST";
  if (method !== "POST") {
    throw new Error(`unsupported_http_method:${method}`);
  }
  return method;
}

function httpTimeoutMs(): number {
  const parsed = Number(process.env.ECHO_GATE_HTTP_TIMEOUT_MS ?? DEFAULT_HTTP_TIMEOUT_MS);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_HTTP_TIMEOUT_MS;
  return Math.min(parsed, DEFAULT_HTTP_TIMEOUT_MS);
}

async function resolveSecretHeaders(secretHeaders: Record<string, string> | undefined): Promise<Record<string, string>> {
  if (!secretHeaders) return {};

  const headers: Record<string, string> = {};
  for (const [headerName, envName] of Object.entries(secretHeaders)) {
    const value = process.env[envName] ?? await readLocalSecretValue(envName);
    if (!value) {
      throw new Error(`missing_secret:${envName}`);
    }
    headers[headerName] = value;
  }
  return headers;
}
