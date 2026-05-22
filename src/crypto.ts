import { createHash, createHmac, randomBytes } from "node:crypto";

export function sha256Json(value: unknown): string {
  return sha256(stableStringify(value));
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function hmacSha256(value: string, key: string): string {
  return createHmac("sha256", key).update(value).digest("base64url");
}

export function createApiKey(): { secret: string; prefix: string; hash: string } {
  const body = randomBytes(24).toString("base64url");
  const secret = `egk_${body}`;
  return {
    secret,
    prefix: secret.slice(0, 12),
    hash: sha256(secret),
  };
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(object[key])}`).join(",")}}`;
}
