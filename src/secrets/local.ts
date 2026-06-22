import { execFile } from "node:child_process";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { promisify } from "node:util";

export type LocalSecretRecord = {
  name: string;
  createdAt: number;
  updatedAt: number;
  backend?: SecretBackend;
};

type FileSecretRecord = LocalSecretRecord & { value?: string };

type LocalSecretState = {
  secrets: FileSecretRecord[];
};

type SecretBackend = "macos-keychain" | "file";

const execFileAsync = promisify(execFile);
const KEYCHAIN_SERVICE = "com.builtbyecho.echo-gate.secret";
const KEYCHAIN_TIMEOUT_MS = 30_000;

export function localSecretPath(): string {
  return join(process.env.ECHO_GATE_STATE_DIR ?? join(homedir(), ".config", "echo-gate"), "secrets.json");
}

export async function readLocalSecretValue(name: string): Promise<string | undefined> {
  const normalized = normalizeSecretName(name);
  const state = await loadSecretState();
  const record = state.secrets.find((secret) => secret.name === normalized);
  if (record?.backend === "macos-keychain" || activeSecretBackend() === "macos-keychain") {
    const keychainValue = await readMacKeychainSecret(normalized);
    if (keychainValue !== undefined) return keychainValue;
  }
  return record?.value;
}

export async function listLocalSecrets(): Promise<LocalSecretRecord[]> {
  const state = await loadSecretState();
  return state.secrets
    .map(({ value: _value, ...safe }) => safe)
    .sort((a, b) => a.name.localeCompare(b.name));
}

export async function setLocalSecret(name: string, value: string): Promise<LocalSecretRecord> {
  const state = await loadSecretState();
  const normalized = normalizeSecretName(name);
  const now = Date.now();
  const existing = state.secrets.find((secret) => secret.name === normalized);
  const backend = activeSecretBackend();
  if (backend === "macos-keychain") {
    await setMacKeychainSecret(normalized, value);
  }
  const record: FileSecretRecord = {
    name: normalized,
    value: backend === "file" ? value : undefined,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    backend,
  };
  state.secrets = existing
    ? state.secrets.map((secret) => secret.name === normalized ? record : secret)
    : [...state.secrets, record];
  await saveSecretState(state);
  const { value: _value, ...safe } = record;
  return safe;
}

export async function deleteLocalSecret(name: string): Promise<boolean> {
  const state = await loadSecretState();
  const normalized = normalizeSecretName(name);
  const existing = state.secrets.find((secret) => secret.name === normalized);
  const removedFromKeychain = existing?.backend === "macos-keychain" || activeSecretBackend() === "macos-keychain"
    ? await deleteMacKeychainSecret(normalized)
    : false;
  const next = state.secrets.filter((secret) => secret.name !== normalized);
  if (next.length === state.secrets.length && !removedFromKeychain) return false;
  state.secrets = next;
  await saveSecretState(state);
  return true;
}

export function normalizeSecretName(name: string): string {
  const normalized = name.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(normalized)) {
    throw new Error("invalid_secret_name");
  }
  return normalized;
}

async function loadSecretState(): Promise<LocalSecretState> {
  try {
    const raw = JSON.parse(await readFile(localSecretPath(), "utf8"));
    return {
      secrets: Array.isArray(raw?.secrets) ? raw.secrets : [],
    };
  } catch (error: any) {
    if (error?.code !== "ENOENT") throw error;
    return { secrets: [] };
  }
}

async function saveSecretState(state: LocalSecretState): Promise<void> {
  const path = localSecretPath();
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  await rename(tmp, path);
  await chmod(path, 0o600).catch(() => undefined);
}

function activeSecretBackend(): SecretBackend {
  const configured = process.env.ECHO_GATE_SECRET_BACKEND;
  if (configured === "file" || configured === "macos-keychain") return configured;
  return "file";
}

async function setMacKeychainSecret(name: string, value: string): Promise<void> {
  await execFileAsync("/usr/bin/security", [
    "add-generic-password",
    "-a", name,
    "-s", KEYCHAIN_SERVICE,
    "-l", `Echo Gate ${name}`,
    "-j", "Echo Gate local tool secret",
    "-U",
    "-w", value,
  ], { timeout: KEYCHAIN_TIMEOUT_MS });
}

async function readMacKeychainSecret(name: string): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/security", [
      "find-generic-password",
      "-a", name,
      "-s", KEYCHAIN_SERVICE,
      "-w",
    ], { maxBuffer: 1024 * 1024, timeout: KEYCHAIN_TIMEOUT_MS });
    return stdout.endsWith("\n") ? stdout.slice(0, -1) : stdout;
  } catch (error: any) {
    if (error?.code === 44 || /could not be found/i.test(String(error?.stderr ?? error?.message ?? ""))) {
      return undefined;
    }
    throw error;
  }
}

async function deleteMacKeychainSecret(name: string): Promise<boolean> {
  try {
    await execFileAsync("/usr/bin/security", [
      "delete-generic-password",
      "-a", name,
      "-s", KEYCHAIN_SERVICE,
    ], { timeout: KEYCHAIN_TIMEOUT_MS });
    return true;
  } catch (error: any) {
    if (error?.code === 44 || /could not be found/i.test(String(error?.stderr ?? error?.message ?? ""))) {
      return false;
    }
    throw error;
  }
}
