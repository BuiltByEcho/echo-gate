#!/usr/bin/env node
import { execFile } from "node:child_process";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { promisify } from "node:util";
import chalk from "chalk";
import { Command } from "commander";
import * as prompts from "@clack/prompts";
import {
  CURSOR_MARKER,
  ProcessTerminal,
  TUI,
  matchesKey,
  parseKey,
  truncateToWidth,
  visibleWidth,
} from "@mariozechner/pi-tui";

const program = new Command();
const baseUrl = () => process.env.ECHO_GATE_URL ?? "http://localhost:8787";
const adminToken = () => process.env.ECHO_GATE_ADMIN_TOKEN;
const apiKey = () => process.env.ECHO_GATE_KEY;
const execFileAsync = promisify(execFile);
const keychainService = "com.builtbyecho.echo-gate.secret";
const keychainTimeoutMs = 30_000;

program
  .name("echo-gate")
  .description("CLI for Echo Gate")
  .version("0.1.0");

program.command("health")
  .description("Check gateway health")
  .action(async () => {
    await printJson(await request("/health"));
  });

program.command("tools")
  .description("List registered tools")
  .action(async () => {
    await printJson(await request("/tools"));
  });

program.command("setup")
  .description("Guided setup for a protected tool and bot key")
  .action(async () => {
    await runSetup();
  });

program.command("add-tool")
  .requiredOption("--slug <slug>")
  .requiredOption("--name <name>")
  .option("--description <description>")
  .option("--type <type>", "echo or http", "echo")
  .option("--url <url>")
  .option("--secret-header <pair...>", "Header/env secret pair, e.g. Authorization=GITHUB_TOKEN")
  .option("--approval-required", "Require approval before this tool can run")
  .option("--price-micros <n>", "Price per successful call in micros")
  .description("Register or update a tool")
  .action(async (opts) => {
    await printJson(await request("/tools", {
      method: "POST",
      admin: true,
      body: {
        slug: opts.slug,
        name: opts.name,
        description: opts.description,
        targetType: opts.type,
        targetUrl: opts.url,
        secretHeaders: parsePairs(opts.secretHeader),
        approvalRequired: opts.approvalRequired,
        priceMicros: opts.priceMicros === undefined ? undefined : Number(opts.priceMicros),
      },
    }));
  });

program.command("create-key")
  .requiredOption("--name <name>")
  .option("--tool <slug...>", "Allowed tool slug; repeat or pass multiple")
  .option("--policy <pair...>", "Per-tool policy, e.g. github.createIssue=approval")
  .option("--spend-limit-micros <n>", "Maximum total successful-call spend for this key")
  .option("--spend-window-seconds <n>", "Optional rolling spend window for the key")
  .description("Create an API key")
  .action(async (opts) => {
    await printJson(await request("/keys", {
      method: "POST",
      admin: true,
      body: {
        name: opts.name,
        allowedTools: opts.tool,
        policies: parsePolicies(opts.policy),
        spendLimitMicros: opts.spendLimitMicros === undefined ? undefined : Number(opts.spendLimitMicros),
        spendWindowSeconds: opts.spendWindowSeconds === undefined ? undefined : Number(opts.spendWindowSeconds),
      },
    }));
  });

const secret = program.command("secret").description("Manage local secrets");

secret.command("add")
  .argument("<name>")
  .option("--value <value>", "Secret value; omit to paste interactively")
  .option("--backend <backend>", "file or macos-keychain; defaults to file")
  .description("Store a local secret value")
  .action(async (name, opts) => {
    const value = opts.value ?? await promptSecretValue(name);
    await printJson({ secret: await setCliSecret(name, value, opts.backend) });
  });

secret.command("backend")
  .description("Show the active secret backend")
  .action(async () => {
    await printJson({
      backend: activeSecretBackend(),
      recommended: process.platform === "darwin" ? "macos-keychain" : "file",
      note: process.platform === "darwin"
        ? "macOS Keychain is safer because the raw value is held by the OS vault instead of local JSON."
        : "Local JSON is the default backend until this platform has a native vault integration.",
    });
  });

secret.command("list")
  .description("List local secret names")
  .action(async () => {
    await printJson({ secrets: await listCliSecrets() });
  });

secret.command("remove")
  .argument("<name>")
  .description("Remove a local secret")
  .action(async (name) => {
    await printJson({ removed: await deleteCliSecret(name) });
  });

secret.command("test")
  .argument("<name>")
  .description("Check whether a local secret exists")
  .action(async (name) => {
    const value = await getCliSecret(name);
    await printJson({ name, exists: value !== undefined });
  });

const access = program.command("access").description("Manage per-bot tool access policies");

access.command("set")
  .requiredOption("--key <id>", "Bot key id")
  .requiredOption("--tool <slug>", "Tool slug")
  .requiredOption("--mode <mode>", "deny, auto, approval, or limited")
  .option("--spend-limit-micros <n>", "Per-tool spend cap for limited mode")
  .option("--spend-window-seconds <n>", "Optional rolling spend window for this tool policy")
  .description("Set access mode for one bot key and tool")
  .action(async (opts) => {
    const policy = {
      mode: opts.mode,
      spendLimitMicros: opts.spendLimitMicros === undefined ? undefined : Number(opts.spendLimitMicros),
      spendWindowSeconds: opts.spendWindowSeconds === undefined ? undefined : Number(opts.spendWindowSeconds),
    };
    validateCliPolicy(policy);
    await printJson(await request(`/keys/${encodeURIComponent(opts.key)}/policies/${encodeURIComponent(opts.tool)}`, {
      method: "PUT",
      admin: true,
      body: policy,
    }));
  });

access.command("list")
  .description("List keys with their policies")
  .action(async () => {
    const keys = await request("/keys", { admin: true });
    await printJson({ keys: keys.keys.map((key) => ({ id: key.id, name: key.name, prefix: key.prefix, policies: key.policies ?? {} })) });
  });

program.command("keys")
  .description("List API keys")
  .action(async () => {
    await printJson(await request("/keys", {
      admin: true,
    }));
  });

program.command("revoke-key")
  .argument("<id>")
  .description("Revoke an API key")
  .action(async (id) => {
    await printJson(await request(`/keys/${encodeURIComponent(id)}`, {
      method: "DELETE",
      admin: true,
    }));
  });

program.command("call")
  .argument("<slug>")
  .option("--json <json>", "JSON payload", "{}")
  .description("Call a registered tool")
  .action(async (slug, opts) => {
    const payload = JSON.parse(opts.json);
    await printJson(await request(`/tools/${encodeURIComponent(slug)}/call`, {
      method: "POST",
      key: true,
      body: payload,
    }));
  });

program.command("receipts")
  .option("--limit <n>", "Receipt count", "25")
  .description("List recent receipts")
  .action(async (opts) => {
    await printJson(await request(`/receipts?limit=${encodeURIComponent(opts.limit)}`, {
      admin: true,
    }));
  });

program.command("approvals")
  .option("--status <status>", "pending, approved, denied, consumed, executed, or failed", "pending")
  .option("--limit <n>", "Approval count", "25")
  .description("List approvals")
  .action(async (opts) => {
    await printJson(await request(`/approvals?status=${encodeURIComponent(opts.status)}&limit=${encodeURIComponent(opts.limit)}`, {
      admin: true,
    }));
  });

program.command("approval-status")
  .argument("<id>")
  .description("Check an approval status using the bot key")
  .action(async (id) => {
    await printJson(await request(`/approvals/${encodeURIComponent(id)}/status`, {
      key: true,
    }));
  });

program.command("approve")
  .argument("<id>")
  .description("Approve a pending tool call")
  .action(async (id) => {
    await printJson(await request(`/approvals/${encodeURIComponent(id)}/decision`, {
      method: "POST",
      admin: true,
      body: { decision: "approved" },
    }));
  });

program.command("deny")
  .argument("<id>")
  .description("Deny a pending tool call")
  .action(async (id) => {
    await printJson(await request(`/approvals/${encodeURIComponent(id)}/decision`, {
      method: "POST",
      admin: true,
      body: { decision: "denied" },
    }));
  });

async function request(path, options = {}) {
  const headers = { accept: "application/json" };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.admin && adminToken()) headers.authorization = `Bearer ${adminToken()}`;
  if (options.key && apiKey()) headers.authorization = `Bearer ${apiKey()}`;

  const response = await fetch(`${baseUrl()}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error ?? `HTTP ${response.status}`);
    error.data = data;
    throw error;
  }
  return data;
}

async function printJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

async function runSetup() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.error("echo-gate setup requires an interactive terminal.");
    process.exit(1);
  }

  prompts.intro(chalk.bold("Echo Gate setup"));
  prompts.note([
    "This flow registers a protected capability and creates a scoped bot key.",
    "Secret values stay local. Echo Gate stores the env var reference, not the raw secret.",
  ].join("\n"), "Local-first firewall");

  const target = await promptSelect({
    message: "What do you want to protect?",
    options: [
      { value: "http", label: "HTTP API tool", hint: "wrap an upstream API behind Echo Gate" },
      { value: "echo", label: "Echo smoke tool", hint: "local test capability" },
    ],
  });

  const slug = await promptText({
    message: "Tool slug",
    placeholder: target === "http" ? "github.createIssue" : "echo",
    defaultValue: target === "http" ? undefined : "echo",
  });

  const name = await promptText({
    message: "Tool display name",
    placeholder: target === "http" ? "GitHub Create Issue" : "Echo",
    defaultValue: target === "http" ? undefined : "Echo",
  });

  let targetUrl;
  let secretHeaders;
  if (target === "http") {
    targetUrl = await promptText({
      message: "Upstream URL",
      placeholder: "https://api.github.com/repos/owner/repo/issues",
    });

    const headerName = await promptText({
      message: "Secret header name",
      placeholder: "Authorization",
      defaultValue: "Authorization",
    });
    const envName = await promptText({
      message: "Local env var that holds the secret",
      placeholder: "GITHUB_TOKEN",
    });
    secretHeaders = { [headerName]: envName };
  }

  const accessMode = await promptSelect({
    message: "Default access mode",
    options: [
      { value: "auto", label: "Auto", hint: "bot can call without asking" },
      { value: "approval", label: "Approval", hint: "block until human approval is wired" },
      { value: "limited", label: "Limited", hint: "allow with spend cap" },
    ],
  });

  const botName = await promptText({
    message: "Bot/key name",
    placeholder: "research-agent",
  });

  let spendLimitMicros;
  if (accessMode === "limited") {
    const dollars = await promptText({
      message: "Spend cap in dollars",
      placeholder: "5.00",
      defaultValue: "5.00",
    });
    spendLimitMicros = Math.round(Number(dollars) * 1_000_000);
    if (!Number.isFinite(spendLimitMicros) || spendLimitMicros < 0) {
      prompts.cancel("Invalid spend cap.");
      process.exit(1);
    }
  }

  const shouldApply = await promptConfirm({
    message: `Apply this to ${baseUrl()} now?`,
    initialValue: true,
  });

  if (!shouldApply) {
    prompts.note([
      `echo-gate add-tool --slug ${slug} --name "${name}" --type ${target}${targetUrl ? ` --url ${targetUrl}` : ""}`,
      `echo-gate create-key --name ${botName} --tool ${slug}${spendLimitMicros ? ` --spend-limit-micros ${spendLimitMicros}` : ""}`,
    ].join("\n"), "Commands");
    prompts.outro("Setup draft ready.");
    return;
  }

  const spinner = prompts.spinner();
  spinner.start("Registering tool");
  await request("/tools", {
    method: "POST",
    admin: true,
    body: {
      slug,
      name,
      targetType: target,
      targetUrl,
      secretHeaders,
      approvalRequired: accessMode === "approval",
    },
  });
  spinner.message("Creating bot key");
  const key = await request("/keys", {
    method: "POST",
    admin: true,
    body: {
      name: botName,
      allowedTools: [slug],
      policies: { [slug]: { mode: accessMode, spendLimitMicros } },
      spendLimitMicros,
    },
  });
  spinner.stop("Protected capability ready");

  prompts.note([
    `Tool: ${slug}`,
    `Bot key name: ${botName}`,
    `Access: ${accessMode}`,
    `Key: ${key.secret}`,
  ].join("\n"), "Created");
  prompts.outro("Store the key somewhere safe. Echo Gate will not show it again.");
}

function parsePairs(values) {
  if (!values?.length) return undefined;
  const pairs = {};
  for (const value of values) {
    const separator = value.indexOf("=");
    if (separator === -1) {
      throw new Error(`Invalid --secret-header value: ${value}`);
    }
    const key = value.slice(0, separator).trim();
    const env = value.slice(separator + 1).trim();
    if (!key || !env) {
      throw new Error(`Invalid --secret-header value: ${value}`);
    }
    pairs[key] = env;
  }
  return pairs;
}

function parsePolicies(values) {
  if (!values?.length) return undefined;
  const policies = {};
  for (const value of values) {
    const separator = value.indexOf("=");
    if (separator === -1) throw new Error(`Invalid --policy value: ${value}`);
    const slug = value.slice(0, separator).trim();
    const policy = parsePolicyValue(value.slice(separator + 1).trim());
    const mode = policy.mode;
    if (!slug || !["deny", "auto", "approval", "limited"].includes(mode)) {
      throw new Error(`Invalid --policy value: ${value}`);
    }
    policies[slug] = policy;
  }
  return policies;
}

function parsePolicyValue(value) {
  const [mode, ...parts] = value.split(":").map((part) => part.trim()).filter(Boolean);
  const policy = { mode };
  for (const part of parts) {
    const [key, raw] = part.split("=");
    if (key === "spend" || key === "spendLimitMicros") {
      policy.spendLimitMicros = Number(raw);
    } else if (key === "window" || key === "spendWindowSeconds") {
      policy.spendWindowSeconds = Number(raw);
    } else {
      throw new Error(`Invalid policy option: ${part}`);
    }
  }
  validateCliPolicy(policy);
  return policy;
}

function validateCliPolicy(policy) {
  if (!["deny", "auto", "approval", "limited"].includes(policy.mode)) {
    throw new Error(`Invalid policy mode: ${policy.mode}`);
  }
  if (policy.spendLimitMicros !== undefined && (!Number.isInteger(policy.spendLimitMicros) || policy.spendLimitMicros < 0)) {
    throw new Error("spendLimitMicros must be a non-negative integer");
  }
  if (policy.spendWindowSeconds !== undefined && (!Number.isInteger(policy.spendWindowSeconds) || policy.spendWindowSeconds <= 0)) {
    throw new Error("spendWindowSeconds must be a positive integer");
  }
  if (policy.mode === "limited" && policy.spendLimitMicros === undefined) {
    throw new Error("limited mode requires --spend-limit-micros or :spend=<micros>");
  }
  if (policy.mode !== "limited" && policy.spendWindowSeconds !== undefined && policy.spendLimitMicros === undefined) {
    throw new Error("spend window requires a spend limit");
  }
}

async function runTui() {
  const terminal = new ProcessTerminal();
  const tui = new TUI(terminal);
  const dashboard = new Dashboard(tui);

  tui.addChild(dashboard);
  tui.setFocus(dashboard);
  tui.addInputListener((data) => {
    if (matchesKey(data, "ctrl+c")) {
      tui.stop();
      process.exit(0);
    }
    return undefined;
  });

  tui.start();
  await dashboard.refresh();
}

class Dashboard {
  constructor(tui) {
    this.tui = tui;
    this.view = "home";
    this.selected = 0;
    this.loading = true;
    this.error = "";
    this.status = {
      health: null,
      tools: [],
      keys: [],
      receipts: [],
      approvals: [],
    };
    this.homeItems = [
      { id: "setup", label: "Setup a new bot", hint: "guided flow for secrets, tools, and access", accent: "cyan" },
      { id: "secrets", label: "Add a secret", hint: "local JSON by default, Keychain recommended on Mac", accent: "green" },
      { id: "access", label: "Configure access", hint: "bot-to-tool permission matrix", accent: "yellow" },
      { id: "approvals", label: "Review approvals", hint: "human-in-the-loop queue", accent: "magenta" },
      { id: "receipts", label: "Audit receipts", hint: "recent tool-call trail", accent: "blue" },
      { id: "tools", label: "Manage tools", hint: "registered protected capabilities", accent: "cyan" },
      { id: "keys", label: "Manage bot keys", hint: "scoped agent access keys", accent: "green" },
    ];
  }

  invalidate() {}

  async refresh() {
    this.loading = true;
    this.error = "";
    this.tui.requestRender(true);

    const [health, tools, keys, receipts, approvals] = await Promise.all([
      safeRequest("/health"),
      safeRequest("/tools"),
      safeRequest("/keys", { admin: true }),
      safeRequest("/receipts?limit=8", { admin: true }),
      safeRequest("/approvals?limit=8", { admin: true }),
    ]);

    this.status = {
      health: health.ok ? health.data : null,
      tools: tools.ok ? tools.data.tools ?? [] : [],
      keys: keys.ok ? keys.data.keys ?? [] : [],
      receipts: receipts.ok ? receipts.data.receipts ?? [] : [],
      approvals: approvals.ok ? approvals.data.approvals ?? [] : [],
    };

    const errors = [health, tools, keys, receipts, approvals].filter((result) => !result.ok);
    this.error = errors.length ? errors[0].error : "";
    this.loading = false;
    this.tui.requestRender(true);
  }

  handleInput(data) {
    if (matchesKey(data, "q")) {
      this.tui.stop();
      process.exit(0);
    }
    if (matchesKey(data, "r")) {
      void this.refresh();
      return;
    }
    if (matchesKey(data, "escape") || matchesKey(data, "backspace")) {
      this.view = "home";
      this.selected = 0;
      this.tui.requestRender();
      return;
    }
    if (matchesKey(data, "up") || matchesKey(data, "k")) {
      this.move(-1);
      return;
    }
    if (matchesKey(data, "down") || matchesKey(data, "j")) {
      this.move(1);
      return;
    }
    if (this.view === "home" && (matchesKey(data, "enter") || matchesKey(data, "space"))) {
      this.view = this.homeItems[this.selected]?.id ?? "home";
      this.selected = 0;
      if (this.view === "setup") {
        this.openSetupDialog();
      }
      this.tui.requestRender();
      return;
    }
    if (this.view === "setup" && (matchesKey(data, "enter") || matchesKey(data, "space"))) {
      this.openSetupDialog();
      return;
    }
    if (this.view === "secrets" && (matchesKey(data, "enter") || matchesKey(data, "space"))) {
      this.openSecretDialog();
      return;
    }
    if (this.view === "access" && matchesKey(data, "space")) {
      void this.cycleSelectedAccessPolicy();
      return;
    }
    if (this.view === "approvals" && matchesKey(data, "a")) {
      void this.decideSelectedApproval("approved");
      return;
    }
    if (this.view === "approvals" && matchesKey(data, "d")) {
      void this.decideSelectedApproval("denied");
      return;
    }
  }

  move(delta) {
    const count = this.itemCount();
    if (count <= 0) return;
    this.selected = (this.selected + delta + count) % count;
    this.tui.requestRender();
  }

  itemCount() {
    if (this.view === "home") return this.homeItems.length;
    if (this.view === "tools") return Math.max(1, this.status.tools.length);
    if (this.view === "keys") return Math.max(1, this.status.keys.length);
    if (this.view === "receipts") return Math.max(1, this.status.receipts.length);
    if (this.view === "approvals") return Math.max(1, this.status.approvals.length);
    if (this.view === "access") return Math.max(1, accessRows(this.status.keys).length);
    return 1;
  }

  async cycleSelectedAccessPolicy() {
    const selected = accessRows(this.status.keys)[this.selected];
    if (!selected) return;
    const modes = ["deny", "auto", "approval"];
    const nextMode = modes[(modes.indexOf(selected.mode) + 1) % modes.length];
    this.loading = true;
    this.error = "";
    this.tui.requestRender(true);
    const result = await safeRequest(`/keys/${encodeURIComponent(selected.keyId)}/policies/${encodeURIComponent(selected.tool)}`, {
      method: "PUT",
      admin: true,
      body: { mode: nextMode },
    });
    if (!result.ok) {
      this.error = result.error;
      this.loading = false;
      this.tui.requestRender(true);
      return;
    }
    await this.refresh();
  }

  async decideSelectedApproval(decision) {
    const approval = this.status.approvals[this.selected];
    if (!approval || approval.status !== "pending") return;
    this.loading = true;
    this.error = "";
    this.tui.requestRender(true);
    const result = await safeRequest(`/approvals/${encodeURIComponent(approval.id)}/decision`, {
      method: "POST",
      admin: true,
      body: { decision },
    });
    if (!result.ok) {
      this.error = result.error;
      this.loading = false;
      this.tui.requestRender(true);
      return;
    }
    await this.refresh();
  }

  openSecretDialog() {
    const dialog = new SecretDialog(async ({ name, value, backend }) => {
      this.loading = true;
      this.error = "";
      this.tui.requestRender(true);
      try {
        await setCliSecret(name, value, backend);
        this.loading = false;
        this.error = `saved secret ${name} (${backend})`;
        this.tui.requestRender(true);
      } catch (error) {
        this.loading = false;
        this.error = error instanceof Error ? error.message : String(error);
        this.tui.requestRender(true);
      }
    });
    dialog.handle = this.tui.showOverlay(dialog, { width: "80%", minWidth: 54, maxHeight: 18 });
  }

  openSetupDialog() {
    const dialog = new SetupDialog(async (payload) => {
      this.loading = true;
      this.error = "";
      this.tui.requestRender(true);
      try {
        if (payload.secretName && payload.secretValue) {
          await setCliSecret(payload.secretName, payload.secretValue, payload.secretBackend);
        }
        await request("/tools", {
          method: "POST",
          admin: true,
          body: {
            slug: payload.slug,
            name: payload.name,
            targetType: payload.targetType,
            targetUrl: payload.targetType === "http" ? payload.targetUrl : undefined,
            secretHeaders: payload.secretName ? { [payload.secretHeader]: payload.secretName } : undefined,
            approvalRequired: payload.accessMode === "approval",
          },
        });
        await request("/keys", {
          method: "POST",
          admin: true,
          body: {
            name: payload.botName,
            allowedTools: [payload.slug],
            policies: { [payload.slug]: { mode: payload.accessMode } },
          },
        });
        this.error = `setup complete: ${payload.botName} -> ${payload.slug}`;
        await this.refresh();
      } catch (error) {
        this.loading = false;
        this.error = error instanceof Error ? error.message : String(error);
        this.tui.requestRender(true);
      }
    });
    dialog.handle = this.tui.showOverlay(dialog, { width: "88%", minWidth: 66, maxHeight: 22 });
  }

  render(width) {
    const safeWidth = Math.max(48, width);
    const lines = [
      "",
      ...this.renderBrand(safeWidth),
      "",
      ...this.renderStatus(safeWidth),
      "",
      ...this.renderBody(safeWidth),
      "",
      rule(safeWidth),
      chalk.dim(this.footerText()),
    ];
    return lines.map((line) => fit(line, safeWidth));
  }

  renderBrand(width) {
    const subtitle = `${chalk.white("Local agent firewall")} ${chalk.dim("|")} ${chalk.dim("secrets stay on this machine")}`;
    if (width < 72) {
      return [
        center(brandTitle("ECHO GATE"), width),
        center(subtitle, width),
      ];
    }
    const tagline = `${statusDot("green")} ${chalk.dim("local-first")}   ${statusDot("cyan")} ${chalk.dim("human-controlled")}   ${statusDot("blue")} ${chalk.dim("audited")}`;
    const title = `${chalk.dim("╔════════════════════════════════════════════╗")}
${chalk.dim("║")}  ${chalk.hex("#2DD4BF").bold("ECHO GATE")}  ${chalk.dim("|")}  ${chalk.dim("local-first tool firewall")}   ${chalk.dim("║")}
${chalk.dim("╚════════════════════════════════════════════╝")}`;
    return [
      ...asciiWordmark(width),
      ...title.split("\n").map((line) => center(line, width)),
      center(subtitle, width),
      center(tagline, width),
    ];
  }

  footerText() {
    if (this.view === "setup") {
      return "  enter setup wizard   ↑/↓ move   r refresh   esc back   q quit";
    }
    if (this.view === "secrets") {
      return "  enter add secret   ↑/↓ move   r refresh   esc back   q quit";
    }
    if (this.view === "approvals") {
      return "  ↑/↓ move   a approve   d deny   r refresh   esc back   q quit";
    }
    if (this.view === "access") {
      return "  ↑/↓ move   space cycle mode   r refresh   esc back   q quit";
    }
    return "  ↑/↓ move   enter open   space select/toggle   r refresh   esc back   q quit";
  }

  renderStatus(width) {
    const health = this.status.health;
    const online = Boolean(health?.ok);
    const left = [
      badge(online ? "LOCAL GATE ONLINE" : "GATE OFFLINE", online ? "green" : "red"),
      ` ${baseUrl()}`,
      this.loading ? chalk.dim(" refreshing...") : "",
    ].join("");
    const counts = [
      chalk.cyan(`${this.status.tools.length} tools`),
      chalk.green(`${this.status.keys.length} keys`),
      chalk.blue(`${this.status.receipts.length} receipts`),
      chalk.magenta(`${this.status.approvals.filter((approval) => approval.status === "pending").length} pending`),
    ].join(chalk.dim("  /  "));
    const lines = [
      chalk.dim("  " + "─".repeat(Math.max(1, width - 4))),
      `  ${left}`,
      `  ${chalk.dim(counts)}`,
      chalk.dim("  " + "─".repeat(Math.max(1, width - 4))),
    ];
    if (this.error && !this.loading) {
      lines.push(`  ${chalk.yellow("notice")} ${chalk.dim(this.error)}`);
    }
    return lines;
  }

  renderBody(width) {
    if (this.view === "home") return this.renderHome();
    if (this.view === "setup") return panel("Setup", [
      "Press enter to launch the guided setup wizard.",
      "",
      "It will:",
      "1. Register a protected tool",
      "2. Store a local secret when needed",
      "3. Create a scoped bot key",
      "4. Apply deny / auto / approval access",
      "",
      "Default secret storage is local JSON; on Mac, Keychain is the recommended safer option.",
      "",
      row(true, "Start setup wizard", "keyboard-only flow"),
    ]);
    if (this.view === "secrets") return panel("Secrets", [
      "Press enter to add a secret without typing CLI commands.",
      "Default storage is local JSON. On Mac, Keychain is the recommended safer option.",
      "",
      row(true, "Add secret", "choose name, storage backend, and value"),
      "",
      chalk.dim("Local secret values are not displayed here."),
    ]);
    if (this.view === "access") return this.renderAccess();
    if (this.view === "approvals") return this.renderApprovals();
    if (this.view === "receipts") return this.renderReceipts();
    if (this.view === "tools") return this.renderTools();
    if (this.view === "keys") return this.renderKeys();
    return [];
  }

  renderHome() {
    const pending = this.status.approvals.filter((approval) => approval.status === "pending").length;
    const selectedItem = this.homeItems[this.selected] ?? this.homeItems[0];
    const inventory = [
      `Gateway   ${this.status.health?.ok ? chalk.green("online") : chalk.red("offline")}   ${chalk.dim(baseUrl())}`,
      `Storage   ${chalk.cyan("local")}    Secrets ${chalk.cyan("local-json")}    Approvals ${pending ? chalk.yellow(String(pending)) : chalk.dim("0")}`,
      `Surface   ${chalk.white("keyboard TUI")}    Audit ${this.status.receipts.length ? chalk.blue("recording") : chalk.dim("ready")}`,
    ];
    const lines = [
      sectionTitle("Control Room", "all local controls"),
      chalk.dim("  Arrow keys and enter. The human stays in the loop."),
      "",
      ...launchPanel([
        ...inventory,
        "",
        quickStats([
          ["Tools", this.status.tools.length, "cyan"],
          ["Bot keys", this.status.keys.length, "green"],
          ["Receipts", this.status.receipts.length, "blue"],
          ["Pending", pending, pending ? "magenta" : "gray"],
        ]).trimStart(),
      ], 74),
      "",
      chalk.dim("  Choose a section"),
    ];
    for (let i = 0; i < this.homeItems.length; i += 1) {
      const item = this.homeItems[i];
      const selected = i === this.selected;
      lines.push(menuRow(selected, item.label, item.hint, item.accent));
    }
    lines.push(
      "",
      chalk.dim("  Selected"),
      callout(selectedItem.label, selectedItem.hint, selectedItem.accent),
    );
    return lines;
  }

  renderAccess() {
    const rows = accessRows(this.status.keys);
    const lines = panel("Access Matrix", ["Space cycles deny / auto / approval. Use CLI for limited spend caps."]);
    if (!rows.length) {
      lines.push(...emptyState("No policies yet.", "Create a bot key with a policy, then return here."));
      return lines;
    }
    rows.forEach((entry, index) => {
      const selected = index === this.selected;
      lines.push(row(selected, `${entry.keyName}  ->  ${entry.tool}`, modeLabel(entry.mode)));
    });
    return lines;
  }

  renderApprovals() {
    const lines = panel("Approvals", []);
    if (!this.status.approvals.length) {
      lines.push(...emptyState("No approvals visible.", "Approval-required calls will appear here."));
      return lines;
    }
    this.status.approvals.forEach((approval, index) => {
      const actionHint = approval.status === "pending" ? "a approve / d deny" : approval.receiptId ? `receipt ${approval.receiptId}` : "";
      lines.push(row(index === this.selected, `${statusDot(statusColor(approval.status))} ${approval.toolSlug} ${chalk.dim(approval.id)}`, `${approval.status} / ${approval.keyPrefix}${actionHint ? ` / ${actionHint}` : ""}`));
    });
    return lines;
  }

  renderTools() {
    const lines = panel("Tools", []);
    if (!this.status.tools.length) {
      lines.push(...emptyState("No tools found.", "Start the gateway or register a protected tool."));
      return lines;
    }
    this.status.tools.forEach((tool, index) => {
      const detail = [
        tool.targetType,
        tool.approvalRequired ? "approval" : "auto",
        tool.secretHeaderNames?.length ? `secrets: ${tool.secretHeaderNames.join(",")}` : "no secrets",
      ].filter(Boolean).join(" / ");
      lines.push(row(index === this.selected, `${statusDot(tool.targetType === "http" ? "blue" : "cyan")} ${tool.slug}`, detail));
    });
    return lines;
  }

  renderKeys() {
    const lines = panel("Bot Keys", []);
    if (!this.status.keys.length) {
      lines.push(...emptyState("No keys visible.", "Admin token may be missing, or no keys exist."));
      return lines;
    }
    this.status.keys.forEach((key, index) => {
      const tools = key.allowedTools?.length ? key.allowedTools.join(",") : "all tools";
      lines.push(row(index === this.selected, `${statusDot(key.status === "active" ? "green" : "red")} ${key.name} ${chalk.dim(key.prefix ?? "")}`, `${key.status} / ${tools}`));
    });
    return lines;
  }

  renderReceipts() {
    const lines = panel("Receipts", []);
    if (!this.status.receipts.length) {
      lines.push(...emptyState("No receipts visible yet.", "Tool calls will leave signed audit trails here."));
      return lines;
    }
    this.status.receipts.forEach((receipt, index) => {
      const label = `${statusDot(receipt.status === "ok" ? "green" : "red")} ${receipt.toolSlug ?? receipt.toolId ?? "tool"} ${chalk.dim(receipt.requestId ?? "")}`;
      const detail = `${receipt.status ?? "unknown"} / ${receipt.httpStatus ?? "-"} / ${receipt.durationMs ?? "-"}ms`;
      lines.push(row(index === this.selected, label, detail));
    });
    return lines;
  }
}

class SecretDialog {
  constructor(onSave) {
    this.onSave = onSave;
    this.focused = false;
    this.field = 0;
    this.backendIndex = 0;
    this.name = "";
    this.value = "";
    this.message = "";
    this.saving = false;
    this.backends = [
      { value: "file", label: "Local JSON", hint: "default, simple, fully local" },
      { value: "macos-keychain", label: "macOS Keychain", hint: "recommended on Mac; OS vault protects the value" },
    ];
  }

  handleInput(data) {
    if (this.saving) return;
    if (matchesKey(data, "escape")) {
      this.close();
      return;
    }
    if (matchesKey(data, "tab") || matchesKey(data, "down")) {
      this.field = (this.field + 1) % 4;
      return;
    }
    if (matchesKey(data, "shift+tab") || matchesKey(data, "up")) {
      this.field = (this.field + 3) % 4;
      return;
    }
    if (this.field === 2 && (matchesKey(data, "left") || matchesKey(data, "right") || matchesKey(data, "space"))) {
      this.backendIndex = (this.backendIndex + 1) % this.backends.length;
      return;
    }
    if (matchesKey(data, "enter")) {
      if (this.field < 3) {
        this.field += 1;
      } else {
        void this.save();
      }
      return;
    }
    if (this.field === 0) {
      this.name = editText(this.name, data);
      return;
    }
    if (this.field === 1) {
      this.value = editText(this.value, data);
    }
  }

  async save() {
    this.message = "";
    const name = this.name.trim();
    if (!name) {
      this.message = "Secret name is required.";
      this.field = 0;
      return;
    }
    if (!this.value) {
      this.message = "Secret value is required.";
      this.field = 1;
      return;
    }
    this.saving = true;
    try {
      await this.onSave({ name, value: this.value, backend: this.backends[this.backendIndex].value });
      this.close();
    } catch (error) {
      this.saving = false;
      this.message = error instanceof Error ? error.message : String(error);
    }
  }

  close() {
    this.handle?.hide();
  }

  render(width) {
    const safeWidth = Math.max(44, width);
    const backend = this.backends[this.backendIndex];
    const lines = [
      chalk.bold("Add Secret"),
      chalk.dim("Use tab or arrows to move. Enter advances. Esc cancels."),
      "",
      inputLine(this.field === 0, "Name", this.name, safeWidth),
      inputLine(this.field === 1, "Value", this.value ? "•".repeat(Math.min(this.value.length, 32)) : "", safeWidth),
      row(this.field === 2, "Storage", `${backend.label} - ${backend.hint}`),
      row(this.field === 3, this.saving ? "Saving..." : "Save secret", "enter"),
    ];
    if (this.message) {
      lines.push("", chalk.yellow(this.message));
    }
    return box(lines, safeWidth);
  }
}

class SetupDialog {
  constructor(onSave) {
    this.onSave = onSave;
    this.focused = false;
    this.field = 0;
    this.saving = false;
    this.message = "";
    this.targetTypes = ["echo", "http"];
    this.targetTypeIndex = 0;
    this.backends = ["file", "macos-keychain"];
    this.backendIndex = 0;
    this.accessModes = ["auto", "approval"];
    this.accessModeIndex = 1;
    this.values = {
      slug: "echo",
      name: "Echo",
      targetUrl: "",
      secretHeader: "Authorization",
      secretName: "",
      secretValue: "",
      botName: "local-agent",
    };
  }

  fields() {
    const base = [
      { id: "targetType", label: "Tool type", kind: "choice" },
      { id: "slug", label: "Tool slug", kind: "text" },
      { id: "name", label: "Tool name", kind: "text" },
    ];
    const http = this.targetType() === "http"
      ? [
          { id: "targetUrl", label: "Upstream URL", kind: "text" },
          { id: "secretHeader", label: "Secret header", kind: "text" },
          { id: "secretName", label: "Secret name", kind: "text" },
          { id: "secretValue", label: "Secret value", kind: "secret" },
          { id: "secretBackend", label: "Secret storage", kind: "choice" },
        ]
      : [];
    return [
      ...base,
      ...http,
      { id: "accessMode", label: "Access mode", kind: "choice" },
      { id: "botName", label: "Bot key name", kind: "text" },
      { id: "save", label: "Create setup", kind: "action" },
    ];
  }

  targetType() {
    return this.targetTypes[this.targetTypeIndex];
  }

  accessMode() {
    return this.accessModes[this.accessModeIndex];
  }

  backend() {
    return this.backends[this.backendIndex];
  }

  handleInput(data) {
    if (this.saving) return;
    const fields = this.fields();
    if (matchesKey(data, "escape")) {
      this.close();
      return;
    }
    if (matchesKey(data, "tab") || matchesKey(data, "down")) {
      this.field = (this.field + 1) % fields.length;
      return;
    }
    if (matchesKey(data, "shift+tab") || matchesKey(data, "up")) {
      this.field = (this.field + fields.length - 1) % fields.length;
      return;
    }
    const current = fields[this.field];
    if (current?.kind === "choice" && (matchesKey(data, "left") || matchesKey(data, "right") || matchesKey(data, "space"))) {
      this.cycleChoice(current.id);
      return;
    }
    if (matchesKey(data, "enter")) {
      if (current?.id === "save") {
        void this.save();
      } else {
        this.field = Math.min(this.field + 1, fields.length - 1);
      }
      return;
    }
    if (current?.kind === "text" || current?.kind === "secret") {
      this.values[current.id] = editText(this.values[current.id] ?? "", data);
    }
  }

  cycleChoice(id) {
    if (id === "targetType") {
      this.targetTypeIndex = (this.targetTypeIndex + 1) % this.targetTypes.length;
      if (this.targetType() === "echo") {
        this.values.slug ||= "echo";
        this.values.name ||= "Echo";
      }
      this.field = Math.min(this.field, this.fields().length - 1);
    }
    if (id === "secretBackend") this.backendIndex = (this.backendIndex + 1) % this.backends.length;
    if (id === "accessMode") this.accessModeIndex = (this.accessModeIndex + 1) % this.accessModes.length;
  }

  async save() {
    const payload = {
      targetType: this.targetType(),
      slug: this.values.slug.trim(),
      name: this.values.name.trim(),
      targetUrl: this.values.targetUrl.trim(),
      secretHeader: this.values.secretHeader.trim(),
      secretName: this.values.secretName.trim(),
      secretValue: this.values.secretValue,
      secretBackend: this.backend(),
      accessMode: this.accessMode(),
      botName: this.values.botName.trim(),
    };
    const error = validateSetupPayload(payload);
    if (error) {
      this.message = error;
      return;
    }
    this.saving = true;
    try {
      await this.onSave(payload);
      this.close();
    } catch (error) {
      this.saving = false;
      this.message = error instanceof Error ? error.message : String(error);
    }
  }

  close() {
    this.handle?.hide();
  }

  render(width) {
    const safeWidth = Math.max(58, width);
    const fields = this.fields();
    const lines = [
      chalk.bold("Setup Wizard"),
      chalk.dim("Use arrows/tab to move. Space changes choices. Enter advances or creates."),
      "",
    ];
    fields.forEach((field, index) => {
      const selected = index === this.field;
      if (field.kind === "choice") {
        lines.push(row(selected, field.label, this.choiceValue(field.id)));
      } else if (field.kind === "action") {
        lines.push(row(selected, this.saving ? "Creating..." : field.label, "register tool + create bot key"));
      } else {
        const raw = this.values[field.id] ?? "";
        const value = field.kind === "secret" && raw ? "•".repeat(Math.min(raw.length, 32)) : raw;
        lines.push(inputLine(selected, field.label, value, safeWidth));
      }
    });
    if (this.message) lines.push("", chalk.yellow(this.message));
    return box(lines, safeWidth);
  }

  choiceValue(id) {
    if (id === "targetType") return this.targetType() === "echo" ? "Echo smoke tool" : "HTTP API tool";
    if (id === "secretBackend") return this.backend() === "file" ? "Local JSON" : "macOS Keychain";
    if (id === "accessMode") return this.accessMode();
    return "";
  }
}

async function safeRequest(path, options = {}) {
  try {
    return { ok: true, data: await request(path, options) };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function panel(title, lines) {
  const output = [
    sectionTitle(title),
    "",
  ];
  for (const line of lines) {
    output.push(line ? `  ${line}` : "");
  }
  return output;
}

function row(selected, label, hint) {
  const pointer = selected ? chalk.cyan("▸") : chalk.dim(" ");
  const text = selected ? chalk.white.bold(label) : chalk.white(label);
  const spacer = hint ? chalk.dim("  —  ") : "";
  return ` ${pointer} ${text}${hint ? `${spacer}${chalk.dim(hint)}` : ""}`;
}

function menuRow(selected, label, hint, accent = "cyan") {
  const paint = accentColor(accent);
  const pointer = selected ? paint("▸") : chalk.dim("·");
  const text = selected ? paint(chalk.bold(label)) : chalk.white(label);
  const rail = selected ? paint("│") : chalk.dim("│");
  const hintText = hint ? chalk.dim(`  ${truncatePlainHint(hint, 44)}`) : "";
  return `  ${rail} ${pointer} ${text}${hintText}`;
}

function quickStats(items) {
  return `  ${items.map(([label, value, color]) => {
    const paint = accentColor(color);
    return `${paint(chalk.bold(String(value)))} ${chalk.dim(label)}`;
  }).join(chalk.dim("    "))}`;
}

function asciiWordmark(width) {
  const dense = [
    "███████╗ ██████╗██╗  ██╗ ██████╗        ██████╗  █████╗ ████████╗███████╗",
    "██╔════╝██╔════╝██║  ██║██╔═══██╗      ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝",
    "█████╗  ██║     ███████║██║   ██║█████╗██║  ███╗███████║   ██║   █████╗  ",
    "██╔══╝  ██║     ██╔══██║██║   ██║╚════╝██║   ██║██╔══██║   ██║   ██╔══╝  ",
    "███████╗╚██████╗██║  ██║╚██████╔╝      ╚██████╔╝██║  ██║   ██║   ███████╗",
    "╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝        ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝",
  ];
  const compact = [
    "____ ____ _  _ ____    ____ ____ ___ ____ ",
    "|___ |    |__| |  | __ | __ |__|  |  |___ ",
    "|___ |___ |  | |__|    |__] |  |  |  |___ ",
  ];

  if (width < 56) {
    return [
      center(brandTitle("ECHO-GATE"), width),
      center(chalk.cyan("local agent firewall"), width),
    ];
  }

  if (width >= 80) {
    const paints = [
      chalk.hex("#38BDF8").bold,
      chalk.hex("#22D3EE").bold,
      chalk.hex("#E0F2FE").bold,
      chalk.hex("#5EEAD4").bold,
      chalk.hex("#2DD4BF").bold,
      chalk.hex("#0F766E").bold,
    ];
    return dense.map((line, index) => center(paints[index](line), width));
  }

  return compact.map((line, index) => {
    const paint = index % 2 === 0 ? chalk.white.bold : chalk.hex("#2DD4BF").bold;
    return center(paint(line), width);
  });
}

function launchPanel(lines, width) {
  const innerWidth = width - 4;
  const frame = chalk.hex("#2DD4BF");
  return [
    `  ${frame("╭" + "─".repeat(innerWidth + 2) + "╮")}`,
    ...lines.map((line) => {
      const clipped = fit(line, innerWidth);
      const padding = " ".repeat(Math.max(0, innerWidth - visibleWidth(clipped)));
      return `  ${frame("│")} ${clipped}${padding} ${frame("│")}`;
    }),
    `  ${frame("╰" + "─".repeat(innerWidth + 2) + "╯")}`,
  ];
}

function truncatePlainHint(hint, width) {
  return hint.length > width ? `${hint.slice(0, Math.max(0, width - 1))}…` : hint;
}

function sectionTitle(title, meta = "") {
  const suffix = meta ? chalk.dim(`  ${meta}`) : "";
  return `  ${chalk.cyan("╭─")} ${chalk.bold(title)}${suffix}`;
}

function emptyState(title, detail) {
  return [
    `  ${chalk.dim("┌")} ${chalk.dim(title)}`,
    `  ${chalk.dim("└")} ${chalk.dim(detail)}`,
  ];
}

function callout(title, detail, accent = "cyan") {
  const paint = accentColor(accent);
  return `  ${paint("╰─")} ${paint(chalk.bold(title))}${detail ? chalk.dim(`  ${detail}`) : ""}`;
}

function brandTitle(text) {
  return [...text].map((char, index) => {
    if (char === " ") return " ";
    return index < 4 ? chalk.white.bold(char) : chalk.hex("#2DD4BF").bold(char);
  }).join("");
}

function brandBoxLine(content, width) {
  const innerWidth = Math.max(2, width - 2);
  const padding = Math.max(0, innerWidth - visibleWidth(content));
  const left = Math.floor(padding / 2);
  const right = padding - left;
  return `${chalk.cyan("║")}${" ".repeat(left)}${content}${" ".repeat(right)}${chalk.cyan("║")}`;
}

function accentColor(name) {
  if (name === "green") return chalk.green;
  if (name === "yellow") return chalk.yellow;
  if (name === "magenta") return chalk.magenta;
  if (name === "blue") return chalk.blue;
  if (name === "gray") return chalk.gray;
  if (name === "red") return chalk.red;
  return chalk.cyan;
}

function statusColor(status) {
  if (status === "executed" || status === "approved" || status === "ok" || status === "active") return "green";
  if (status === "pending" || status === "approval") return "yellow";
  if (status === "failed" || status === "denied" || status === "error" || status === "revoked") return "red";
  return "cyan";
}

function statusDot(color) {
  return accentColor(color)("●");
}

function inputLine(selected, label, value, width) {
  const marker = selected ? chalk.cyan("›") : " ";
  const cursor = selected ? CURSOR_MARKER : "";
  const display = value || chalk.dim("empty");
  return fit(` ${marker} ${chalk.bold(label)}  ${cursor}${display}`, Math.max(12, width - 2));
}

function box(lines, width) {
  const innerWidth = Math.max(20, width - 4);
  const top = `╭${"─".repeat(innerWidth + 2)}╮`;
  const bottom = `╰${"─".repeat(innerWidth + 2)}╯`;
  return [
    top,
    ...lines.map((line) => {
      const clipped = fit(line, innerWidth);
      const padding = " ".repeat(Math.max(0, innerWidth - visibleWidth(clipped)));
      return `│ ${clipped}${padding} │`;
    }),
    bottom,
  ];
}

function editText(value, data) {
  if (matchesKey(data, "backspace")) return value.slice(0, -1);
  const parsed = parseKey(data);
  if (parsed && parsed.length === 1 && visibleWidth(parsed) === 1) return `${value}${parsed}`;
  if (data.length === 1) {
    const code = data.charCodeAt(0);
    if (code >= 32 && code !== 127) return `${value}${data}`;
  }
  return value;
}

function validateSetupPayload(payload) {
  if (!payload.slug) return "Tool slug is required.";
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(payload.slug)) return "Tool slug must be lowercase letters, numbers, or hyphens.";
  if (!payload.name) return "Tool name is required.";
  if (!payload.botName) return "Bot key name is required.";
  if (payload.targetType === "http") {
    if (!payload.targetUrl) return "Upstream URL is required for HTTP tools.";
    try {
      new URL(payload.targetUrl);
    } catch {
      return "Upstream URL must be a valid URL.";
    }
    if (!payload.secretHeader) return "Secret header is required for HTTP tools.";
    if (!payload.secretName) return "Secret name is required for HTTP tools.";
    if (!payload.secretValue) return "Secret value is required for HTTP tools.";
  }
  return "";
}

function modeLabel(mode) {
  if (mode === "auto") return chalk.green("auto");
  if (mode === "approval") return chalk.yellow("approval");
  if (mode === "limited") return chalk.cyan("limited");
  return chalk.red("deny");
}

function badge(text, color) {
  const paint = color === "green" ? chalk.green : color === "red" ? chalk.red : chalk.cyan;
  return paint(`[${text}]`);
}

function center(text, width) {
  const padding = Math.max(0, Math.floor((width - visibleWidth(text)) / 2));
  return `${" ".repeat(padding)}${text}`;
}

function rule(width) {
  return chalk.dim("─".repeat(Math.max(1, width)));
}

function fit(line, width) {
  return visibleWidth(line) > width ? truncateToWidth(line, width) : line;
}

function accessRows(keys) {
  return keys.flatMap((key) => Object.entries(key.policies ?? {}).map(([tool, policy]) => ({
    keyId: key.id,
    keyName: key.name ?? key.id,
    tool,
    mode: policy.mode,
  })));
}

async function promptSecretValue(name) {
  const value = await prompts.password({
    message: `Secret value for ${name}`,
  });
  if (prompts.isCancel(value)) {
    prompts.cancel("Secret add cancelled.");
    process.exit(0);
  }
  return String(value);
}

function cliSecretPath() {
  return join(process.env.ECHO_GATE_STATE_DIR ?? join(homedir(), ".config", "echo-gate"), "secrets.json");
}

async function readCliSecretState() {
  try {
    const raw = JSON.parse(await readFile(cliSecretPath(), "utf8"));
    return { secrets: Array.isArray(raw?.secrets) ? raw.secrets : [] };
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    return { secrets: [] };
  }
}

async function writeCliSecretState(state) {
  const path = cliSecretPath();
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  await rename(tmp, path);
}

function normalizeCliSecretName(name) {
  const normalized = String(name).trim();
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(normalized)) {
    throw new Error("invalid_secret_name");
  }
  return normalized;
}

async function setCliSecret(name, value, backendOverride) {
  const normalized = normalizeCliSecretName(name);
  const state = await readCliSecretState();
  const now = Date.now();
  const existing = state.secrets.find((secret) => secret.name === normalized);
  const backend = normalizeSecretBackend(backendOverride ?? activeSecretBackend());
  if (backend === "macos-keychain") {
    await setMacKeychainSecret(normalized, value);
  }
  const record = {
    name: normalized,
    value: backend === "file" ? value : undefined,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
    backend,
  };
  state.secrets = existing
    ? state.secrets.map((secret) => secret.name === normalized ? record : secret)
    : [...state.secrets, record];
  await writeCliSecretState(state);
  const { value: _, ...safe } = record;
  return safe;
}

async function listCliSecrets() {
  const state = await readCliSecretState();
  return state.secrets
    .map(({ value, ...safe }) => safe)
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function getCliSecret(name) {
  const normalized = normalizeCliSecretName(name);
  const state = await readCliSecretState();
  const record = state.secrets.find((secret) => secret.name === normalized);
  if (record?.backend === "macos-keychain" || activeSecretBackend() === "macos-keychain") {
    const keychainValue = await readMacKeychainSecret(normalized);
    if (keychainValue !== undefined) return keychainValue;
  }
  return record?.value;
}

async function deleteCliSecret(name) {
  const normalized = normalizeCliSecretName(name);
  const state = await readCliSecretState();
  const existing = state.secrets.find((secret) => secret.name === normalized);
  const removedFromKeychain = existing?.backend === "macos-keychain" || activeSecretBackend() === "macos-keychain"
    ? await deleteMacKeychainSecret(normalized)
    : false;
  const next = state.secrets.filter((secret) => secret.name !== normalized);
  if (next.length === state.secrets.length && !removedFromKeychain) return false;
  await writeCliSecretState({ secrets: next });
  return true;
}

function activeSecretBackend() {
  const configured = process.env.ECHO_GATE_SECRET_BACKEND;
  if (configured) return normalizeSecretBackend(configured);
  return "file";
}

function normalizeSecretBackend(value) {
  if (value === "file" || value === "macos-keychain") return value;
  throw new Error("invalid_secret_backend");
}

async function setMacKeychainSecret(name, value) {
  await execFileAsync("/usr/bin/security", [
    "add-generic-password",
    "-a", name,
    "-s", keychainService,
    "-l", `Echo Gate ${name}`,
    "-j", "Echo Gate local tool secret",
    "-U",
    "-w", value,
  ], { timeout: keychainTimeoutMs });
}

async function readMacKeychainSecret(name) {
  try {
    const { stdout } = await execFileAsync("/usr/bin/security", [
      "find-generic-password",
      "-a", name,
      "-s", keychainService,
      "-w",
    ], { maxBuffer: 1024 * 1024, timeout: keychainTimeoutMs });
    return stdout.endsWith("\n") ? stdout.slice(0, -1) : stdout;
  } catch (error) {
    if (error?.code === 44 || /could not be found/i.test(String(error?.stderr ?? error?.message ?? ""))) {
      return undefined;
    }
    throw error;
  }
}

async function deleteMacKeychainSecret(name) {
  try {
    await execFileAsync("/usr/bin/security", [
      "delete-generic-password",
      "-a", name,
      "-s", keychainService,
    ], { timeout: keychainTimeoutMs });
    return true;
  } catch (error) {
    if (error?.code === 44 || /could not be found/i.test(String(error?.stderr ?? error?.message ?? ""))) {
      return false;
    }
    throw error;
  }
}

async function promptText(options) {
  const value = await prompts.text(options);
  if (prompts.isCancel(value)) {
    prompts.cancel("Setup cancelled.");
    process.exit(0);
  }
  return String(value).trim();
}

async function promptSelect(options) {
  const value = await prompts.select(options);
  if (prompts.isCancel(value)) {
    prompts.cancel("Setup cancelled.");
    process.exit(0);
  }
  return value;
}

async function promptConfirm(options) {
  const value = await prompts.confirm(options);
  if (prompts.isCancel(value)) {
    prompts.cancel("Setup cancelled.");
    process.exit(0);
  }
  return Boolean(value);
}

try {
  if (process.argv.length <= 2 && process.stdout.isTTY && process.stdin.isTTY) {
    await runTui();
  } else if (process.argv.length <= 2) {
    program.outputHelp();
  } else {
    await program.parseAsync();
  }
} catch (error) {
  if (error?.data) {
    console.error(JSON.stringify(error.data, null, 2));
  } else {
    console.error(chalk.red(error instanceof Error ? error.message : String(error)));
  }
  process.exit(1);
}
