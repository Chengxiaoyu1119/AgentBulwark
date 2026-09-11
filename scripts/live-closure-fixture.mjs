import { createWriteStream } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
function resolvePython() {
  const explicit = String(process.env.AGENT_SUPERVISOR_PYTHON || "").trim();
  if (explicit) return { command: explicit, args: [] };
  if (process.platform === "win32") {
    const probe = spawnSync("py", ["-3", "-c", "import uvicorn"], {
      stdio: "ignore",
      windowsHide: true,
    });
    if (!probe.error && probe.status === 0) return { command: "py", args: ["-3"] };
  }
  return { command: "python", args: [] };
}

const pythonRuntime = resolvePython();
const python = pythonRuntime.command;
const pythonArgs = pythonRuntime.args;
const runtime = resolve(
  repoRoot,
  "apps/api/runtime/quality/live-closure-fixture",
  `run-${process.pid}-${Date.now()}`,
);
const stableReportPath = resolve(
  repoRoot,
  "apps/api/runtime/quality/live-closure-fixture/last-run.json",
);
const providerPort = "18082";
const apiPort = "8022";
const reportPath = resolve(runtime, "last-run.json");
const childProcesses = [];
let completed = false;

function childEnvironment(overrides) {
  return { ...process.env, PYTHONUTF8: "1", ...overrides };
}

function start(command, args, env, logName) {
  const log = createWriteStream(resolve(runtime, logName), { flags: "a" });
  const child = spawn(command, args, {
    cwd: repoRoot,
    env: childEnvironment(env),
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.pipe(log);
  child.stderr.pipe(log);
  childProcesses.push(child);
  return child;
}

async function waitForApi() {
  const healthUrl = `http://127.0.0.1:${apiPort}/api/public/status`;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(healthUrl);
      if (response.ok) return;
    } catch {
      // The server may still be loading its local schema.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
  }
  throw new Error("isolated-api-not-ready");
}

async function registerMcpFixtureAgent() {
  const baseUrl = `http://127.0.0.1:${apiPort}`;
  const adminHeaders = {
    Authorization: "Bearer live-admin-token",
    "Content-Type": "application/json",
  };
  const createdResponse = await fetch(`${baseUrl}/api/agents`, {
    method: "POST",
    headers: adminHeaders,
    body: JSON.stringify({ agent_id: "live-closure-agent", display_name: "Live closure MCP fixture" }),
  });
  if (!createdResponse.ok) {
    throw new Error(`isolated-agent-registration-failed-${createdResponse.status}`);
  }
  const created = await createdResponse.json();
  const token = String(created.token || "").trim();
  if (!token) throw new Error("isolated-agent-token-missing");

  const policyResponse = await fetch(`${baseUrl}/api/policy_settings`, {
    method: "PATCH",
    headers: adminHeaders,
    body: JSON.stringify({
      agent_tool_allowlists: { "live-closure-agent": ["file.read"] },
      agent_model_allowlists: { "live-closure-agent": ["fixture-model"] },
      agent_api_allowlists: { "live-closure-agent": [] },
      agent_context_allowlists: {
        "live-closure-agent": { resources: [], resource_templates: [], prompts: [] },
      },
      comment: "isolated live closure fixture binding",
    }),
  });
  if (!policyResponse.ok) throw new Error(`isolated-agent-policy-binding-failed-${policyResponse.status}`);
  return token;
}

async function main() {
  await mkdir(runtime, { recursive: true });
  start(python, [...pythonArgs, "-X", "utf8", "-m", "apps.api.tests.fixtures.openai_gateway_provider"], {
    FIXTURE_PROVIDER_PORT: providerPort,
  }, "provider.log");

  start(python, [...pythonArgs, "-X", "utf8", "-m", "apps.api.dev_server"], {
    AGENT_SUPERVISOR_API_HOST: "127.0.0.1",
    AGENT_SUPERVISOR_API_PORT: apiPort,
    AGENT_SUPERVISOR_RUNTIME_DIR: runtime,
    AGENT_SUPERVISOR_AUTH_DISABLED: "false",
    AGENT_SUPERVISOR_SECURITY_PROFILE: "local",
    AGENT_SUPERVISOR_API_TOKEN_ADMIN: "live-admin-token",
    AGENT_SUPERVISOR_API_TOKEN_ANALYST: "live-analyst-token",
    AGENT_SUPERVISOR_API_TOKEN_OBSERVER: "live-observer-token",
    AGENT_SUPERVISOR_API_TOKEN_EXECUTOR: "",
    AGENT_SUPERVISOR_AUDIT_HMAC_KEY: "live-closure-hmac-key",
    AGENT_SUPERVISOR_CORS_ORIGINS: "http://127.0.0.1:5182",
    AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS: "true",
    AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS: "true",
    MODEL_REAL_API_ENABLED: "true",
    MODEL_PROVIDER_PRIORITY: "openai-compatible",
    OPENAI_COMPATIBLE_API_KEY: "fixture-provider-key",
    OPENAI_COMPATIBLE_BASE_URL: `http://127.0.0.1:${providerPort}/v1`,
    OPENAI_COMPATIBLE_MODEL: "fixture-model",
    TARGET_MODEL_PROVIDER_PRIORITY: "openai-compatible",
    TARGET_REAL_MODEL_PROVIDER: "openai-compatible",
    TARGET_OPENAI_COMPATIBLE_API_KEY: "fixture-provider-key",
    TARGET_OPENAI_COMPATIBLE_BASE_URL: `http://127.0.0.1:${providerPort}/v1`,
    TARGET_OPENAI_COMPATIBLE_MODEL: "fixture-model",
    AGENT_SUPERVISOR_PROVIDER_DNS_MODE: "system",
    MCP_GATEWAY_ENABLED: "true",
    MCP_GATEWAY_GUARD_ENABLED: "true",
    MCP_GATEWAY_UPSTREAM_COMMAND: [python, ...pythonArgs, "-X", "utf8", "-m", "apps.api.tests.fixtures.mcp_echo_server"]
      .map((item) => (String(item).includes(" ") ? `"${item}"` : item))
      .join(" "),
    MCP_GATEWAY_SESSION_ISOLATION: "true",
    MCP_GATEWAY_RESOURCE_LIMITS_ENABLED: "true",
    MCP_GATEWAY_NETWORK_MODE: "reject-unpinned",
    MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS: "false",
    MCP_GATEWAY_REQUEST_STATE_SECRET: "live-mcp-request-state-secret-32-bytes",
    MCP_GATEWAY_SERVER_NAME: "智垒 MCP Gateway",
    MCP_ECHO_SERVER_REQUEST: "0",
  }, "api.log");

  await waitForApi();
  const mcpToken = await registerMcpFixtureAgent();
  const smoke = spawn(process.execPath, [resolve(repoRoot, "scripts/live-closure-smoke.mjs")], {
    cwd: repoRoot,
    env: childEnvironment({
      AGENT_SUPERVISOR_LIVE_SMOKE: "true",
      AGENT_SUPERVISOR_LIVE_BASE_URL: `http://127.0.0.1:${apiPort}`,
      AGENT_SUPERVISOR_LIVE_OPERATOR_TOKEN: "live-admin-token",
      AGENT_SUPERVISOR_LIVE_MCP_TOKEN: mcpToken,
      AGENT_SUPERVISOR_MCP_LIVE_PROBE_JSON: JSON.stringify({
        read_only: true,
        tool: "file.read",
        arguments: { path: "public/project-overview" },
      }),
      AGENT_SUPERVISOR_LIVE_REPORT_PATH: reportPath,
    }),
    stdio: "inherit",
    windowsHide: true,
  });
  const exitCode = await new Promise((resolvePromise, reject) => {
    smoke.once("error", reject);
    smoke.once("exit", (code, signal) => resolvePromise(signal ? 1 : code ?? 1));
  });
  if (exitCode !== 0) throw new Error(`live-closure-fixture-failed-${exitCode}`);
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  if (
    report.status !== "passed" ||
    report.provider_called !== true ||
    report.mcp_status !== "passed" ||
    report.receipt_verified !== true ||
    report.evidence_status !== "provider-and-mcp-verified"
  ) {
    throw new Error("live-closure-fixture-evidence-incomplete");
  }
  await writeFile(stableReportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}

try {
  await main();
  completed = true;
  console.log(JSON.stringify({ status: "passed", runtime, report: stableReportPath }, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : "live-closure-fixture-failed");
  process.exitCode = 1;
} finally {
  for (const child of childProcesses) {
    if (!child.killed) child.kill();
  }
  if (completed) {
    await rm(runtime, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  } else {
    console.error(`闭环失败日志保留于 ${runtime}`);
  }
}
