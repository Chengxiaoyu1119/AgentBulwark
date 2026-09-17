import { createHash } from "node:crypto";
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
const providerOnlyReportPath = resolve(runtime, "provider-only-last-run.json");
const providerToolReportPath = resolve(runtime, "provider-tool-last-run.json");
const unconfiguredProviderReportPath = resolve(runtime, "provider-unconfigured-last-run.json");
const mcpTracePath = resolve(runtime, "mcp-upstream.jsonl");
const fixtureAgentId = "live-closure-agent";
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

async function runSmoke(env) {
  const smoke = spawn(process.execPath, [resolve(repoRoot, "scripts/live-closure-smoke.mjs")], {
    cwd: repoRoot,
    env: childEnvironment(env),
    stdio: "inherit",
    windowsHide: true,
  });
  const exitCode = await new Promise((resolvePromise, reject) => {
    smoke.once("error", reject);
    smoke.once("exit", (code, signal) => resolvePromise(signal ? 1 : code ?? 1));
  });
  if (exitCode !== 0) throw new Error(`live-closure-fixture-failed-${exitCode}`);
}

async function fixtureProviderRequestCount() {
  const response = await fetch(`http://127.0.0.1:${providerPort}/_fixture/stats`);
  const body = await response.json();
  return Number(body.request_count || 0);
}

function tamperReceipt(runtimePath, auditId) {
  const script = [
    "import json, sqlite3, sys",
    "db_path, target_audit_id = sys.argv[1], sys.argv[2]",
    "connection = sqlite3.connect(db_path)",
    "row = connection.execute(\"SELECT id, payload FROM runtime_events WHERE event_type = 'execution-receipt' AND json_extract(payload, '$.audit_id') = ? ORDER BY id DESC LIMIT 1\", (target_audit_id,)).fetchone()",
    "assert row is not None, 'receipt-not-found'",
    "payload = json.loads(row[1])",
    "payload['receipt_hash'] = '0' * 64",
    "connection.execute('UPDATE runtime_events SET payload = ? WHERE id = ?', (json.dumps(payload, ensure_ascii=False, separators=(',', ':')), row[0]))",
    "connection.commit()",
  ].join("; ");
  const result = spawnSync(
    python,
    [...pythonArgs, "-c", script, resolve(runtimePath, "agent_supervisor.sqlite3"), auditId],
    { cwd: repoRoot, env: childEnvironment({ AGENT_SUPERVISOR_RUNTIME_DIR: runtimePath }), encoding: "utf8", windowsHide: true },
  );
  if (result.error || result.status !== 0) throw new Error("fixture-receipt-tamper-failed");
}

async function verifyTamperedReceipt(runtimePath, report) {
  const auditId = String(report.mcp_audit_id || "").trim();
  if (!auditId) throw new Error("fixture-receipt-audit-missing");
  tamperReceipt(runtimePath, auditId);
  const response = await fetch(`http://127.0.0.1:${apiPort}/api/evidence/${encodeURIComponent(auditId)}/verify`, {
    method: "POST",
    headers: { Authorization: "Bearer live-admin-token" },
  });
  const body = await response.json();
  const invalid =
    response.ok &&
    body.evidence_status === "invalid" &&
    body.verification?.receipt_integrity_valid === false &&
    body.verification?.valid === false;
  report.scenarios.push({
    id: "receipt-tamper",
    category: "attack",
    expected_result: "篡改执行回执必须标记 invalid，不得自动完成或重放。",
    actual_decision: "invalid",
    provider_called: false,
    tool_reached_upstream: null,
    side_effect_observed: false,
    execution_status: "invalid",
    execution_evidence: "invalid",
    receipt_verified: false,
    evidence_verified: false,
    local_latency_ms: null,
    status: invalid ? "passed" : "failed",
    reason: invalid ? "证据接口识别回执 Hash 篡改；重放阻断由回执单测覆盖。" : "证据接口没有识别回执 Hash 篡改。",
  });
  report.metrics = {
    ...report.metrics,
    scenario_count: Number(report.metrics?.scenario_count || 0) + 1,
    passed_count: Number(report.metrics?.passed_count || 0) + (invalid ? 1 : 0),
    failed_count: Number(report.metrics?.failed_count || 0) + (invalid ? 0 : 1),
    attack_scenario_count: Number(report.metrics?.attack_scenario_count || 0) + 1,
    attack_blocked_count: Number(report.metrics?.attack_blocked_count || 0) + (invalid ? 1 : 0),
  };
  if (!invalid) throw new Error("fixture-receipt-tamper-not-invalid");
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
    body: JSON.stringify({ agent_id: fixtureAgentId, display_name: "Live closure MCP fixture" }),
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
      agent_tool_allowlists: { [fixtureAgentId]: ["file.read", "mail.send"] },
      agent_model_allowlists: { [fixtureAgentId]: ["fixture-model"] },
      agent_api_allowlists: { [fixtureAgentId]: [] },
      agent_context_allowlists: {
        [fixtureAgentId]: { resources: [], resource_templates: [], prompts: [] },
      },
      task_profiles: {
        "live-read-public": {
          agent_id: fixtureAgentId,
          name: "Live public read",
          enabled: true,
          allowed_capabilities: ["file.read"],
          allowed_file_paths: ["public/*"],
          allowed_api_origins: [],
          allowed_email_domains: [],
          require_approval: false,
          expires_at: "",
        },
        "live-approval-mail": {
          agent_id: fixtureAgentId,
          name: "Live approval mail",
          enabled: true,
          allowed_capabilities: ["mail.send"],
          allowed_file_paths: [],
          allowed_api_origins: [],
          allowed_email_domains: ["example.net"],
          require_approval: true,
          expires_at: "",
        },
        "live-other-agent": {
          agent_id: "other-fixture-agent",
          name: "Live other Agent",
          enabled: true,
          allowed_capabilities: [],
          allowed_file_paths: [],
          allowed_api_origins: [],
          allowed_email_domains: [],
          require_approval: false,
          expires_at: "",
        },
        "live-expired": {
          agent_id: fixtureAgentId,
          name: "Live expired task",
          enabled: true,
          allowed_capabilities: ["file.read"],
          allowed_file_paths: ["public/*"],
          allowed_api_origins: [],
          allowed_email_domains: [],
          require_approval: false,
          expires_at: "2020-01-01T00:00:00+00:00",
        },
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
    DEEPSEEK_API_KEY: "",
    TARGET_DEEPSEEK_API_KEY: "",
    ZHIPU_API_KEY: "",
    TARGET_ZHIPU_API_KEY: "",
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
    MCP_ECHO_EXTRA_TOOL: "1",
    MCP_ECHO_POISON_TOOL: "1",
    MCP_ECHO_TRACE: mcpTracePath,
  }, "api.log");

  await waitForApi();
  const mcpToken = await registerMcpFixtureAgent();
  const agentNamespace = createHash("sha256").update(fixtureAgentId, "utf8").digest("hex").slice(0, 32);
  const workspace = resolve(runtime, "agents", agentNamespace, "workspace", "public");
  await mkdir(workspace, { recursive: true });
  await writeFile(resolve(workspace, "项目说明.md"), "受控运行时 fixture：只读文件用于服务端执行回执验证。\n", "utf8");
  const smokeBaseEnvironment = {
    AGENT_SUPERVISOR_LIVE_SMOKE: "true",
    AGENT_SUPERVISOR_LIVE_BASE_URL: `http://127.0.0.1:${apiPort}`,
    AGENT_SUPERVISOR_LIVE_OPERATOR_TOKEN: "live-admin-token",
  };

  await runSmoke({
    ...smokeBaseEnvironment,
    AGENT_SUPERVISOR_LIVE_SCOPE: "provider",
    AGENT_SUPERVISOR_LIVE_PROVIDER_ID: "openai-compatible",
    AGENT_SUPERVISOR_LIVE_FIXTURE_MATRIX: "",
    AGENT_SUPERVISOR_MCP_LIVE_PROBE_JSON: "",
    AGENT_SUPERVISOR_LIVE_REPORT_PATH: providerOnlyReportPath,
  });
  const providerOnlyReport = JSON.parse(await readFile(providerOnlyReportPath, "utf8"));
  if (
    providerOnlyReport.status !== "passed" ||
    providerOnlyReport.validation_scope !== "provider" ||
    providerOnlyReport.provider_id !== "openai-compatible" ||
    providerOnlyReport.provider_runs?.length !== 3 ||
    providerOnlyReport.metrics?.end_to_end_latency_ms?.sample_count !== 3 ||
    providerOnlyReport.mcp_status !== "not_run" ||
    providerOnlyReport.mcp_reason !== "provider-scope"
  ) {
    throw new Error("live-closure-provider-scope-evidence-incomplete");
  }

  await runSmoke({
    ...smokeBaseEnvironment,
    AGENT_SUPERVISOR_LIVE_SCOPE: "provider-tool",
    AGENT_SUPERVISOR_LIVE_PROVIDER_ID: "openai-compatible",
    AGENT_SUPERVISOR_LIVE_AGENT_TOKEN: mcpToken,
    AGENT_SUPERVISOR_LIVE_AGENT_ID: fixtureAgentId,
    AGENT_SUPERVISOR_LIVE_TASK_ID: "live-read-public",
    AGENT_SUPERVISOR_LIVE_FIXTURE_MATRIX: "",
    AGENT_SUPERVISOR_MCP_LIVE_PROBE_JSON: "",
    AGENT_SUPERVISOR_LIVE_REPORT_PATH: providerToolReportPath,
  });
  const providerToolReport = JSON.parse(await readFile(providerToolReportPath, "utf8"));
  if (
    providerToolReport.status !== "passed" ||
    providerToolReport.validation_scope !== "provider-tool" ||
    providerToolReport.provider_id !== "openai-compatible" ||
    providerToolReport.tool_call_status !== "passed" ||
    providerToolReport.managed_execution_status !== "completed" ||
    providerToolReport.integrity_mode !== "hmac-signed" ||
    providerToolReport.mcp_status !== "not_run" ||
    providerToolReport.mcp_reason !== "provider-tool-scope" ||
    !providerToolReport.scenarios?.some((item) => item?.id === "managed-server-execution" && item.status === "passed")
  ) {
    throw new Error("live-closure-provider-tool-evidence-incomplete");
  }

  const providerRequestsBefore = await fixtureProviderRequestCount();
  await runSmoke({
    ...smokeBaseEnvironment,
    AGENT_SUPERVISOR_LIVE_SCOPE: "provider",
    AGENT_SUPERVISOR_LIVE_PROVIDER_ID: "deepseek",
    AGENT_SUPERVISOR_LIVE_FIXTURE_MATRIX: "",
    AGENT_SUPERVISOR_MCP_LIVE_PROBE_JSON: "",
    AGENT_SUPERVISOR_LIVE_REPORT_PATH: unconfiguredProviderReportPath,
  });
  const unconfiguredProviderReport = JSON.parse(await readFile(unconfiguredProviderReportPath, "utf8"));
  if (
    unconfiguredProviderReport.status !== "not_run" ||
    unconfiguredProviderReport.validation_scope !== "provider" ||
    unconfiguredProviderReport.provider_id !== "deepseek" ||
    unconfiguredProviderReport.provider_called !== false ||
    unconfiguredProviderReport.provider_runs?.length !== 0 ||
    unconfiguredProviderReport.mcp_reason !== "provider-scope" ||
    (await fixtureProviderRequestCount()) !== providerRequestsBefore
  ) {
    throw new Error("live-closure-provider-selection-not-blocked");
  }

  await runSmoke({
    ...smokeBaseEnvironment,
    AGENT_SUPERVISOR_LIVE_SCOPE: "full",
    AGENT_SUPERVISOR_LIVE_PROVIDER_ID: "",
    AGENT_SUPERVISOR_LIVE_MCP_TOKEN: mcpToken,
    AGENT_SUPERVISOR_LIVE_AGENT_TOKEN: mcpToken,
    AGENT_SUPERVISOR_LIVE_AGENT_ID: fixtureAgentId,
    AGENT_SUPERVISOR_LIVE_FIXTURE_MATRIX: "true",
    AGENT_SUPERVISOR_MCP_LIVE_TRACE_PATH: mcpTracePath,
    AGENT_SUPERVISOR_MCP_LIVE_PROBE_JSON: JSON.stringify({
      read_only: true,
      tool: "file.read",
      arguments: { path: "public/project-overview" },
    }),
    AGENT_SUPERVISOR_LIVE_REPORT_PATH: reportPath,
  });
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  await verifyTamperedReceipt(runtime, report);
  const requiredScenarioIds = [
    "normal-provider-request",
    "managed-server-execution",
    "mcp-read",
    "direct-prompt-injection",
    "untrusted-context-injection",
    "tool-definition-poisoning",
    "mcp-tool-description-poisoning",
    "mcp-tool-result-injection",
    "unregistered-capability",
    "parameter-out-of-scope",
    "approval-replay",
    "task-normal",
    "task-missing",
    "task-wrong-agent",
    "task-target-out-of-scope",
    "task-expired",
    "task-approval-policy-change",
    "receipt-tamper",
    "provider-failure",
  ];
  const scenarioIds = new Set(Array.isArray(report.scenarios) ? report.scenarios.map((item) => item?.id) : []);
  if (
    report.status !== "passed" ||
    report.provider_called !== true ||
    report.mcp_status !== "passed" ||
    report.receipt_verified !== true ||
    report.evidence_status !== "provider-and-mcp-verified" ||
    requiredScenarioIds.some((id) => !scenarioIds.has(id)) ||
    report.metrics?.failed_count !== 0
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
