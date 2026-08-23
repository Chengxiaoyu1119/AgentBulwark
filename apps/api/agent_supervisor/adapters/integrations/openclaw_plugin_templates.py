from __future__ import annotations

import json


def _openclaw_plugin_package_json() -> str:
    return json.dumps(
        {
            "name": "@agent-security-supervisor/openclaw-guard",
            "version": "0.1.0",
            "private": True,
            "type": "module",
            "description": "Agent Security Supervisor tool-call guard for OpenClaw native plugin hooks.",
            "openclaw": {
                "extensions": ["./src/index.ts"],
                "runtimeExtensions": ["./dist/index.js"],
                "compat": {
                    "pluginApi": ">=2026.3.24-beta.2",
                    "minGatewayVersion": "2026.3.24-beta.2",
                },
            },
            "peerDependencies": {
                "openclaw": "*",
            },
            "files": [
                "dist",
                "src",
                "openclaw.plugin.json",
                "README.md",
            ],
        },
        ensure_ascii=False,
        indent=2,
    )


def _openclaw_plugin_manifest(supervisor_url: str) -> str:
    return json.dumps(
        {
            "id": "agent-supervisor-openclaw-guard",
            "name": "智安哨 OpenClaw Guard",
            "description": "在 OpenClaw 工具调用前接入智安哨行为监督器，输出允许、拒绝、询问、隔离决策。",
            "version": "0.1.0",
            "hooks": ["before_tool_call", "after_tool_call"],
            "configSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "supervisorUrl": {
                        "type": "string",
                        "default": supervisor_url,
                        "description": "智安哨 OpenClaw 兼容监督接口。",
                    },
                    "apiToken": {
                        "type": "string",
                        "default": "",
                        "description": "智安哨执行 Token；优先使用 AGENT_SUPERVISOR_AGENT_TOKEN 或 AGENT_SUPERVISOR_API_TOKEN_EXECUTOR。",
                    },
                    "timeoutMs": {
                        "type": "integer",
                        "default": 5000,
                        "minimum": 1000,
                        "maximum": 60000,
                    },
                    "failClosedDecision": {
                        "type": "string",
                        "enum": ["询问", "拒绝"],
                        "default": "询问",
                    },
                    "inspectToolResults": {
                        "type": "boolean",
                        "default": True,
                    },
                    "emitRiskHint": {
                        "type": "boolean",
                        "default": False,
                        "description": "是否发送插件推断的风险提示；盲测和正式部署默认关闭，避免自标注。",
                    },
                },
            },
        },
        ensure_ascii=False,
        indent=2,
    )


def _openclaw_plugin_source(supervisor_url: str) -> str:
    return _openclaw_plugin_runtime(supervisor_url)


def _openclaw_plugin_runtime(supervisor_url: str) -> str:
    return f"""
import {{ definePluginEntry }} from "openclaw/plugin-sdk/plugin-entry";

const DEFAULT_SUPERVISOR_URL = "{supervisor_url}";
const DEFAULT_TIMEOUT_MS = 5_000;

export default definePluginEntry({{
  id: "agent-supervisor-openclaw-guard",
  name: "智安哨 OpenClaw Guard",
  description: "Intercepts OpenClaw tool calls and asks Agent Security Supervisor for allow/deny/approval decisions.",
  configSchema: {{
    type: "object",
    additionalProperties: false,
    properties: {{
      supervisorUrl: {{ type: "string", default: DEFAULT_SUPERVISOR_URL }},
      apiToken: {{ type: "string", default: "" }},
      timeoutMs: {{ type: "integer", default: DEFAULT_TIMEOUT_MS, minimum: 1000, maximum: 60000 }},
      failClosedDecision: {{ type: "string", enum: ["询问", "拒绝"], default: "询问" }},
      inspectToolResults: {{ type: "boolean", default: true }},
      emitRiskHint: {{ type: "boolean", default: false }}
    }}
  }},
  register(api) {{
    api.on(
      "before_tool_call",
      async (event) => {{
        const config = getConfig(event);
        const supervisorResult = await evaluateToolCall(event, config, "before_tool_call");
        return toOpenClawBeforeToolDecision(supervisorResult, event, config);
      }},
      {{ priority: 100, timeoutMs: DEFAULT_TIMEOUT_MS }},
    );

    api.on(
      "after_tool_call",
      async (event) => {{
        const config = getConfig(event);
        if (config.inspectToolResults === false) {{
          return;
        }}
        await observeToolResult(event, config);
      }},
      {{ priority: 10, timeoutMs: DEFAULT_TIMEOUT_MS }},
    );
  }},
}});

function getConfig(event) {{
  const pluginConfig = event?.context?.pluginConfig ?? {{}};
  return {{
    supervisorUrl: String(
      pluginConfig.supervisorUrl ??
        process.env.AGENT_SUPERVISOR_URL ??
        DEFAULT_SUPERVISOR_URL,
    ),
    apiToken: String(
      pluginConfig.apiToken ??
      process.env.AGENT_SUPERVISOR_AGENT_TOKEN ??
      process.env.AGENT_SUPERVISOR_API_TOKEN_EXECUTOR ??
      ""
    ),
    timeoutMs: Number(pluginConfig.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    failClosedDecision: String(pluginConfig.failClosedDecision ?? "询问"),
    inspectToolResults: pluginConfig.inspectToolResults !== false,
    emitRiskHint: pluginConfig.emitRiskHint === true,
  }};
}}

async function evaluateToolCall(event, config, phase) {{
  const payload = buildSupervisorPayload(event, phase, config);
  try {{
    return await postJson(config.supervisorUrl, payload, config.timeoutMs, config.apiToken);
  }} catch (error) {{
    return {{
      decision: config.failClosedDecision === "拒绝" ? "拒绝" : "询问",
      risk_level: "high",
      policy_id: "openclaw-plugin-supervisor-unavailable",
      reason: `智安哨监督器不可用，按 fail-closed 策略处理：${{error instanceof Error ? error.message : String(error)}}`,
      recommendation: "暂停自动工具调用，确认智安哨 API 服务是否运行。",
    }};
  }}
}}

async function observeToolResult(event, config) {{
  const payload = buildSupervisorPayload(event, "after_tool_call", config);
  payload.model_output = stringifyBounded(event?.result ?? event?.error ?? "", 2000);
  payload.tool_call.observed_result = {{
    ok: !event?.error,
    duration_ms: event?.durationMs ?? event?.duration_ms ?? null,
  }};
  try {{
    await postJson(config.supervisorUrl, payload, Math.min(config.timeoutMs, 3000), config.apiToken);
  }} catch {{
    // after_tool_call is observation-only. Do not change the OpenClaw run if audit export fails.
  }}
}}

function buildSupervisorPayload(event, phase, config) {{
  const toolName = String(event?.toolName ?? event?.tool_name ?? event?.name ?? "unknown");
  const params = event?.params ?? event?.arguments ?? event?.input ?? {{}};
  const context = event?.context ?? {{}};
  return {{
    conversation_id: String(context.sessionKey ?? event?.sessionId ?? event?.conversationId ?? "openclaw-session"),
    agent_id: String(context.agentId ?? event?.agentId ?? "openclaw-agent"),
    agent_role: String(context.agentRole ?? event?.agentRole ?? "executor"),
    source_app: "OpenClaw",
    model_input: stringifyBounded(event?.prompt ?? event?.modelInput ?? event?.inputText ?? "", 2000),
    model_output: stringifyBounded(event?.modelOutput ?? event?.assistantMessage ?? "", 2000),
    tool_call: {{
      tool: normalizeTool(toolName),
      arguments: params && typeof params === "object" ? params : {{ value: params }},
      ...(config.emitRiskHint ? {{ risk_hint: inferRiskHint(toolName, params) }} : {{}}),
      openclaw_tool_name: toolName,
      openclaw_phase: phase,
      openclaw_run_id: context.runId ?? event?.runId ?? null,
    }},
    context_sources: ["openclaw", "plugin", phase],
    guard_enabled: true,
    execute_in_sandbox: false,
  }};
}}

function toOpenClawBeforeToolDecision(result, event, config) {{
  const decision = String(result?.decision ?? "询问");
  if (decision === "允许") {{
    return undefined;
  }}
  const reason = formatReason(result);
  // F1 强制阻断：拒绝和隔离都必须 100% 不执行，禁止人工审批放行
  if (decision === "拒绝" || decision === "隔离") {{
    return {{
      block: true,
      blockReason: reason,
      metadata: buildDecisionMetadata(result),
    }};
  }}
  // 询问：暂停工具调用，等待人工确认（人工可选择放行或拒绝）
  return {{
    requireApproval: {{
      title: "确认 OpenClaw 工具调用",
      description: reason,
      severity: "info",
      timeoutMs: 60_000,
      timeoutBehavior: "deny",
      metadata: buildDecisionMetadata(result),
    }},
  }};
}}

function buildDecisionMetadata(result) {{
  return {{
    source: "agent-security-supervisor",
    run_id: result?.run_id,
    audit_id: result?.audit_id,
    policy_id: result?.policy_id,
    risk_level: result?.risk_level,
    risk_score: result?.risk_score,
    anomaly_score: result?.anomaly_score,
  }};
}}

function formatReason(result) {{
  const policy = result?.policy_id ? `策略 ${{result.policy_id}}` : "智安哨策略";
  const score = Number.isFinite(Number(result?.risk_score)) ? `，风险分 ${{result.risk_score}}` : "";
  const anomaly = Number.isFinite(Number(result?.anomaly_score)) ? `，异常分 ${{result.anomaly_score}}` : "";
  const reason = result?.reason ? String(result.reason) : "工具调用需要安全复核。";
  const recommendation = result?.recommendation ? ` 建议：${{result.recommendation}}` : "";
  return `${{policy}}${{score}}${{anomaly}}：${{reason}}${{recommendation}}`;
}}

async function postJson(url, payload, timeoutMs, apiToken) {{
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {{
    const response = await fetch(url, {{
      method: "POST",
      headers: {{
        "Content-Type": "application/json",
        ...(apiToken ? {{ Authorization: `Bearer ${{apiToken}}` }} : {{}}),
      }},
      body: JSON.stringify(payload),
      signal: controller.signal,
    }});
    if (!response.ok) {{
      throw new Error(`HTTP ${{response.status}} ${{await response.text()}}`);
    }}
    return await response.json();
  }} finally {{
    clearTimeout(timer);
  }}
}}

function normalizeTool(toolName) {{
  const lowered = String(toolName).toLowerCase();
  if ((lowered.includes("file") || lowered.includes("fs")) && lowered.includes("read")) return "file.read";
  if ((lowered.includes("file") || lowered.includes("fs")) && lowered.includes("write")) return "file.write";
  if (lowered.includes("mail") || lowered.includes("email") || lowered.includes("send_message")) return "mail.send";
  if (lowered.includes("exec") || lowered.includes("shell") || lowered.includes("terminal") || lowered.includes("bash") || lowered.includes("powershell")) return "code.run";
  if (lowered.includes("memory") && lowered.includes("write")) return "memory.write";
  if (lowered.includes("memory") && lowered.includes("read")) return "memory.read";
  if (lowered.includes("env")) return "env.read";
  if (lowered.includes("api") || lowered.includes("http") || lowered.includes("fetch") || lowered.includes("web") || lowered.includes("browser")) return "api.call";
  return toolName;
}}

function inferRiskHint(toolName, params) {{
  const lowered = `${{toolName}} ${{stringifyBounded(params, 1000)}}`.toLowerCase();
  if (lowered.includes("confidential") || lowered.includes("secret") || lowered.includes("token")) return "sensitive_file";
  if (lowered.includes("external") || lowered.includes("@") || lowered.includes("http://") || lowered.includes("https://")) return "external_target";
  if (lowered.includes("bulk") || lowered.includes("export") || lowered.includes("all")) return "bulk_export";
  if (lowered.includes("rm ") || lowered.includes("del ") || lowered.includes("curl ") || lowered.includes("wget ")) return "dangerous_command";
  return "openclaw_tool_call";
}}

function stringifyBounded(value, maxLength) {{
  let text;
  try {{
    text = typeof value === "string" ? value : JSON.stringify(value);
  }} catch {{
    text = String(value);
  }}
  if (!text) return "";
  return text.length > maxLength ? `${{text.slice(0, maxLength)}}...` : text;
}}
""".strip()


def _openclaw_plugin_readme(supervisor_url: str) -> str:
    return f"""
# 智安哨 OpenClaw Guard

这是一个 OpenClaw native plugin。它在 OpenClaw 工具执行前注册 `before_tool_call`，把工具名、参数、上下文和运行标识发送到智安哨监督器，再把智安哨的 `允许 / 拒绝 / 询问 / 隔离` 映射为 OpenClaw 的放行、阻断或人工审批。

## 安装

```powershell
openclaw plugins install -l ./agent-supervisor-openclaw-guard
openclaw plugins inspect agent-supervisor-openclaw-guard --runtime --json
openclaw plugins enable agent-supervisor-openclaw-guard
```

## 配置

默认监督接口：

```text
{supervisor_url}
```

也可以通过 OpenClaw 插件配置或环境变量覆盖：

```powershell
$env:AGENT_SUPERVISOR_URL="http://127.0.0.1:8012/api/integrations/openclaw/events"
```

## 验收

1. 启动智安哨后端：`npm run api`
2. 安装并启用本插件。
3. 让 OpenClaw 执行文件读取、邮件发送、API 调用或代码执行工具。
4. 在智安哨页面查看审计日志、告警、策略命中、risk_score、anomaly_score 和 audit_hash。

## 安全默认值

- 智安哨不可用时 fail-closed，默认进入人工确认。
- `拒绝` 和 `隔离` 强制映射为 OpenClaw block，工具调用 100% 不执行，人工无法放行。
- `询问` 映射为 OpenClaw requireApproval，暂停等待人工确认，超时自动拒绝。
- `允许` 放行工具调用。
- `after_tool_call` 只做审计观察，不改变 OpenClaw 运行结果。
""".strip()
