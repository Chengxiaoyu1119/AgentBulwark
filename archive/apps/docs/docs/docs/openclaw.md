---
id: openclaw
title: 外部 Agent 接入
---

# 外部 Agent 接入

智安哨可以作为外部 Agent 的工具调用监督服务。接入方在工具执行前发送事件，监督服务返回决策和审计信息。

虽然文档中保留 OpenClaw 兼容接口，接入模型并不限定于 OpenClaw。任何能在工具执行前拿到工具名、参数和上下文的 Agent 框架，都可以按同一事件格式接入。

## 接入模式

| 模式 | 说明 |
| --- | --- |
| 事件转发 | 外部 Agent 在工具执行前调用 `/api/runtime/evaluate` |
| OpenClaw 兼容 | 使用 `/api/integrations/openclaw/events`，返回 OpenClaw 风格字段 |
| 插件包生成 | 生成本地 OpenClaw native plugin 包和验证报告 |
| 最小演示 | 使用仓库内样例事件验证监督服务可用 |

## 事件入口

通用入口：

```text
POST /api/runtime/evaluate
```

OpenClaw 兼容入口：

```text
POST /api/integrations/openclaw/events
```

## 最小事件

```json
{
  "conversation_id": "demo-conv",
  "agent_id": "external-agent-1",
  "agent_role": "assistant",
  "tool_call": {
    "tool": "file.read",
    "arguments": {
      "path": "confidential/customers.csv"
    }
  },
  "guard_enabled": true,
  "execute_in_sandbox": false
}
```

## 返回结果

典型返回字段包括：

| 字段 | 说明 |
| --- | --- |
| `decision` | `允许`、`拒绝`、`询问` 或 `隔离` |
| `policy_id` | 命中的主要策略 |
| `reason` | 决策原因 |
| `recommendation` | 建议处理方式 |
| `risk_score` | 风险分 |
| `anomaly_score` | 异常分 |
| `audit_log` | 审计记录，包含 hash 字段 |

## CLI 演示

运行 OpenClaw 风格事件批量演示：

```powershell
npm run cli -- demo-external
```

运行最小外部 Agent 工具调度演示：

```powershell
npm run cli -- external-agent-demo
```

生成插件包：

```powershell
npm run cli -- openclaw-plugin --output apps/api/sandbox/reports
```

生成插件包验证报告：

```powershell
npm run cli -- openclaw-plugin-validate --output apps/api/sandbox/reports
```

验证会实际执行生成后的插件代码，检查 `before_tool_call`/`after_tool_call` 注册、Bearer Token、默认不发送 `risk_hint`、风险阻断和正常放行。该检查属于插件契约端到端验收；真实 OpenClaw 加载状态另由 runtime inspect 证明。

如果当前环境安装了 OpenClaw CLI，可以追加 `--inspect-runtime` 做 runtime inspect：

```powershell
npm run cli -- openclaw-plugin-validate --inspect-runtime --output apps/api/sandbox/reports
```

## 接入注意事项

- 监督服务默认只给决策，不替外部系统执行真实工具。
- `execute_in_sandbox=true` 只会调用本地沙箱工具。
- 外部 Agent 应在执行真实工具前等待监督结果。
- 插件支持 `apiToken` 配置或 `AGENT_SUPERVISOR_API_TOKEN` 环境变量；正式部署开启后端鉴权时必须配置。
- `emitRiskHint` 默认是 `false`，评测时由监督器依据工具名、参数、上下文和历史行为独立判定。
- `询问` 决策应进入人工复核流程，不应自动放行。
- 工具返回内容应作为低信任数据处理，不能覆盖系统规则或授权判断。
