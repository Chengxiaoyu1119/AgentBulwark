---
id: api
title: API 地图
---

# API 地图

AgentBulwark API 默认监听 `127.0.0.1:8012`。本地控制台通过 Vite 代理访问同一服务，外部 Agent 可以把 OpenAI Base URL 指向 `http://127.0.0.1:8012/v1`。

## 服务与运行状态

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 公共服务状态 | GET | `/api/public/status` |
| 健康检查 | GET | `/api/health` |
| 当前鉴权上下文 | GET | `/api/auth/context` |
| 运行总览 | GET | `/api/overview` |
| 模型列表 | GET | `/api/models` |
| 模型配置 | GET / PATCH | `/api/model_config` |
| 运行状态 | GET | `/api/runtime_status` |
| 观测指标 | GET | `/api/observability/metrics` |
| 审计事件 | GET | `/api/audit_logs` |
| 风险告警 | GET | `/api/alerts` |
| 实时事件流 | GET | `/api/events/stream` |

## OpenAI 兼容网关

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 模型目录 | GET | `/v1/models` |
| Chat Completions | POST | `/v1/chat/completions` |
| Responses | POST | `/v1/responses` |

`/v1/chat/completions` 支持流式和非流式响应；`/v1/responses` 当前提供非流式响应。网关会在请求进入 Provider 前绑定 Agent、Session、Provider 路由并执行输入检查，模型返回的 Tool Call 还要经过工具闸门。

## MCP Gateway

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| Gateway 信息 | GET | `/api/mcp/info` |
| MCP 消息 | POST | `/api/mcp` |
| 通知投递 | POST | `/api/mcp/notifications` |
| 工具证据 | GET | `/api/mcp/tools/evidence` |
| 上下文证据 | GET | `/api/mcp/context/evidence` |

`/api/mcp` 处理 `initialize`、`tools/list` 和 `tools/call`。网关支持 stdio 与 Streamable HTTP 上游，并用 Agent 与 Session 绑定跨请求状态。

## 策略与审批

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 策略列表 | GET | `/api/policies` |
| 更新策略 | PATCH | `/api/policies/{policy_id}` |
| 策略配置 | GET | `/api/policy_config` |
| 策略设置 | PATCH | `/api/policy_settings` |
| 策略版本 | GET | `/api/policies/versions` |
| 工具注册表 | GET | `/api/tool_registry` |
| 审批列表 | GET | `/api/approvals` |
| 审批详情 | GET | `/api/approvals/{review_id}` |
| 领取审批 | POST | `/api/approvals/{review_id}/claim` |
| 批准行动 | POST | `/api/approvals/{review_id}/approve` |
| 拒绝行动 | POST | `/api/approvals/{review_id}/deny` |
| 完成审批 | POST | `/api/approvals/{review_id}/complete` |

审批凭证绑定参数 Hash、Agent、Session、策略版本、目标、有效期和一次性消费状态。修改任一绑定字段、过期或重复提交都会失败。

## Trace 与执行回执

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| Trace 列表 | GET | `/api/gateway/traces` |
| Trace 详情 | GET | `/api/gateway/traces/{request_id}` |
| 服务端托管工具执行 | POST | `/api/gateway/tool_calls/{audit_id}/execute` |
| 回执列表 | GET | `/api/runtime/executions` |
| 回执详情 | GET | `/api/runtime/executions/{audit_id}` |
| 提交执行回执 | POST | `/api/runtime/executions/{audit_id}/complete` |

Trace、Provider 请求/响应 Hash、Tool Call、执行回执和 HMAC 证据共享请求链标识。控制台事件页以 Trace 为入口展示完整处置顺序。

## Agent 接入契约

| 能力 | 方法 | 路径 |
| --- | --- | --- |
| 接入包 JSON | GET | `/api/integrations/agents/bundle` |
| 接入包 Markdown | GET | `/api/integrations/agents/bundle.md` |
| 事件流 | GET | `/api/events/stream` |

Agent 应为每个调用提供稳定的 Agent 身份和 Session 标识；当服务端开启鉴权时，使用 `Authorization: Bearer <token>`。Provider 和 MCP 凭证由后端环境读取，不写入浏览器请求。

## 最小请求示例

```powershell
$body = @{
  model = "configured-model"
  messages = @(@{ role = "user"; content = "请总结这段公开文本" })
  stream = $false
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Uri "http://127.0.0.1:8012/v1/chat/completions" -Method Post -ContentType "application/json" -Body $body
```
