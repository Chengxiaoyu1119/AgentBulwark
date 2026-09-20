---
id: scenarios
title: 闭环验证
---

# 闭环验证

AgentBulwark 的验证场景覆盖三条真实运行契约：OpenAI 透明代理、服务端托管工具执行和独立 MCP 子进程调用。每条路径都经过策略与对应执行闸门，场景输出只记录可核验的状态、Trace、Hash 和执行回执。

## 验证对象

| 场景 | 需要确认的结果 |
| --- | --- |
| 正常文本请求 | Provider 被调用一次，响应终态清晰，Trace 可读取 |
| 请求前阻断 | 提示注入或恶意上下文在 Provider 前被拒绝，Provider 调用次数为 0 |
| 未知工具 | Provider 返回未登记 Tool Call 时停止传播，不进入任何执行路径 |
| 工具参数越权 | 参数、目标或 Schema 不符合策略时阻断，不产生工具副作用 |
| 一次性审批 | 审批绑定参数 Hash、Agent、Session 和策略版本，只能消费一次 |
| Provider 异常 | 4xx、5xx、超时、重定向和畸形响应都有明确失败终态 |
| MCP 会话隔离 | `initialize`、`tools/list`、`tools/call` 按 Agent 与 Session 隔离 |
| 证据一致性 | Trace、请求/响应 Hash、执行回执和 HMAC 指向同一请求链 |

## 使用真实夹具

确定性闭环使用仓库内的 HTTP Provider 和 MCP stdio 子进程夹具，不写入正式运营数据库：

```text
apps/api/tests/fixtures/openai_gateway_provider.py
apps/api/tests/fixtures/mcp_echo_server.py
apps/api/runtime/quality/live-closure-fixture/
```

运行完整的本地闭环验证：

```powershell
npm run verify:live:fixture
```

验证报告只保留摘要字段，例如 `request_id`、`decision`、`approval_id`、`receipt_id` 和 `evidence_status`；密钥、完整请求体和完整响应体不会写入报告。

## 结果判定

- `passed`：真实夹具完成调用，Trace 可读取，Hash 一致，回执和证据核验通过。
- `failed`：任一策略、协议、会话、回执或证据检查失败，流程以明确失败终态结束。
- `not_run`：没有显式启用外部服务烟测，或缺少所需配置；不把未执行写成通过。

## 外部服务烟测

默认不访问外部 Provider。只有显式设置 `AGENT_SUPERVISOR_LIVE_SMOKE=true` 才运行低风险文本请求；真实 MCP 工具调用还需要通过 `AGENT_SUPERVISOR_MCP_LIVE_PROBE_JSON` 提供只读探针。外部请求不自动重试，也不把凭证写入浏览器、日志或验证产物。

## 与控制台对应

打开控制台的“事件”页，可以按请求链查看输入检查、Provider 路由、Tool Call、策略命中、审批、执行回执和证据状态。验证场景应与页面显示的终态一致，不能依赖静态演示数据。
