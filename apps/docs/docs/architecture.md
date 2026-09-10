---
id: architecture
title: 运行架构
---

# 运行架构

AgentBulwark 是一个单机优先的 AI Agent 防火墙。API、控制台、官网和文档站分开运行，共享协议边界；运行数据保存在后端本地目录。

## 应用边界

```text
AgentBulwark/
├─ apps/
│  ├─ api/agent_supervisor/  FastAPI 入口、网关、策略、审批、回执
│  ├─ api/tests/             后端单元、协议和闭环测试
│  ├─ console/               React + Vite 操作控制台
│  ├─ www/                   产品介绍页
│  └─ docs/                  Docusaurus 文档站
├─ docs/                     产品、工程和研究资料
└─ scripts/                  启动、维护和质量检查脚本
```

## 请求生命周期

```text
Agent
  -> POST /v1/chat/completions 或 /v1/responses
  -> 请求身份、Session、Provider 路由绑定
  -> 输入与外部上下文检查
  -> 固定 Provider 出口
  -> 模型响应标准化
  -> Tool Call 注册、Schema、目标与策略检查
  -> ALLOW / DENY / ASK / ISOLATE
  -> POST /api/mcp
  -> MCP initialize / tools/list / tools/call
  -> 执行回执
  -> Trace、Hash、HMAC 证据
```

## 四层防护

| 层 | 检查对象 | 主要结果 |
| --- | --- | --- |
| 请求层 | Agent、Session、提示和外部上下文 | 输入不通过时不访问 Provider |
| 模型层 | 响应、工具描述和 Tool Call | 未登记工具、污染定义或畸形参数停止传播 |
| 行动层 | 工具、Schema、参数、目标、审批和 MCP 会话 | 只允许符合身份与策略的行动产生副作用 |
| 证据层 | Trace、请求/响应 Hash、执行回执和 HMAC | 状态或证据不一致时保持拒绝终态 |

## 决策优先级

策略可能同时命中多个规则，最终按以下顺序收敛：

```text
DENY > ISOLATE > ASK > ALLOW
```

审批绑定参数 Hash、Agent、Session、策略版本、目标、有效期和一次性凭证。任一绑定字段变化、过期或重复消费都会使审批失效。

## Provider 与 MCP 边界

- Provider 目标由主机、协议、端口和路径组成固定路由。
- Provider 与 MCP 凭证只从后端环境或系统密钥环读取。
- MCP stdio 上游以真实子进程运行，Streamable HTTP 通过会话标识隔离状态。
- 工具 Schema 发生漂移时需要重新审核，不能自动扩大权限。

## 运行数据

```text
apps/api/runtime/
├─ operational/  SQLite、策略、审批、审计和运行状态
├─ quality/      测试、闭环验证和安全审计产物
└─ backups/      明确创建的运行数据备份
```

这些目录属于本地运行边界，不应写入前端产物或公开日志。控制台只读取后端提供的 DTO，不直接访问 SQLite。
