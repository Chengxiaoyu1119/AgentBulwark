---
id: intro
title: 概览
slug: /
---

# AgentBulwark · 智垒

AgentBulwark（智垒）是一个本地优先的 **AI Agent 防火墙**。它把模型请求、外部上下文、模型输出和工具行动放在同一条运行时防护链中，在产生副作用前完成策略判断，并保留可核验的 Trace、执行回执与证据。

## 防护链路

```text
Agent
  -> OpenAI Gateway
  -> Request / Context Guard
  -> Provider
  -> Model Response / Tool Call
  -> Policy Decision
  -> MCP Gateway
  -> Execution Receipt
  -> Hash / HMAC Evidence
```

## 核心能力

| 能力 | 说明 |
| --- | --- |
| OpenAI 兼容网关 | 支持 `/v1/chat/completions` 流式与非流式请求，以及 `/v1/responses` 非流式请求 |
| MCP Gateway | 连接 stdio 与 Streamable HTTP Server，按 Agent 和 Session 隔离会话 |
| 运行时策略 | 对身份、工具、Schema、参数、目标和上下文执行 `ALLOW`、`DENY`、`ASK`、`ISOLATE` 判断 |
| 一次性审批 | 审批绑定参数 Hash、Agent、Session、策略版本、目标和有效期，重复或篡改立即失效 |
| Provider 出口 | 固定主机、协议、端口和路径，凭证只由后端读取 |
| 可验证证据 | Trace、请求/响应 Hash、执行回执和 HMAC 证据关联同一条请求链 |
| 本地控制台 | 在防护、事件和设置页面查看实时行动、审批、接入和证据状态 |

## 一次行动如何被处置

1. 网关为请求绑定请求链标识，并记录 Agent、Session 与 Provider 路由。
2. 输入和外部上下文接受风险检查；不满足策略时，请求不会到达 Provider。
3. Provider 响应被标准化，未知工具、漂移的 Schema 和畸形参数不能直接进入执行阶段。
4. 策略输出四态决策；需要人工判断时生成带精确参数 Hash 的审批。
5. MCP Gateway 再次检查会话、工具注册、Schema、目标和权限，允许后才执行。
6. 服务端写入执行回执，并把 Trace、Hash、HMAC 和状态绑定为可离线核验的证据链。

## 运行界面

| 页面 | 用途 |
| --- | --- |
| 防护 | 查看服务状态、策略模式和最近行动 |
| 事件 | 按请求链查看模型请求、Tool Call、阻断、审批和执行结果 |
| 设置 | 管理 Provider、MCP Server、Agent、Session、策略和凭证引用 |

## 仓库应用

```text
apps/api/agent_supervisor/  FastAPI 服务与运行内核
apps/api/tests/             协议夹具、策略测试和闭环验证
apps/console/               React + Vite 操作控制台
apps/www/                   产品介绍页
apps/docs/                  本文档站
docs/                       产品、工程和研究资料
legacy/                     只读历史资料
scripts/                    启动、维护和质量检查脚本
```

## 从这里开始

- 第一次本地运行：阅读 [快速开始](./quickstart)。
- 了解数据流和信任边界：阅读 [运行架构](./architecture)。
- 接入 OpenAI 兼容模型或 MCP：阅读 [API 地图](./api)。
- 配置四态策略和审批：阅读 [防护策略](./policies)。
- 检查 Trace、回执与证据：阅读 [证据与回执](./reports)。
