---
id: faq
title: 常见问题
---

# 常见问题

## AgentBulwark 是什么

AgentBulwark（智垒）是 AI Agent 防火墙。它保护模型请求、外部上下文、模型输出和工具调用，并在 MCP 执行前给出可追踪的策略决策。

## 页面能打开是否代表 API 在线

不代表。官网和文档站可以独立运行。控制台数据是否实时，以 `http://127.0.0.1:8012/api/health` 的结果和控制台状态为准。

## 项目需要什么运行环境

Node.js 22+、npm 9.6.5+ 和 Python 3.11。本地使用 `npm run install:all` 安装控制台、官网、文档站和后端开发依赖。

## 如何接入模型

将 Agent 的 OpenAI Base URL 指向 `http://127.0.0.1:8012/v1`，并在后端配置已登记的 Provider 与模型。Provider 凭证只由后端读取。

## 为什么 Tool Call 没有执行

常见原因包括工具未登记、Schema 不匹配、Agent 或 Session 无权限、目标不在允许范围、策略要求审批，或 MCP 上游不可用。事件详情会显示决策和下一步状态。

## 审批可以重复使用吗

不能。审批绑定参数 Hash、Agent、Session、策略版本、目标、有效期和一次性 Nonce。重复消费、过期或参数变化都会失败。

## 页面中的 source status 是什么意思

`proved` 表示客户端携带一次性关联凭证并通过验证；`correlated` 表示网关根据会话、工具、参数和时间窗口完成关联；`unknown` 表示无法可靠关联。相关性不会被显示为密码学证明。

## 凭证会进入浏览器吗

不会。Provider、MCP 和 API 凭证由后端 `.env` 或进程环境管理，前端只显示脱敏状态和引用。

## 如何查看一次完整行动

打开控制台的“事件”页面，选择请求后依次查看输入检查、Provider 路由、模型响应、Tool Call、策略命中、审批、执行回执和 Hash/HMAC 证据。

## 官网、文档站和控制台如何配置地址

本地默认使用 `127.0.0.1`。托管环境通过 `VITE_AGENT_SUPERVISOR_CONSOLE_URL`、`VITE_AGENT_SUPERVISOR_DOCS_URL`、`AGENT_SUPERVISOR_WWW_URL` 和 `AGENT_SUPERVISOR_DOCS_SITE_URL` 设置实际地址。
