---
id: quickstart
title: 快速开始
---

# 快速开始

AgentBulwark 是单机本地项目。第一次运行只需要准备 Node.js、Python 和项目依赖，然后分别启动 API、控制台、官网或文档站。

## 环境要求

| 依赖 | 版本 | 用途 |
| --- | --- | --- |
| Node.js | 22 或更高 | 运行 React、Vite、Docusaurus 和启动脚本 |
| npm | 9.6.5 或更高 | 安装 JavaScript 依赖 |
| Python | 3.10 或更高 | 运行 FastAPI 和后端测试 |

## 安装

```powershell
git clone https://github.com/Chengxiaoyu1119/AgentBulwark.git
cd AgentBulwark
npm run install:all
Copy-Item .env.example .env
```

Provider、MCP 和鉴权配置只放在后端环境或系统密钥环中。浏览器只接收脱敏后的状态和引用。

## 启动 API

```powershell
npm run api
```

默认地址：

```text
http://127.0.0.1:8012
```

健康检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8012/api/health
```

## 启动控制台

在另一个终端运行：

```powershell
npm run console:dev
```

打开 `http://127.0.0.1:5178`。控制台提供防护、事件和设置三个主要工作区。

## 启动官网与文档站

```powershell
npm run www:dev
npm run docs:dev
```

官网地址为 `http://127.0.0.1:4321`，文档站地址为 `http://127.0.0.1:3000`。

生产或托管环境请通过以下变量设置实际地址：

```text
VITE_AGENT_SUPERVISOR_CONSOLE_URL
VITE_AGENT_SUPERVISOR_DOCS_URL
AGENT_SUPERVISOR_WWW_URL
AGENT_SUPERVISOR_DOCS_SITE_URL
```

## 发送第一条请求

将 Agent 的 OpenAI Base URL 指向 `http://127.0.0.1:8012/v1`，使用已登记的模型和 Provider。请求会先经过输入检查和固定出口，模型返回的 Tool Call 还要经过策略与 MCP 闸门。

## 验证

```powershell
npm run console:test
npm run api:test
npm run www:verify
npm run docs:build
npm run verify:live:fixture
```

`verify:live:fixture` 使用仓库内 HTTP Provider 和 MCP stdio 子进程验证完整闭环；`verify:live` 默认返回 `status=not_run`，只有显式配置 `AGENT_SUPERVISOR_LIVE_SMOKE=true` 才访问外部 Provider。

## 故障定位

| 现象 | 检查 |
| --- | --- |
| 页面可打开但没有数据 | 访问 `/api/health`，确认 API 进程运行 |
| Provider 请求被拒绝 | 检查 Provider 路由、模型登记、身份和策略版本 |
| Tool Call 没有执行 | 在事件页查看决策、审批、MCP 会话和执行回执 |
| 文档构建失败 | 运行 `npm --prefix apps/docs run clear` 后重新执行 `npm run docs:build` |
