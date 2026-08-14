---
id: quickstart
title: 快速开始
---

# 快速开始

本页说明如何在本机启动 API、控制台、官网和文档站。第一次运行建议先启动 API 和控制台，确认核心链路可用后再启动其他站点。

## 环境要求

| 依赖 | 版本 | 用途 |
| --- | --- | --- |
| Node.js | 22 或更高 | 运行控制台、官网、文档站和 Node CLI 包装脚本 |
| npm | 9.6.5 或更高 | 安装前端和文档站依赖 |
| Python | 3.10 或更高 | 运行 FastAPI 服务和后端 CLI |

## 安装依赖

在仓库根目录运行：

```powershell
npm run install:all
```

这个命令会安装三个前端应用的依赖，并安装后端开发依赖。只想运行文档站时，也可以单独安装：

```powershell
npm --prefix apps/docs ci
```

## 启动 API

```powershell
npm run api
```

默认地址：

```text
http://127.0.0.1:8012
```

健康检查：

```text
http://127.0.0.1:8012/api/health
```

`npm run api` 是本地开发入口，会设置 `AGENT_SUPERVISOR_AUTH_DISABLED=true`，方便第一次运行。直接部署时也可以继续关闭 API 鉴权；这只影响后端接口访问校验，不影响 DeepSeek、智谱等大模型调用。

## 启动控制台

打开第二个终端：

```powershell
npm run console:dev
```

默认地址：

```text
http://127.0.0.1:5178
```

控制台通过 Vite 代理访问 `/api`，所以本地开发时不需要手动配置后端地址。

## 启动文档站

```powershell
npm run docs:dev
```

默认地址：

```text
http://127.0.0.1:3000
```

文档站是 Docusaurus 应用，源码位于 `apps/docs`。

## 启动官网

```powershell
npm run www:dev
```

默认地址：

```text
http://127.0.0.1:4321
```

官网位于 `apps/www`，用于项目介绍；控制台和文档站分别在 `apps/console`、`apps/docs`。

## 验证一次完整链路

1. 启动 API：`npm run api`
2. 启动控制台：`npm run console:dev`
3. 打开 `http://127.0.0.1:5178`
4. 进入“攻击复现实验室”
5. 选择 `TOOL-HIJACK-001`
6. 运行一次有防护/无防护对比
7. 在“行为监督记录”查看策略命中和审计日志

## 后端未启动时的表现

控制台会使用内置样本数据展示页面。页面能打开不代表 API 在线。判断 API 是否在线，以 `/api/health` 或控制台顶部提示为准。
