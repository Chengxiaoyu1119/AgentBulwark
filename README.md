# 智安哨

智安哨是一个本地优先的 Agent 行动控制网关。它把 OpenAI 兼容请求和 MCP 工具调用接入同一条可审计链路，在执行前给出策略决策，在执行后验证回执与证据。

## 当前能力

- OpenAI 兼容 `POST /v1/chat/completions`，支持流式和非流式请求。
- OpenAI `POST /v1/responses` 非流式兼容入口。
- MCP Gateway：stdio 与 Streamable HTTP。
- 工具策略：`允许`、`拒绝`、`询问`、`隔离`。
- 精确绑定的审批、一次性执行回执和 Hash/HMAC 审计链。
- Provider 固定出口校验，拒绝重定向、私网解析和未绑定目标。
- 本地 React 控制台：防护、事件、设置三页；loopback 默认免登录。
- 本地运行时只提供受限文件、记忆和外发队列操作，不执行任意命令或代码。

## 目录

```text
apps/api/agent_supervisor/  FastAPI 服务与运行内核
apps/api/tests/             后端契约、策略、网关和回执测试
apps/console/               React + Vite 控制台
docs/product/               产品定位与方案
docs/engineering/           本地启动、接入和安全配置
docs/research/              研究资料与技术审查
docs/media/                 视频、图标等不参与构建的媒体
legacy/                     只读历史资料，不被生产入口导入
scripts/                    本地启动、维护和质量检查
```

## 本地启动

首次使用先安装依赖（Python 虚拟环境是隔离项目依赖的目录）：

```powershell
npm install
python -m pip install -r apps/api/requirements-dev.txt
```

启动单机服务：

```powershell
npm run dev
```

服务默认监听 `127.0.0.1:8012`，构建后的控制台由 API 同源提供。开发时需要 Vite 热更新，可在第二个终端运行 `npm run dev:console`，然后打开 `http://127.0.0.1:5178`。

## Provider 与 MCP

复制 `.env.example` 为 `.env`，填写真实 Provider 的 API Key、固定 Base URL 和模型名。密钥只在后端环境中使用，不会写入浏览器产物。MCP stdio 命令和上游环境变量也只从后端配置读取。

常用接口：

```text
GET  /api/public/status
GET  /api/health
GET  /api/overview
POST /v1/chat/completions
POST /v1/responses
POST /api/mcp
GET  /api/events/stream
GET  /api/runtime/executions
GET  /api/gateway/traces
```

需要人工处理的行动在控制台“事件”页完成审批；完整 Hash、回执和验证结果也可通过运行时接口读取。

## 验证

```powershell
npm run console:test
npm run console:build
python -X utf8 -m unittest discover -s apps/api/tests -t . -p "test_*.py"
npm run verify:local
```

`verify:local` 只执行本机检查，不依赖外部部署环境。运行数据和临时输出统一放在 `apps/api/runtime/`，该目录已加入 Git 忽略规则。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
