# AgentBulwark / 智垒项目协作指南

本文件面向参与仓库开发的工程师和编码代理。用户可先阅读 [README.md](README.md) 了解产品与启动方式。

## 项目定位

AgentBulwark（智垒）是本地优先的 AI Agent 防火墙。OpenAI 兼容请求和 MCP 工具调用共享策略、审批、执行回执与 Hash/HMAC 证据边界。

## 代码边界

| 内容 | 路径 |
| --- | --- |
| FastAPI 入口与运行内核 | `apps/api/agent_supervisor/` |
| 后端测试与协议夹具 | `apps/api/tests/` |
| React + Vite 控制台 | `apps/console/` |
| 产品、工程和研究文档 | `docs/` |
| 启动、维护和质量脚本 | `scripts/` |
| 本地运行数据与质量产物 | `apps/api/runtime/` |

`apps/api/runtime/`、`.env`、控制台依赖、构建产物和媒体文件属于本地运行边界，不进入 Git 提交。

## 开发流程

1. 先阅读与任务直接相关的源码、测试和文档，记录可验证的成功标准。
2. 保持改动局部，复用现有 API、类型、存储和测试夹具。
3. 先运行直接相关测试，再运行 `npm run verify`。
4. 检查 `git diff --check`、敏感信息和忽略边界。
5. 提交前说明改动文件、影响范围和未执行的验证。

## 关键不变量

- 默认监听 `127.0.0.1`；生产模式使用后端 Bearer 鉴权。
- Provider 地址、协议、端口和路径固定，凭证只由后端读取。
- Tool Call 必须经过注册、Schema、Agent 权限和策略判断。
- 决策只有 `ALLOW`、`DENY`、`ASK`、`ISOLATE` 四态；冲突按拒绝优先。
- 审批绑定参数 Hash、策略版本、Agent、会话、目标和有效期，并且只能消费一次。
- 未知工具、畸形参数、策略错误、数据库错误和证据验证失败默认拒绝执行。
- 执行回执、请求 Hash、响应 Hash 和 HMAC 证据必须保持同一条请求链。
- 来源状态只可写为 `proved`、`correlated` 或 `unknown`，不得把相关性推断写成密码学证明。

## 常用命令

```powershell
npm run install:all
npm run dev
npm run console:test
npm run api:test
npm run verify
npm run verify:live
npm run verify:live:fixture
```

`verify:live` 默认写入 `not_run`；只有显式设置 `AGENT_SUPERVISOR_LIVE_SMOKE=true` 才会发起闭环烟测。烟测报告位于 `apps/api/runtime/quality/live-closure/`。

## Git 约定

- `main` 保持可运行；开发分支使用 `codex/<scope>`。
- 提交信息使用中文 Emoji Conventional Commits，格式为 `<emoji><type>(<scope>): <description>`。
- 描述不超过 50 字，按独立功能和可回滚边界拆分提交。
- 远程推送、分支删除和真实外部服务验证需要在任务中明确授权。
