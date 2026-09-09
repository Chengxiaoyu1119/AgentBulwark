# 贡献指南

感谢你关注 AgentBulwark / 智垒。项目的核心目标是让 AI Agent 的请求、工具调用和真实执行都经过可验证的运行时边界。

## 先确认边界

- 生产代码位于 `apps/api/agent_supervisor/` 和 `apps/console/`。
- `legacy/` 只保存历史资料，不进入默认 API、控制台构建或测试。
- 本项目是单机本地运行，不引入 Docker、任意命令执行或攻击实验入口。
- Provider 与 MCP 凭证只能由后端读取，禁止提交密钥、运行数据库和构建产物。

## 开发环境

要求：Node.js >= 22、Python >= 3.11。

```powershell
git clone https://github.com/Chengxiaoyu1119/AgentBulwark.git
cd AgentBulwark
npm run install:all
Copy-Item .env.example .env
```

启动本地控制台与 API：

```powershell
npm run dev
```

## 修改前后都要验证

先阅读直接相关的源码、测试和文档，保持改动局部。提交 Pull Request 前运行：

```powershell
npm run verify
```

闭环夹具验证使用本地 HTTP Provider 和 MCP stdio 子进程，不会改写正式运行数据：

```powershell
npm run verify:live:fixture
```

外部 Provider 烟测默认关闭。只有明确设置 `AGENT_SUPERVISOR_LIVE_SMOKE=true` 才会访问外部服务。

常用单项检查：

| 检查         | 命令                          |
| ------------ | ----------------------------- |
| 后端测试     | `npm run api:test`            |
| 后端 Lint    | `npm run api:lint`            |
| 后端类型检查 | `npm run api:typecheck`       |
| 架构边界     | `npm run api:architecture`    |
| 前端 Lint    | `npm run console:lint:strict` |
| 前端测试     | `npm run console:test`        |
| 前端构建     | `npm run console:build`       |

## 提交类型

使用中文 Emoji Conventional Commits，描述不超过 50 字：

```text
✨feat(scope): 新增功能
🐛fix(scope): 修复缺陷
📝docs(scope): 更新文档
♻️refactor(scope): 重构实现
🧪test(scope): 补充测试
🧹chore(scope): 调整工具或配置
```

按独立功能和可回滚边界拆分提交。不要把 `.env`、`apps/api/runtime/`、`apps/console/node_modules/` 或构建产物加入暂存区。

## Pull Request

请在描述中写清楚：

1. 改动解决了什么问题；
2. 影响了哪些接口、页面或数据流；
3. 执行了哪些验证，哪些验证尚未执行；
4. 是否改变了安全边界、策略、审批或证据链。

安全漏洞不要公开创建 Issue，请按 [安全策略](SECURITY.md) 私密报告。

## 代码边界

| 内容                   | 路径                         |
| ---------------------- | ---------------------------- |
| FastAPI 入口与运行内核 | `apps/api/agent_supervisor/` |
| 后端测试与协议夹具     | `apps/api/tests/`            |
| React + Vite 控制台    | `apps/console/`              |
| 产品、工程和研究文档   | `docs/`                      |
| 启动、维护和质量脚本   | `scripts/`                   |
| 本地运行数据与质量产物 | `apps/api/runtime/`          |

详细不变量和代理协作规则见 [AGENTS.md](AGENTS.md)。

## 许可证

提交即表示你同意贡献内容以 [Apache License 2.0](LICENSE) 授权。
