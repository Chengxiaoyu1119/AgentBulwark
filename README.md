<div align="center">
  <img src="apps/console/public/favicon.png" alt="智垒" width="96" />
  <h1>AgentBulwark · 智垒</h1>
  <p><strong>AI Agent 防火墙</strong><br />在请求、上下文、模型输出和工具调用之间建立可验证的运行时边界。</p>
  <p>
    <a href="https://github.com/Chengxiaoyu1119/agent-security-supervisor/actions/workflows/quality.yml"><img src="https://github.com/Chengxiaoyu1119/agent-security-supervisor/actions/workflows/quality.yml/badge.svg" alt="Quality" /></a>
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-2f6fed.svg" alt="Apache-2.0" /></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11-3776ab.svg" alt="Python 3.11" /></a>
    <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-22-5fa04e.svg" alt="Node.js 22" /></a>
  </p>
</div>

AgentBulwark 是一个本地优先的 AI Agent 防火墙。它让 OpenAI 兼容请求和 MCP 工具调用经过同一条可观测、可阻断、可审计的控制链。

```text
Request → Policy → Provider → Tool Gate → MCP → Receipt
```

## 能力

- **请求防护**：检查提示、外部上下文、模型输出和工具定义，风险请求在到达 Provider 前即可阻断。
- **行动控制**：按 Agent、Session、Schema、目标和策略处理 `ALLOW`、`DENY`、`ASK`、`ISOLATE`。
- **MCP 网关**：支持 stdio 与 Streamable HTTP，隔离会话并阻止未登记、越权或异常工具调用。
- **可验证证据**：用请求/响应 Hash、HMAC 审计链和服务端执行回执证明实际处置结果。
- **本地控制台**：在防护、事件和设置页面查看实时行动、审批、执行状态与证据。

## 快速开始

要求：Node.js 22+、Python 3.11+。

```powershell
git clone https://github.com/Chengxiaoyu1119/agent-security-supervisor.git
cd agent-security-supervisor
npm run install:all
Copy-Item .env.example .env
npm run dev
```

打开 [http://127.0.0.1:8012](http://127.0.0.1:8012)。服务默认只监听本机回环地址；Provider 密钥和 MCP 凭证只由后端读取。

## 接入

将 Agent 的 OpenAI Base URL 指向 `http://127.0.0.1:8012/v1`，再在 `.env` 登记 Provider 和 MCP。

```text
POST /v1/chat/completions
POST /v1/responses
POST /api/mcp
GET  /api/overview
GET  /api/gateway/traces
GET  /api/runtime/executions
```

提交或发布前运行本地质量门禁：

```powershell
npm run verify
npm run verify:live:fixture
```

`verify:live:fixture` 使用仓库内真实 HTTP Provider 与 MCP stdio 子进程完成确定性闭环，不改写正式运行数据。`verify:live` 默认不访问外部服务；只有显式设置 `AGENT_SUPERVISOR_LIVE_SMOKE=true` 才会运行外部 Provider 烟测。

## 文档

- [产品定位](docs/product/产品定位.md)
- [安全边界](docs/engineering/安全边界.md)
- [研究与决策](docs/research/大模型防火墙研究证据与产品决策.md)
- [贡献指南](CONTRIBUTING.md)
- [协作与编码代理指南](AGENTS.md)

## 结构

```text
apps/api/agent_supervisor/  FastAPI 服务与运行内核
apps/api/tests/             后端测试与协议夹具
apps/console/               React + Vite 控制台
docs/                       产品、工程与研究文档
legacy/                     历史资料
scripts/                    启动、维护与质量检查
```

## 许可证

Apache-2.0，详见 [LICENSE](LICENSE)。
