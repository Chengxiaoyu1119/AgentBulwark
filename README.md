<div align="center">
  <img src="apps/console/public/favicon.svg" alt="智安哨" width="96" />
  <h1>智安哨</h1>
  <p><strong>Agent Security Supervisor</strong><br />让每一次 Agent 行动可控、可见、可验证。</p>
  <p>
    <a href="https://github.com/Chengxiaoyu1119/agent-security-supervisor/actions/workflows/quality.yml"><img src="https://github.com/Chengxiaoyu1119/agent-security-supervisor/actions/workflows/quality.yml/badge.svg" alt="Quality" /></a>
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-2f6fed.svg" alt="Apache-2.0" /></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11-3776ab.svg" alt="Python 3.11" /></a>
    <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-22-5fa04e.svg" alt="Node.js 22" /></a>
  </p>
</div>

智安哨是一个本地优先的 Agent 行动安全网关。它把 OpenAI 兼容请求与 MCP 工具调用放进同一条控制链：执行前做策略判断，执行中保留可追踪状态，执行后验证回执与证据。

## 核心能力

| 能力 | 说明 |
| --- | --- |
| OpenAI Gateway | `/v1/chat/completions` 支持流式与非流式；`/v1/responses` 支持非流式。 |
| MCP Gateway | 支持 stdio 与 Streamable HTTP，按 Agent + Session 隔离会话。 |
| 行动决策 | `ALLOW`、`DENY`、`ASK`、`ISOLATE` 四态策略，冲突按拒绝优先。 |
| 审批与回执 | 参数 Hash、策略版本、Agent、会话和有效期绑定；审批凭证一次性消费。 |
| 证据链 | 请求、响应、工具参数、策略和执行结果写入 Hash/HMAC 审计链，支持离线验证。 |
| 本地控制台 | 防护、事件、设置三页，实时查看行动状态、审批和证据。 |

## 工作流

```text
Agent
  -> OpenAI Gateway
  -> Provider 固定出口
  -> Tool Call 标准化
  -> 策略决策 / 审批
  -> MCP Gateway 或受限运行时
  -> 执行回执
  -> Hash/HMAC 证据
  -> 控制台
```

## 快速开始

要求：Node.js 22+、Python 3.11+。

```powershell
git clone https://github.com/Chengxiaoyu1119/agent-security-supervisor.git
cd agent-security-supervisor
npm run install:all
Copy-Item .env.example .env
npm run dev
```

打开 [http://127.0.0.1:8012](http://127.0.0.1:8012)。默认只监听本机回环地址；Provider 密钥和 MCP 凭证由后端读取，不进入浏览器构建产物。

## 接入与验证

将 Agent 的 OpenAI Base URL 指向 `http://127.0.0.1:8012/v1`，再在 `.env` 登记 Provider 和 MCP。常用入口：

```text
POST /v1/chat/completions
POST /v1/responses
POST /api/mcp
GET  /api/overview
GET  /api/gateway/traces
GET  /api/runtime/executions
```

本地质量门禁：

```powershell
npm run verify
```

可选闭环烟测默认不访问外部服务；只有显式设置 `AGENT_SUPERVISOR_LIVE_SMOKE=true` 才会运行，并将结果写入被忽略的 `apps/api/runtime/quality/live-closure/`。

## 文档

- [产品定位](docs/product/产品定位.md)
- [安全边界](docs/engineering/安全边界.md)
- [研究与决策](docs/research/大模型防火墙研究证据与产品决策.md)
- [贡献指南](CONTRIBUTING.md)
- [协作与编码代理指南](AGENTS.md)

## 项目结构

```text
apps/api/agent_supervisor/  FastAPI 服务与运行内核
apps/api/tests/             后端测试与协议夹具
apps/console/               React + Vite 控制台
docs/                       产品、工程与研究文档
legacy/                     历史资料
scripts/                    启动、维护与质量检查
```

## 参与贡献

请先阅读 [AGENTS.md](AGENTS.md) 和 [CONTRIBUTING.md](CONTRIBUTING.md)，提交前运行 `npm run verify`。

## 许可证

Apache-2.0，详见 [LICENSE](LICENSE)。
