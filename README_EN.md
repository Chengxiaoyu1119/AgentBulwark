<div align="center">
  <img src="apps/console/public/favicon.png" alt="AgentBulwark" width="96" />
  <h1>AgentBulwark · 智垒</h1>
  <p><strong>AI Agent Firewall</strong><br />A verifiable runtime boundary for requests, context, model output, and tool calls.</p>
  <p>
    <a href="https://github.com/Chengxiaoyu1119/agent-security-supervisor/actions/workflows/quality.yml"><img src="https://github.com/Chengxiaoyu1119/agent-security-supervisor/actions/workflows/quality.yml/badge.svg" alt="Quality" /></a>
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-2f6fed.svg" alt="Apache-2.0" /></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11-3776ab.svg" alt="Python 3.11" /></a>
    <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-22-5fa04e.svg" alt="Node.js 22" /></a>
  </p>
</div>

AgentBulwark is a local-first AI Agent Firewall. OpenAI-compatible requests and MCP tool calls share one observable, enforceable, and auditable control path.

```text
Request → Policy → Provider → Tool Gate → MCP → Receipt
```

## Capabilities

- **Request protection**: inspect prompts, external context, model output, and tool definitions before risky traffic reaches the Provider.
- **Action control**: decide `ALLOW`, `DENY`, `ASK`, or `ISOLATE` using the Agent, Session, Schema, target, and policy.
- **MCP Gateway**: support stdio and Streamable HTTP with session isolation and guarded tool execution.
- **Verifiable evidence**: bind request/response hashes, an HMAC audit chain, and server-observed execution receipts.
- **Local console**: inspect live actions, approvals, execution state, and evidence in Protection, Events, and Settings.

## Quick start

Requirements: Node.js 22+ and Python 3.11+.

```powershell
git clone https://github.com/Chengxiaoyu1119/agent-security-supervisor.git
cd agent-security-supervisor
npm run install:all
Copy-Item .env.example .env
npm run dev
```

Open [http://127.0.0.1:8012](http://127.0.0.1:8012). The service listens on loopback by default; Provider keys and MCP credentials are read only by the backend.

## Integration

Point an Agent's OpenAI Base URL to `http://127.0.0.1:8012/v1`, then register Provider and MCP settings in `.env`.

```text
POST /v1/chat/completions
POST /v1/responses
POST /api/mcp
GET  /api/overview
GET  /api/gateway/traces
GET  /api/runtime/executions
```

Run the local quality gate before sharing changes:

```powershell
npm run verify
npm run verify:live:fixture
```

`verify:live:fixture` runs a deterministic closure with the repository's real HTTP Provider and MCP stdio fixtures without rewriting operational data. `verify:live` does not contact external services by default; set `AGENT_SUPERVISOR_LIVE_SMOKE=true` explicitly for an external Provider smoke test.

## Documentation

- [Product positioning](docs/product/产品定位.md)
- [Security boundary](docs/engineering/安全边界.md)
- [Research and decisions](docs/research/大模型防火墙研究证据与产品决策.md)
- [Contributing](CONTRIBUTING.md)
- [Agent and collaboration guide](AGENTS.md)

## Repository layout

```text
apps/api/agent_supervisor/  FastAPI service and runtime
apps/api/tests/             backend tests and protocol fixtures
apps/console/               React + Vite console
docs/                       product, engineering, and research docs
legacy/                     historical material
scripts/                    startup, maintenance, and quality checks
```

## License

Apache-2.0. See [LICENSE](LICENSE).
