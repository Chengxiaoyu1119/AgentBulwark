<div align="center">
  <img src="apps/console/public/favicon.svg" alt="Zhi An Shao" width="96" />
  <h1>Zhi An Shao</h1>
  <p><strong>Agent Security Supervisor</strong><br />Control every agent action before, during, and after execution.</p>
  <p>
    <a href="https://github.com/Chengxiaoyu1119/agent-security-supervisor/actions/workflows/quality.yml"><img src="https://github.com/Chengxiaoyu1119/agent-security-supervisor/actions/workflows/quality.yml/badge.svg" alt="Quality" /></a>
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-2f6fed.svg" alt="Apache-2.0" /></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11-3776ab.svg" alt="Python 3.11" /></a>
    <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-22-5fa04e.svg" alt="Node.js 22" /></a>
  </p>
</div>

Zhi An Shao is a local-first agent action security gateway. OpenAI-compatible requests and MCP tool calls share one control path for policy decisions, approvals, execution receipts, and verifiable evidence.

## Core capabilities

| Capability             | What it provides                                                                                 |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| OpenAI Gateway         | Streaming and non-streaming `/v1/chat/completions`; non-streaming `/v1/responses`.               |
| MCP Gateway            | stdio and Streamable HTTP with Agent + Session isolation.                                        |
| Action decisions       | `ALLOW`, `DENY`, `ASK`, and `ISOLATE`, with deny-first conflict handling.                        |
| Approvals and receipts | One-time approvals bound to arguments, policy version, agent, session, and expiry.               |
| Evidence chain         | Hash/HMAC audit evidence for requests, responses, tool arguments, policy, and execution results. |
| Local console          | Protection, events, and settings pages for live status, approvals, and evidence.                 |

## Request flow

```text
Agent
  -> OpenAI Gateway
  -> Pinned Provider egress
  -> Tool Call normalization
  -> Policy decision / approval
  -> MCP Gateway or bounded runtime
  -> Execution receipt
  -> Hash/HMAC evidence
  -> Console
```

## Quick start

Requirements: Node.js 22+ and Python 3.11+.

```powershell
git clone https://github.com/Chengxiaoyu1119/agent-security-supervisor.git
cd agent-security-supervisor
npm run install:all
Copy-Item .env.example .env
npm run dev
```

Open [http://127.0.0.1:8012](http://127.0.0.1:8012). The service listens on loopback by default. Provider keys and MCP credentials are read by the backend and are not placed in browser bundles.

## Integration and verification

Point an agent's OpenAI Base URL to `http://127.0.0.1:8012/v1`, then register the Provider and MCP settings in `.env`.

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
```

The optional closure smoke does not contact external services by default. Set `AGENT_SUPERVISOR_LIVE_SMOKE=true` explicitly to run it; reports are written under ignored `apps/api/runtime/quality/live-closure/`.

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
