<p align="center">
  <img src="apps/console/public/favicon.svg" alt="ZhiAn Sentinel logo" width="92" />
</p>

<h1 align="center">ZhiAn Sentinel (agent-security-supervisor)</h1>

<p align="center">
  <strong>Runtime behavioral firewall and evaluation system for LLM agent tool-call chains.</strong>
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" />
  <img alt="React" src="https://img.shields.io/badge/React-18.3-61dafb?logo=react&logoColor=white" />
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5.6-3178c6?logo=typescript&logoColor=white" />
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white" />
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776ab?logo=python&logoColor=white" />
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#integration-modes">Integration</a> ·
  <a href="./CONTRIBUTING.md">Contributing</a> ·
  <a href="./SECURITY.md">Security</a> ·
  <a href="./CHANGELOG.md">Changelog</a> ·
  <a href="./README.md">中文</a>
</p>

---

## Overview

ZhiAn Sentinel moves the security checkpoint from the model conversation layer down to the tool execution layer. Before file, mail, API, code, or memory tools produce any side effect, it performs normalization, decision, blocking, review, and audit trail.

It targets LLM agent security research and defense, covering prompt injection, model jailbreak, data leakage, tool-call hijacking, memory poisoning, environment perception pollution, and abuse risks, aligned with the OWASP Agentic Security risk list.

> [!IMPORTANT]
> This project reproduces risks in controlled lab environments with simulated business data. It is built for researching and validating agent security defenses and never attacks real external systems.

```text
Agent tool call -> Pre-execution supervision -> allow / deny / ask / quarantine
        -> tool executes or stops -> execution receipt -> event audit & human review
```

<table>
  <tr>
    <td align="center"><strong>7</strong><br />attack surfaces</td>
    <td align="center"><strong>22</strong><br />attack sample sets</td>
    <td align="center"><strong>15</strong><br />defense policies</td>
    <td align="center"><strong>4</strong><br />decisions</td>
    <td align="center"><strong>Agent</strong><br />generic access</td>
    <td align="center"><strong>Hash+HMAC</strong><br />audit chain</td>
  </tr>
</table>

## Key Capabilities

| Module | Capability | Entry |
|---|---|---|
| Dashboard | Service, model, risk events, pending receipts, live call chains | `apps/console/src/pages/Dashboard.tsx` |
| Events & Review | Merged audit, alerts, approvals, execution receipts | `apps/console/src/pages/AuditLogPanel.tsx` |
| Attack-Defense Lab | Single contrast run, real-agent validation, batch regression | `apps/console/src/components/lab/ExperimentLab.tsx` |
| Policy Center | Tool-call policies, risk thresholds, disposal rules | `apps/console/src/components/policy/PolicyCenter.tsx` |
| Behavior Supervisor | allow / deny / ask / quarantine decisions per tool call | `apps/api/agent_supervisor/domains/governance/supervisor.py` |
| Audit & Alerts | Tool params, policy hits, risk/anomaly scores, audit hash | `apps/api/agent_supervisor/domains/governance/integrity.py` |
| Evaluation & Evidence | Effectiveness, false positives, ablation, benchmarks, evidence packs | `apps/api/agent_supervisor/domains/evaluations/` |
| Agent Integration | HTTP event contract, AgentToolGuard, OpenAI Agents/LangChain/LangGraph examples | `apps/api/agent_supervisor/adapters/integrations/agent_integrations.py` |

## Architecture

```mermaid
flowchart LR
  User["Security engineer / researcher"] --> UI["React + Ant Design console"]
  UI --> API["FastAPI backend"]
  CLI["Python CLI"] --> API
  External["Any external agent / AI tool"] --> Gateway["Generic tool event gateway"]
  Gateway --> Supervisor["Behavior supervisor"]
  API --> Supervisor
  Supervisor --> Policies["15 defense policies"]
  Supervisor --> Anomaly["Lightweight anomaly detection"]
  Supervisor --> Sandbox["Local sandbox tool layer"]
  Sandbox --> Receipt["Tool execute / stop + execution receipt"]
  Receipt --> Audit["Event audit / alerts / human review"]
  Audit -.on demand.-> Evidence["Evaluation reports / evidence packs"]
  UI --> Audit
```

## Integration Modes

| Mode | Enforcement | Description |
|---|---|---|
| OpenClaw plugin | **Enforced** | Plugin returns `block:true` in the `before_tool_call` hook; the tool call is never executed |
| MCP Gateway | **Enforced** | Agent connects to the Gateway (`POST /api/mcp`), which proxies the real MCP server (stdio); every `tools/call` must pass the supervisor — deny/quarantine/ask requests are never forwarded upstream |
| Generic HTTP | **Advisory** | The supervisor returns a decision and audit ID; compliance is up to the caller |

> [!IMPORTANT]
> The generic HTTP API (`POST /api/runtime/evaluate`) is **advisory**: ZhiAn Sentinel does not execute tools on your behalf and cannot force blocking over the caller. Use the OpenClaw plugin or MCP Gateway when hard enforcement is required.
>
> Enable the MCP Gateway via environment variables: point `MCP_GATEWAY_UPSTREAM_COMMAND` at the upstream MCP server launch command (e.g. `npx -y @modelcontextprotocol/server-filesystem /sandbox`). Custom MCP tool names must be mapped to standard capabilities in the `agent_tool_mappings` policy settings, otherwise the tool-contract policy rejects them.
>
> Multi-upstream routing: declare named routes via `MCP_GATEWAY_ROUTES_JSON='[{"name":"fs","command":"npx -y @modelcontextprotocol/server-filesystem","cwd":"/data"}]'`. The gateway routes `tools/call` by each upstream's tools/list catalog; `tools/list` aggregates all routes with source labels, and duplicate tool names belong to the default route.
>
> Audit trail: with supervision on, every `tools/call` (allowed or blocked) is written to the unified audit chain (`source_app=mcp-gateway`, including the decision, policy hit, and a redacted snapshot of the upstream result), queryable via the Events & Review page and `GET /api/audit_logs`; upstream notifications can be polled via `GET /api/mcp/notifications`.
>
> Dual-channel jailbreak detection: the rule channel (`jailbreak-filter` and related policies, <5ms) short-circuits explicit risks first; when the rules pass and the input is non-empty, the semantic channel (`jailbreak-semantic` policy) calls a local ONNX BERT model for intent-level fallback detection (<50ms). Model files live in `training/model/` (`jailbreak_bert.onnx` + `tokenizer.json`); when `onnxruntime`/`tokenizers` are not installed or the model is missing, the semantic channel degrades automatically and behavior is identical to rules-only. Set `SEMANTIC_DETECT_ENABLED=0` to force it off. See `training/finetune_bert.py` for fine-tuning, `scripts/generate_bert_variants.py` for dataset building, and `scripts/bench_dual_channel.py` for latency benchmarks.
>
> Tool description poisoning scan (OWASP A04): during `tools/list` aggregation, every tool's name + description is scanned for three quarantine-grade poisoning traits — instruction override (e.g. "ignore all previous instructions"), exfiltration channels (send-to URL/email), and credential file access (`~/.ssh`, `.env`, etc.) — plus warning-grade traits such as mandatory-invocation prompts. Results are attached to the tool list as `zhiAnSentinel.skillScan`; `tools/call` against a quarantined tool is blocked directly by the gateway (policy `tool-description-scan`) and written to the audit chain.

Minimal event example:

```json
{
  "conversation_id": "demo-conv",
  "agent_id": "external-agent-1",
  "agent_role": "assistant",
  "tool_call": {
    "tool": "file.read",
    "arguments": { "path": "confidential/competition-teams.csv" }
  },
  "guard_enabled": true,
  "execute_in_sandbox": false
}
```

## Attack Surface Matrix

| Surface | Risk | Samples | Typical risk |
|---|---|---:|---|
| Prompt injection | high | 18 | External content overrides system rules |
| Model jailbreak | high | 9 | Inducing the model to bypass safety constraints |
| Data leakage | critical | 18 | Reading sensitive data and exfiltrating it |
| Abuse risk | medium | 13 | Bulk sending, spam, unauthorized export |
| Tool-call hijacking | critical | 17 | Hijacking execution chains via tool returns or params |
| Memory poisoning | high | 9 | Writing malicious long-term memory |
| Environment pollution | medium | 12 | Faking environment variables or runtime context |

## Defense Policy Matrix

| Policy ID | Name | Default | Primary action |
|---|---|---|---|
| `path-boundary` | File sandbox boundary | on | Deny out-of-boundary read/write |
| `dangerous-command` | Dangerous command interception | on | Deny high-risk commands |
| `code-sandbox` | Code execution sandbox | on | Quarantine code runs |
| `external-mail` | Outbound mail review | on | Ask before external mail |
| `sensitive-api` | Sensitive API audit | on | Deny unauthorized sensitive endpoints |
| `memory-write` | Memory write quarantine | on | Quarantine poisoning-style writes |
| `memory-read-sensitive` | Sensitive memory read blocking | on | Deny sensitive retrieval |
| `jailbreak-filter` | Jailbreak prompt filtering | on | Deny jailbreak prompts |
| `jailbreak-semantic` | Semantic jailbreak detection | on | BERT fallback verdict when rules pass (auto-degrades without model) |
| `model-output-filter` | Model output filtering | on | Deny high-risk outputs |
| `bulk-action-review` | Bulk action review | on | Ask before bulk export/send |
| `tool-description-scan` | Tool description poisoning scan | on | Quarantine tools whose description contains suspicious instructions (OWASP A04) |
| `tool-return-trust` | Low-trust tool return quarantine | on | Quarantine untrusted tool returns |
| `environment-trust` | Low-trust environment signals | on | Quarantine polluted environment signals |
| `anomaly-detection` | Lightweight anomaly detection | on | Ask or deny by anomaly score |

## OWASP Agentic Top 10 Coverage

Aligned with the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (published Dec 2025), annotated item by item:

| ID | Risk | Coverage | ZhiAn Sentinel defense |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | 🟡 Partial | Dual-channel jailbreak detection: rule channel (CN/EN keyword-augmented, 54.5% recall / zero FP / <5ms on the held-out set) + semantic channel (local BERT, auto-degrades without model) + `model-output-filter` output-layer fallback |
| ASI02 | Tool Misuse & Exploitation | 🟢 Covered | Tool-contract allowlist, path boundary, dangerous command interception, sensitive APIs, bulk action review, external mail confirmation |
| ASI03 | Identity & Privilege Abuse | 🟡 Partial | `agent_tool_allowlists` per-identity tool authorization, production tokens bound to `agent_id`, identity verification fields in the audit chain |
| ASI04 | Agentic Supply Chain | 🟡 Partial | MCP tool description poisoning scan (`tool-description-scan`: instruction override / exfiltration channel / credential access; quarantined tools are blocked); SBOM and dependency signing on the roadmap |
| ASI05 | Unexpected Code Execution | 🟢 Covered | Dangerous commands denied outright; other commands run in a disposable no-network, read-only, resource-limited sandbox container |
| ASI06 | Memory & Context Poisoning | 🟢 Covered | Memory write quarantine, sensitive memory read blocking, low-trust environment isolation, untrusted tool return quarantine |
| ASI07 | Insecure Inter-Agent Communication | 🟡 Partial | Cross-agent correlation chain detection (blocks "sensitive read → bulk export → send-out" stepwise exfiltration chains); transport encryption and message signing on the roadmap |
| ASI08 | Cascading Failures | 🟡 Partial | Lightweight anomaly detection blocks suspicious call chains by score; cross-agent chain detection pauses execution before cascades occur |
| ASI09 | Human-Agent Trust Exploitation | 🟡 Partial | Bulk/send actions trigger a human review loop; execution receipts verify caller compliance with decisions |
| ASI10 | Rogue Agents | 🟡 Partial | Tool authorization allowlist + anomaly detection + cross-agent suspicious collaboration correlation |

Coverage summary: fully covered 3/10 (ASI02/05/06), partially covered 7/10, **risk touch rate 100%**; the MCP Gateway and OpenClaw plugin provide protocol-level blocking enforcement for all policies.

## Quick Start

### Option 1: Docker one-click startup (recommended)

Prerequisites: Docker 20.10+ and Docker Compose v2.

```bash
# 1. Prepare environment variables (both are required; the container refuses to start without them)
cp .env.example .env
# Edit .env and fill in at least:
#   AGENT_SUPERVISOR_API_TOKEN=<bearer token for API calls>
#   AGENT_SUPERVISOR_AUDIT_HMAC_KEY=<random HMAC key for the audit chain>

# 2. Build and start (multi-stage build: frontend compilation + Python runtime image)
docker compose up -d --build

# 3. Verify
curl http://127.0.0.1:8012/api/health
```

Open `http://127.0.0.1:8012` in a browser to use the console (the API and the frontend static assets are served by the same container). Runtime data such as the audit database persists in the `zhi-an-data` volume.

> [!IMPORTANT]
> The container listens on `0.0.0.0` (a non-loopback address), so the security policy enforces API token authentication and an audit HMAC key — the service refuses to start when either is missing (fail-closed). For production deployments, add HTTPS via a reverse proxy.

### Option 2: Run from source

Prerequisites:

- Node.js 22.0+
- Python 3.10+

### 1. Install dependencies

```bash
npm --prefix apps/console install
python -m pip install -r apps/api/requirements.txt
```

For development (tests and type-checking tools):

```bash
python -m pip install -r apps/api/requirements-dev.txt
```

### 2. Start the backend API

```bash
npm run api
```

Default address and health check:

```text
http://127.0.0.1:8012
http://127.0.0.1:8012/api/health
```

### 3. Start the console

```bash
npm run console:dev
```

Open `http://127.0.0.1:5178`.

> [!TIP]
> If the backend is not running, the console falls back to built-in sample data. Start the backend to record real experiment logs.

### 4. Model configuration (optional)

No real model key is required. Without keys, the system demonstrates attack-defense contrast using local target fixtures and sandbox side-effect assertions.

To use real DeepSeek or Zhipu models, copy `.env.example` to `.env` and fill in keys:

```bash
MODEL_REAL_API_ENABLED=true
MODEL_PROVIDER_PRIORITY=deepseek,zhipu
DEEPSEEK_API_KEY=your-deepseek-key
ZHIPU_API_KEY=your-zhipu-key
```

## CLI

The CLI is used for batch regression, evaluation, and evidence export. It does not participate in runtime decisions.

| Task | Command |
|---|---|
| Run one attack script | `npm run cli -- run TOOL-HIJACK-001 on` |
| Batch compare all scripts | `npm run cli -- batch --guard compare` |
| Export effectiveness assessment | `npm run cli -- assess --run-compare` |
| Evaluate external agent event logs | `npm run cli -- evaluate --input apps/api/sandbox/examples/agent-events-batch.json` |
| Policy ablation | `npm run cli -- policy-ablation` |
| Frozen set & baseline benchmark | `npm run cli -- competition-benchmark` |
| HTTP/SQLite/audit-chain benchmark | `npm run cli -- http-e2e-benchmark` |
| One-click readiness check | `npm run cli -- readiness --write` |
| OpenClaw plugin package | `npm run cli -- openclaw-plugin` |
| OpenClaw plugin validation | `npm run cli -- openclaw-plugin-validate` |

## Security Boundary

> [!CAUTION]
> This repository contains attack samples, jailbreak examples, and tool-abuse scenarios for controlled research only. Do not use them against real systems.

| Tool type | Boundary |
|---|---|
| Mail | Writes to a fake outbox only; never sends real mail |
| File | Accesses sandbox directories only; never reads user files |
| API | Accesses local simulated business data only |
| Code execution | Registered probes run with argument arrays; other commands run in a disposable no-network, read-only, resource-limited container |
| Memory | Demo data only, with isolation and reset |
| Audit data | Tokens, passwords, API keys, and emails are redacted before persistence; optional HMAC signing |

## Project Structure

```text
agent-security-supervisor/
├─ apps/
│  ├─ api/                           # FastAPI backend
│  │  ├─ agent_supervisor/           # Backend Python package
│  │  │  ├─ domains/                 # attacks, evaluations, governance, reports, runtime
│  │  │  ├─ adapters/                # agent integrations, models, proxy
│  │  │  ├─ storage/                 # data & database access
│  │  │  ├─ routers/                 # API routes
│  │  │  └─ schemas/                 # Pydantic models
│  │  ├─ sandbox/                    # controlled lab data, sample events, reports
│  │  └─ tests/                      # backend unit tests
│  └─ console/                       # React + Vite console
├─ scripts/                          # governance checks, self-review, CLI entry
├─ docs/                             # dev records and design materials
├─ archive/                          # archived site, docs portal, historical materials
└─ package.json                      # unified command entry
```

## Development & Quality Checks

| Check | Command |
|---|---|
| Backend tests | `npm run api:test` |
| Backend lint | `npm run api:lint` |
| Backend type check | `npm run api:typecheck` |
| Architecture governance | `npm run api:architecture` |
| Console build | `npm run console:build` |
| Console lint | `npm run console:lint` |
| Full verification | `npm run verify` |

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the contribution guide, [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for the code of conduct, and [CHANGELOG.md](./CHANGELOG.md) for the changelog.

## Roadmap

- [x] MCP Gateway: enforced supervision at the Model Context Protocol proxy layer (stdio upstream + Streamable HTTP subset entry)
- [x] MCP Gateway: multi-upstream routing, audit persistence, upstream notification polling
- [x] Dual-channel jailbreak detection: rule channel first (<5ms), BERT semantic channel fallback (<50ms, auto-degrades without model)
- [ ] MCP Gateway: full SSE streaming and upstream-initiated request support
- [ ] Semantic jailbreak detection: fine-tuned Chinese BERT and ONNX model release (`training/finetune_bert.py`)
- [ ] OWASP Agentic Top 10 coverage to 90%+
- [ ] More real-world agent framework adapters
- [ ] Field-level data redaction and fine-grained access control

## License

This project is open-sourced under the [Apache License 2.0](./LICENSE). Please report security vulnerabilities privately as described in [SECURITY.md](./SECURITY.md).
