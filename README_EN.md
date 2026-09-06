# Agent Security Supervisor

Agent Security Supervisor is a local-first control gateway for agent actions. OpenAI-compatible requests and MCP tool calls pass through one policy, approval, execution-receipt, and hash/HMAC evidence boundary.

## Scope

- OpenAI-compatible chat completions with streaming and non-streaming responses.
- Non-streaming OpenAI Responses compatibility endpoint.
- MCP Gateway for stdio and Streamable HTTP.
- Four decisions: allow, deny, ask, and isolate.
- Exact approval binding, one-time execution receipts, and tamper-evident evidence.
- Pinned Provider egress with redirect, private-address, and unbound-target rejection.
- Local React console with protection, events, and settings pages.
- Bounded local file, memory, and outbox operations; no arbitrary command execution.

## Local start

```powershell
npm --prefix apps/console ci
python -m pip install -r apps/api/requirements-dev.txt
npm run dev
```

The service listens on `127.0.0.1:8012` and serves the built console from the same origin. For Vite hot reload, run `npm run dev:console` and open `http://127.0.0.1:5178`.

Copy `.env.example` to `.env` and configure Provider and MCP values on the server side. Secrets are never placed in browser bundles.

## Layout

```text
apps/api/agent_supervisor/  FastAPI service and runtime
apps/api/tests/             backend tests and fixtures
apps/api/runtime/           local runtime, backups, E2E, and quality output (ignored)
apps/console/               React + Vite console
docs/product/               product documents
docs/engineering/           local operations and security
docs/research/              research notes
docs/media/                 non-build media
legacy/                     read-only historical material
scripts/                    local maintenance and quality checks
```

## Verification

```powershell
npm run console:test
npm run console:build
python -X utf8 -m unittest discover -s apps/api/tests -t . -p "test_*.py"
npm run verify:local
```

Runtime data and quality output stay under `apps/api/runtime/` and are ignored by Git. The repository root does not retain coverage, audit reports, or tool caches. The project is designed for a single local machine; external deployment is outside the current product boundary.

Apache-2.0. See [LICENSE](LICENSE).
