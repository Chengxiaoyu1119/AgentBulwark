$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

function Resolve-ProjectPython {
    $candidates = @()
    if ($env:AGENT_SUPERVISOR_PYTHON) {
        $candidates += $env:AGENT_SUPERVISOR_PYTHON
    }
    $candidates += @(Get-Command python.exe -All -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Source) { $_.Source } else { $_.Definition }
    })
    foreach ($candidate in @($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        & $candidate -c "import fastapi, uvicorn" *> $null
        if ($LASTEXITCODE -eq 0) {
            return $candidate
        }
    }
    throw "Missing a Python interpreter with fastapi and uvicorn; set AGENT_SUPERVISOR_PYTHON."
}

$python = Resolve-ProjectPython
$env:AGENT_SUPERVISOR_PYTHON = $python
$probeOutput = "apps/api/sandbox/reports/current-gateway-probe-8034.json"
$agentRunOutput = "apps/api/sandbox/reports/current-gateway-agent-run-8034.json"
$mcpOutput = "apps/api/sandbox/reports/current-mcp-probe-8034.json"
$env:AGENT_SUPERVISOR_API_PORT = "8034"
$env:AGENT_SUPERVISOR_API_TOKEN = "admin-token"
$env:AGENT_SUPERVISOR_DEFAULT_ROLE = "admin"
$env:AGENT_SUPERVISOR_AUTH_DISABLED = "false"
$env:AGENT_SUPERVISOR_SECURITY_PROFILE = "local"
$env:AGENT_SUPERVISOR_LABS_ENABLED = "true"
$env:AGENT_SUPERVISOR_RUNTIME_DIR = Join-Path $repoRoot "apps\api\sandbox\runtime\fixture-evidence-8034"
$env:AGENT_SUPERVISOR_AGENT_TOKENS_JSON = (@{ "fixture-agent" = "fixture-agent-token" } | ConvertTo-Json -Compress)
$env:AGENT_SUPERVISOR_AUDIT_HMAC_KEY = "fixture-hmac-key"
$env:AGENT_SUPERVISOR_PROXY_REQUIRE_TOOL_RECEIPTS = "true"
$env:AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS = "true"
$env:AGENT_SUPERVISOR_PROVIDER_DNS_MODE = "doh"
$env:AGENT_SUPERVISOR_PROVIDER_DOH_URL = "https://cloudflare-dns.com/dns-query"
$env:AGENT_SUPERVISOR_PROVIDER_DOH_TIMEOUT_SECONDS = "5"
$env:REAL_MODEL_EVALUATION_PROVIDER = "zhipu"
$env:MCP_GATEWAY_ENABLED = "true"
$env:MCP_GATEWAY_GUARD_ENABLED = "true"
$pythonQuote = [char]34
$env:MCP_GATEWAY_UPSTREAM_COMMAND = $pythonQuote + $python + $pythonQuote + " -X utf8 -m apps.api.tests.fixtures.mcp_echo_server"
$env:MCP_GATEWAY_SESSION_ISOLATION = "true"
$env:MCP_GATEWAY_RESOURCE_LIMITS_ENABLED = "true"
$env:MCP_GATEWAY_NETWORK_MODE = "reject-unpinned"
$env:MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS = "false"
$targetEnvironmentNames = @(
    "TARGET_MODEL_PROVIDER_PRIORITY",
    "TARGET_REAL_MODEL_PROVIDER",
    "TARGET_OPENAI_COMPATIBLE_API_KEY",
    "TARGET_OPENAI_COMPATIBLE_BASE_URL",
    "TARGET_OPENAI_COMPATIBLE_MODEL",
    "TARGET_DEEPSEEK_API_KEY",
    "TARGET_DEEPSEEK_BASE_URL",
    "TARGET_DEEPSEEK_MODEL",
    "TARGET_ZHIPU_API_KEY",
    "TARGET_ZHIPU_API_URL",
    "TARGET_ZHIPU_MODEL"
)
foreach ($name in $targetEnvironmentNames) {
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}
node scripts/agent-supervisor-cli.mjs gateway-probe --strict --payload-file=apps/api/sandbox/examples/live-provider-smoke.json --url=http://127.0.0.1:8034/v1/chat/completions --api-token=admin-token --session-id=deep-audit-probe-8034 --output=$probeOutput
if ($LASTEXITCODE -ne 0) {
    throw "gateway-probe failed with exit code $LASTEXITCODE"
}
$probeEvidence = Get-Content -Raw -Encoding UTF8 -LiteralPath $probeOutput | ConvertFrom-Json
if ($probeEvidence.contract.passed -ne $true) {
    throw "gateway-probe contract did not pass"
}

node scripts/agent-supervisor-cli.mjs gateway-agent-run --strict --input=apps/api/sandbox/examples/gateway-real-full-causal-cases.json --url=http://127.0.0.1:8034/v1/chat/completions --api-token=admin-token --causal-url=http://127.0.0.1:8034/api/gateway/compare --output=$agentRunOutput
if ($LASTEXITCODE -ne 0) {
    throw "gateway-agent-run failed with exit code $LASTEXITCODE"
}
$agentEvidence = Get-Content -Raw -Encoding UTF8 -LiteralPath $agentRunOutput | ConvertFrom-Json
if ($agentEvidence.summary.evidence_verdict -ne "complete" -or $agentEvidence.summary.gateway_contract_pass_rate -ne 100) {
    throw "gateway-agent-run contract did not pass"
}

node scripts/agent-supervisor-cli.mjs mcp-probe --strict --url=http://127.0.0.1:8034/api/mcp --api-token=fixture-agent-token --operator-api-token-env=AGENT_SUPERVISOR_API_TOKEN --operator-agent-id=fixture-agent --session-id=mcp-probe-8034 --tool=file.read --output=$mcpOutput
if ($LASTEXITCODE -ne 0) {
    throw "mcp-probe failed with exit code $LASTEXITCODE"
}
$mcpEvidence = Get-Content -Raw -Encoding UTF8 -LiteralPath $mcpOutput | ConvertFrom-Json
if ($mcpEvidence.summary.evidence_verdict -ne "complete") {
    throw "mcp-probe contract did not pass"
}
$mcpContextSummary = $mcpEvidence.operator_evidence.context.summary
if ([int]$mcpContextSummary.catalog_entry_count -lt 1 -or [int]$mcpContextSummary.visible_context_count -lt 1) {
    throw "mcp-probe did not observe a registered MCP context entry"
}
if ([int]$mcpContextSummary.failed_route_count -ne 0) {
    throw "mcp-probe observed an MCP context route failure"
}

& $python -X utf8 -m apps.api.agent_supervisor.commands.cli real-model-eval --output=apps/api/sandbox/reports
if ($LASTEXITCODE -ne 0) {
    throw "real-model-eval failed with exit code $LASTEXITCODE"
}

# Readiness fingerprints bind Provider routing, MCP routing, receipt posture,
# model-evaluation selector and source code. Run the report in this same
# process so it sees the exact environment used by the API and all probes.
& $python -X utf8 -m apps.api.agent_supervisor.commands.cli readiness --output=apps/api/sandbox/reports --write
if ($LASTEXITCODE -ne 0) {
    throw "readiness report generation failed"
}

# Generate the deterministic self-review after readiness so it sees the same
# Provider/MCP configuration and freshly written gateway evidence.  The JSON
# printed by the Node script is the gate summary; fail the evidence batch when
# any review item remains unresolved.
$selfReviewRaw = (& node scripts/project-self-review.mjs --output apps/api/sandbox/reports | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "project-self-review failed with exit code $LASTEXITCODE"
}
$selfReviewSummary = $selfReviewRaw | ConvertFrom-Json
if ([int]$selfReviewSummary.unresolved_count -ne 0) {
    throw "project-self-review unresolved_count was $($selfReviewSummary.unresolved_count)"
}
