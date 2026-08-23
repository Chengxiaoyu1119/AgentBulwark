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
$env:AGENT_SUPERVISOR_API_PORT = "8034"
$env:AGENT_SUPERVISOR_API_TOKEN = "admin-token"
$env:AGENT_SUPERVISOR_DEFAULT_ROLE = "admin"
$env:AGENT_SUPERVISOR_AUTH_DISABLED = "false"
$env:AGENT_SUPERVISOR_SECURITY_PROFILE = "local"
$env:AGENT_SUPERVISOR_LABS_ENABLED = "true"
$env:AGENT_SUPERVISOR_RUNTIME_DIR = Join-Path $repoRoot "apps\api\sandbox\runtime\fixture-evidence-8034"
$env:AGENT_SUPERVISOR_AGENT_TOKENS_JSON = (@{ "fixture-agent" = "fixture-agent-token" } | ConvertTo-Json -Compress)
$env:AGENT_SUPERVISOR_REAL_MODEL_EVALUATION_AGENT_ID = "real-model-target-agent"
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
$fixturePolicyScript = @'
from apps.api.agent_supervisor.adapters.models.model_adapter import provider_status
from apps.api.agent_supervisor.storage.data import update_policy_settings

agent_ids = ('real-model-target-agent', 'fixture-agent', 'openai-compatible-proxy')
configured_models = sorted({
    str(item.get('model') or '').strip()
    for item in provider_status('target')
    if item.get('configured') and str(item.get('model') or '').strip()
})
if not configured_models:
    raise SystemExit('Fixture evidence requires at least one configured target model.')
update_policy_settings({
    'require_agent_capability_registration': True,
    'require_agent_model_registration': True,
    'require_agent_context_registration': True,
    'agent_tool_allowlists': {
        'real-model-target-agent': ['file.read', 'api.call', 'mail.send'],
        'fixture-agent': ['file.read', 'file.write', 'api.call', 'mail.send'],
        'openai-compatible-proxy': ['file.read', 'file.write', 'api.call', 'mail.send'],
    },
    'agent_api_allowlists': {agent_id: [] for agent_id in agent_ids},
    'agent_model_allowlists': {agent_id: configured_models for agent_id in agent_ids},
    'agent_context_allowlists': {
        agent_id: {
            'resources': ['fixture://public/*'],
            'resource_templates': ['fixture://public/{name}'],
            'prompts': ['fixture-summary'],
        }
        for agent_id in agent_ids
    },
})
'@
& $python -X utf8 -c $fixturePolicyScript
if ($LASTEXITCODE -ne 0) {
    throw "Failed to initialize fixture evidence Agent policy bindings."
}
& $python -m apps.api.dev_server
