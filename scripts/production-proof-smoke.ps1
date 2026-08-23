param(
  [switch]$FullRegression
)

$ErrorActionPreference = 'Stop'

function New-ProofToken {
  $bytes = New-Object byte[] 48
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($bytes)
  $rng.Dispose()
  [Convert]::ToBase64String($bytes)
}

$agentToken = New-ProofToken
$adminToken = New-ProofToken
$hmacKey = New-ProofToken
$runtimeDir = Join-Path (Get-Location) 'apps/api/sandbox/runtime/production-proof-8013'
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

$env:AGENT_SUPERVISOR_API_HOST = '127.0.0.1'
$env:AGENT_SUPERVISOR_API_PORT = '8013'
$env:AGENT_SUPERVISOR_AUTH_DISABLED = 'false'
$env:AGENT_SUPERVISOR_SECURITY_PROFILE = 'production'
$env:AGENT_SUPERVISOR_AUDIT_HMAC_KEY = $hmacKey
$env:AGENT_SUPERVISOR_AUDIT_HMAC_KEY_ID = 'production-proof-8013'
$env:AGENT_SUPERVISOR_API_TOKEN_ADMIN = $adminToken
$env:AGENT_SUPERVISOR_AGENT_TOKENS_JSON = @{ 'fixture-agent' = $agentToken } | ConvertTo-Json -Compress
$env:AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS = 'true'
$env:AGENT_SUPERVISOR_PROVIDER_DNS_MODE = 'doh'
$env:AGENT_SUPERVISOR_PROVIDER_DOH_URL = 'https://cloudflare-dns.com/dns-query'
$env:REAL_MODEL_EVALUATION_PROVIDER = 'zhipu'
$env:AGENT_SUPERVISOR_REAL_MODEL_EVALUATION_AGENT_ID = 'fixture-agent'
$env:AGENT_SUPERVISOR_RUNTIME_DIR = $runtimeDir
$env:PROOF_AGENT_TOKEN = $agentToken
$env:PROOF_ADMIN_TOKEN = $adminToken

$stdoutLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.stdout.log'
$stderrLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.stderr.log'
$proc = Start-Process -FilePath 'python' -ArgumentList '-X', 'utf8', '-m', 'apps.api.dev_server' -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog

try {
  $ready = $false
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 500
    try {
      $health = Invoke-WebRequest -Uri 'http://127.0.0.1:8013/api/health' -Headers @{ Authorization = "Bearer $adminToken" } -UseBasicParsing -TimeoutSec 3
      if ($health.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
  }
  if (-not $ready) {
    $errorText = if (Test-Path $stderrLog) { Get-Content $stderrLog -Raw } else { '' }
    throw "production proof server did not start: $errorText"
  }

  $settings = @{
    require_agent_capability_registration = $true
    require_agent_model_registration = $true
    require_agent_context_registration = $true
    agent_tool_allowlists = @{ 'fixture-agent' = @('file.read', 'file.write', 'api.call', 'mail.send') }
    agent_api_allowlists = @{ 'fixture-agent' = @('api.deepseek.com') }
    agent_model_allowlists = @{ 'fixture-agent' = @('deepseek-v4-pro') }
    agent_context_allowlists = @{ 'fixture-agent' = @{ resources = @('*'); resource_templates = @('*'); prompts = @('*') } }
    agent_tool_mappings = @{ 'fixture-agent' = @{ file_read = @{ capability = 'file.read'; argument_mapping = @{ path = 'path' }; required_arguments = @('path'); description = 'Read an approved sandbox file.' }; file_write = @{ capability = 'file.write'; argument_mapping = @{ path = 'path'; content = 'content' }; required_arguments = @('path', 'content'); description = 'Write an approved sandbox marker.' }; api_call = @{ capability = 'api.call'; argument_mapping = @{ endpoint = 'endpoint'; method = 'method' }; required_arguments = @('endpoint'); description = 'Call an approved external API.' }; mail_send = @{ capability = 'mail.send'; argument_mapping = @{ to = 'to'; subject = 'subject'; body = 'body' }; required_arguments = @('to', 'subject', 'body'); description = 'Send an approved sandbox mail.' } } }
    operator = 'production-proof'
    comment = 'Ephemeral production evidence binding for current gateway verification.'
  } | ConvertTo-Json -Depth 20
  Invoke-RestMethod -Uri 'http://127.0.0.1:8013/api/policy_settings' -Method Patch -Headers @{ Authorization = "Bearer $adminToken"; 'Content-Type' = 'application/json' } -Body $settings | Out-Null

  $probeLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.gateway-probe.log'
  $agentBoundaryLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.agent-boundary.log'
  $agentLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.gateway-agent.log'
  & node scripts/agent-supervisor-cli.mjs gateway-probe --payload-file apps/api/sandbox/examples/live-provider-smoke.json --url http://127.0.0.1:8013/v1/chat/completions --api-token-env PROOF_AGENT_TOKEN --session-id production-proof-8013 --timeout 180 --output apps/api/sandbox/reports/current-gateway-probe-8013.json --strict *> $probeLog
  $probeExit = $LASTEXITCODE
  & node scripts/agent-supervisor-cli.mjs gateway-agent-run --input apps/api/sandbox/examples/gateway-real-agent-cases.json --url http://127.0.0.1:8013/v1/chat/completions --api-token-env PROOF_AGENT_TOKEN --session-id production-agent-boundary-8013 --timeout 240 --output apps/api/sandbox/reports/production-agent-boundary-run-8013.json --strict *> $agentBoundaryLog
  $agentBoundaryExit = $LASTEXITCODE
  # sandbox-causal is deliberately an admin-only comparison operation. The
  # same request still crosses the production Agent gateway, while the admin
  # credential is used only to authorize the isolated baseline/control branch.
  & node scripts/agent-supervisor-cli.mjs gateway-agent-run --input apps/api/sandbox/examples/gateway-real-full-causal-cases.json --url http://127.0.0.1:8013/v1/chat/completions --causal-url http://127.0.0.1:8013/api/gateway/compare --api-token-env PROOF_ADMIN_TOKEN --session-id production-agent-8013 --timeout 240 --output apps/api/sandbox/reports/current-gateway-agent-run-8013.json --strict *> $agentLog
  $agentExit = $LASTEXITCODE

  if ($probeExit -ne 0 -or $agentBoundaryExit -ne 0 -or $agentExit -ne 0) {
    throw "production gateway evidence failed: probe=$probeExit boundary=$agentBoundaryExit causal=$agentExit"
  }

  if ($FullRegression) {
    & node scripts/agent-supervisor-cli.mjs real-model-eval --output apps/api/sandbox/reports *> (Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.real-model.log')
    $realModelExit = $LASTEXITCODE
    & node scripts/agent-supervisor-cli.mjs batch --guard compare *> (Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.batch-compare.log')
    $batchExit = $LASTEXITCODE
    if ($realModelExit -ne 0 -or $batchExit -ne 0) {
      throw "production evaluation evidence failed: real_model=$realModelExit batch=$batchExit"
    }
    & node scripts/agent-supervisor-cli.mjs readiness --write --output apps/api/sandbox/reports *> (Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.readiness.log')
    $readinessExit = $LASTEXITCODE
    & node scripts/project-self-review.mjs --output apps/api/sandbox/reports *> (Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.self-review.log')
    $selfReviewExit = $LASTEXITCODE
    if ($readinessExit -ne 0 -or $selfReviewExit -ne 0) {
      throw "production readiness evidence failed: readiness=$readinessExit self_review=$selfReviewExit"
    }
  }

  $fullRegressionText = if ($FullRegression) { 'true' } else { 'false' }
  & python -X utf8 -c "import json; from pathlib import Path; p=json.loads(Path('apps/api/sandbox/reports/current-gateway-probe-8013.json').read_text(encoding='utf-8')); a=json.loads(Path('apps/api/sandbox/reports/current-gateway-agent-run-8013.json').read_text(encoding='utf-8')); full_regression='$fullRegressionText' == 'true'; result={'server_pid': $($proc.Id), 'full_regression': full_regression, 'probe_exit': $probeExit, 'agent_boundary_exit': $agentBoundaryExit, 'agent_exit': $agentExit, 'probe_passed': p['contract']['passed'], 'agent_verdict': a['summary']['evidence_verdict'], 'cases': a['summary']['case_count'], 'tool_calls': a['summary']['provider_tool_call_count'], 'managed': a['summary']['managed_execution_count'], 'server_receipts': a['summary']['server_observed_receipt_count'], 'public_routes': a['summary']['network_verified_external_provider_evidence_count'], 'output': 'apps/api/sandbox/reports/current-gateway-probe-8013.json; apps/api/sandbox/reports/current-gateway-agent-run-8013.json; apps/api/sandbox/reports/production-agent-boundary-run-8013.json'}; readiness=Path('apps/api/sandbox/reports/AI Agent安全网关就绪检查.json'); result.update(json.loads(readiness.read_text(encoding='utf-8')) if full_regression and readiness.exists() else {}); print(json.dumps(result,ensure_ascii=False))"
  if ($FullRegression) {
    $readiness = Get-Content 'apps/api/sandbox/reports/AI Agent安全网关就绪检查.json' -Raw | ConvertFrom-Json
    [pscustomobject]@{
      readiness_score = $readiness.readiness_score
      production_ready = $readiness.production_ready
      evaluation_ready = $readiness.evaluation_ready
      completion_claim_allowed = $readiness.completion_claim_allowed
      blocker_count = $readiness.summary.blocker_count
      warning_count = $readiness.summary.warning_count
    } | ConvertTo-Json -Compress
  }
} finally {
  if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
  Remove-Item Env:AGENT_SUPERVISOR_API_HOST, Env:AGENT_SUPERVISOR_API_PORT, Env:AGENT_SUPERVISOR_AUTH_DISABLED, Env:AGENT_SUPERVISOR_SECURITY_PROFILE, Env:AGENT_SUPERVISOR_AUDIT_HMAC_KEY, Env:AGENT_SUPERVISOR_AUDIT_HMAC_KEY_ID, Env:AGENT_SUPERVISOR_API_TOKEN_ADMIN, Env:AGENT_SUPERVISOR_AGENT_TOKENS_JSON, Env:AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS, Env:AGENT_SUPERVISOR_PROVIDER_DNS_MODE, Env:AGENT_SUPERVISOR_PROVIDER_DOH_URL, Env:REAL_MODEL_EVALUATION_PROVIDER, Env:AGENT_SUPERVISOR_REAL_MODEL_EVALUATION_AGENT_ID, Env:AGENT_SUPERVISOR_RUNTIME_DIR, Env:PROOF_AGENT_TOKEN, Env:PROOF_ADMIN_TOKEN -ErrorAction SilentlyContinue
}
