param(
  [switch]$FullRegression,
  [ValidateSet('system', 'doh')]
  [string]$ProviderDnsMode = 'system'
)

$ErrorActionPreference = 'Stop'

function New-ProofToken {
  $bytes = New-Object byte[] 48
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($bytes)
  $rng.Dispose()
  [Convert]::ToBase64String($bytes)
}

function Get-Sha256Hex {
  param(
    [Parameter(Mandatory = $true)][string]$Value
  )

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
    return -join ($bytes | ForEach-Object { $_.ToString('x2') })
  } finally {
    $sha.Dispose()
  }
}

function Invoke-ApprovalProof {
  param(
    [Parameter(Mandatory = $true)][string]$Suffix,
    [Parameter(Mandatory = $true)][ValidateSet('approve', 'reject')][string]$Action,
    [Parameter(Mandatory = $true)][string]$AgentToken,
    [Parameter(Mandatory = $true)][string]$AdminToken
  )

  $toolCall = @{
    tool = 'mail.send'
    arguments = @{
      to = "external-$Suffix@example.net"
      subject = "Production approval proof $Suffix"
      body = "Controlled approval evidence $Suffix"
    }
  }
  $event = @{
    conversation_id = "production-approval-$Suffix"
    agent_id = 'fixture-agent'
    agent_role = 'production-proof-agent'
    source_app = 'production-proof'
    model_input = 'Evaluate this external notification and require an operator decision.'
    model_output = ''
    tool_call = $toolCall
    context_sources = @('production-proof')
  } | ConvertTo-Json -Depth 10 -Compress
  $evaluation = Invoke-RestMethod -Uri 'http://127.0.0.1:8013/api/runtime/evaluate' -Method Post -Headers @{ Authorization = "Bearer $AgentToken"; 'Content-Type' = 'application/json' } -Body $event
  if ($evaluation.policy_id -ne 'external-mail' -or -not $evaluation.audit_id -or -not $evaluation.approval_review.id) {
    throw "approval proof did not enter review: suffix=$Suffix decision=$($evaluation.decision)"
  }

  $inventory = Invoke-RestMethod -Uri 'http://127.0.0.1:8013/api/approvals?limit=100' -Headers @{ Authorization = "Bearer $AdminToken" }
  $review = $inventory.reviews | Where-Object { $_.audit_id -eq $evaluation.audit_id } | Select-Object -First 1
  if (-not $review -or -not $review.id) { throw "approval proof review missing: suffix=$Suffix" }

  $decision = @{
    action = $Action
    operator = 'production-proof-operator'
    comment = "Production proof $Action decision for $Suffix."
  } | ConvertTo-Json -Compress
  $decisionResult = Invoke-RestMethod -Uri "http://127.0.0.1:8013/api/approvals/$($review.id)/decision" -Method Post -Headers @{ Authorization = "Bearer $AdminToken"; 'Content-Type' = 'application/json' } -Body $decision
  if ($decisionResult.review.approval_action -ne $Action -or -not $decisionResult.review.hash_valid) {
    throw "approval proof decision evidence invalid: suffix=$Suffix action=$Action"
  }

  if ($Action -eq 'approve') {
    $claimBody = @{ agent_id = 'fixture-agent'; tool_call = $toolCall } | ConvertTo-Json -Depth 10 -Compress
    $claim = Invoke-RestMethod -Uri "http://127.0.0.1:8013/api/approvals/$($review.id)/claim" -Method Post -Headers @{ Authorization = "Bearer $AgentToken"; 'Content-Type' = 'application/json' } -Body $claimBody
    if (-not $claim.granted -or -not $claim.claim_id) { throw 'approved proof call was not claimable' }
    $resultHash = Get-Sha256Hex -Value $Suffix
    $completeBody = @{ agent_id = 'fixture-agent'; claim_id = $claim.claim_id; succeeded = $true; result_hash = $resultHash } | ConvertTo-Json -Compress
    $completed = Invoke-RestMethod -Uri "http://127.0.0.1:8013/api/approvals/$($review.id)/complete" -Method Post -Headers @{ Authorization = "Bearer $AgentToken"; 'Content-Type' = 'application/json' } -Body $completeBody
    if ($completed.review.execution_status -ne 'completed' -or -not $completed.review.hash_valid) {
      throw 'approved proof call completion evidence is invalid'
    }
  }

  $persistedReview = Invoke-RestMethod -Uri "http://127.0.0.1:8013/api/approvals/$($review.id)" -Headers @{ Authorization = "Bearer $AdminToken" }
  $expectedExecutionStatus = if ($Action -eq 'approve') { 'completed' } else { 'rejected' }
  if (
    $persistedReview.approval_action -ne $Action -or
    $persistedReview.execution_status -ne $expectedExecutionStatus -or
    -not $persistedReview.hash_valid
  ) {
    throw "approval proof persisted evidence invalid: suffix=$Suffix action=$Action"
  }
  return $persistedReview
}

$agentToken = New-ProofToken
$adminToken = New-ProofToken
$hmacKey = New-ProofToken
$mcpRequestStateSecret = New-ProofToken
$pythonPath = (Get-Command python -ErrorAction Stop).Source
$quote = [char]34
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
$env:AGENT_SUPERVISOR_PROVIDER_DNS_MODE = $ProviderDnsMode
$env:AGENT_SUPERVISOR_PROVIDER_DOH_URL = 'https://cloudflare-dns.com/dns-query'
$env:REAL_MODEL_EVALUATION_PROVIDER = 'zhipu'
$env:AGENT_SUPERVISOR_REAL_MODEL_EVALUATION_AGENT_ID = 'fixture-agent'
$env:AGENT_SUPERVISOR_RUNTIME_DIR = $runtimeDir
$env:MCP_GATEWAY_ENABLED = 'true'
$env:MCP_GATEWAY_GUARD_ENABLED = 'true'
$env:MCP_GATEWAY_UPSTREAM_COMMAND = $quote + $pythonPath + $quote + ' -X utf8 -m apps.api.tests.fixtures.mcp_echo_server'
$env:MCP_GATEWAY_SESSION_ISOLATION = 'true'
$env:MCP_GATEWAY_RESOURCE_LIMITS_ENABLED = 'true'
$env:MCP_GATEWAY_NETWORK_MODE = 'reject-unpinned'
$env:MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS = 'false'
$env:MCP_GATEWAY_REQUEST_STATE_SECRET = $mcpRequestStateSecret
$env:PROOF_AGENT_TOKEN = $agentToken
$env:PROOF_ADMIN_TOKEN = $adminToken

$proc = $null
try {
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
}
$env:PROOF_POLICY_SETTINGS_JSON = $settings | ConvertTo-Json -Depth 20 -Compress
# The runtime fingerprint is intentionally a startup snapshot. Seed the exact
# least-privilege policy before the API process starts; changing it through
# HTTP afterwards would correctly make the later CLI deployment fingerprint
# differ from the process-start evidence.
& python -X utf8 -c "import json,os; from apps.api.agent_supervisor.storage.data import update_policy_settings; update_policy_settings(json.loads(os.environ['PROOF_POLICY_SETTINGS_JSON']))" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'production proof policy pre-seed failed' }

$stdoutLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.stdout.log'
$stderrLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.stderr.log'
$proc = Start-Process -FilePath 'python' -ArgumentList '-X', 'utf8', '-m', 'apps.api.dev_server' -WorkingDirectory (Get-Location) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog

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

  $probeLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.gateway-probe.log'
  $agentBoundaryLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.agent-boundary.log'
  $agentLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.gateway-agent.log'
  $mcpLog = Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.mcp.log'
  & node scripts/agent-supervisor-cli.mjs gateway-probe --payload-file apps/api/sandbox/examples/live-provider-smoke.json --url http://127.0.0.1:8013/v1/chat/completions --api-token-env PROOF_AGENT_TOKEN --session-id production-proof-8013 --timeout 180 --output apps/api/sandbox/reports/current-gateway-probe-8013.json --strict *> $probeLog
  $probeExit = $LASTEXITCODE
  & node scripts/agent-supervisor-cli.mjs gateway-agent-run --input apps/api/sandbox/examples/gateway-real-agent-cases.json --url http://127.0.0.1:8013/v1/chat/completions --api-token-env PROOF_AGENT_TOKEN --session-id production-agent-boundary-8013 --timeout 240 --output apps/api/sandbox/reports/production-agent-boundary-run-8013.json --strict *> $agentBoundaryLog
  $agentBoundaryExit = $LASTEXITCODE
  # sandbox-causal is deliberately an admin-only comparison operation. The
  # same request still crosses the production Agent gateway, while the admin
  # credential is used only to authorize the isolated baseline/control branch.
  & node scripts/agent-supervisor-cli.mjs gateway-agent-run --input apps/api/sandbox/examples/gateway-real-full-causal-cases.json --url http://127.0.0.1:8013/v1/chat/completions --causal-url http://127.0.0.1:8013/api/gateway/compare --api-token-env PROOF_ADMIN_TOKEN --session-id production-agent-8013 --timeout 240 --output apps/api/sandbox/reports/current-gateway-agent-run-8013.json --strict *> $agentLog
  $agentExit = $LASTEXITCODE
  & node scripts/agent-supervisor-cli.mjs mcp-probe --url http://127.0.0.1:8013/api/mcp --api-token-env PROOF_AGENT_TOKEN --operator-api-token-env PROOF_ADMIN_TOKEN --operator-agent-id fixture-agent --session-id production-mcp-8013 --tool file.read --output apps/api/sandbox/reports/current-mcp-probe-8013.json --strict *> $mcpLog
  $mcpExit = $LASTEXITCODE

  if ($probeExit -ne 0 -or $agentBoundaryExit -ne 0 -or $agentExit -ne 0 -or $mcpExit -ne 0) {
    throw "production gateway evidence failed: probe=$probeExit boundary=$agentBoundaryExit causal=$agentExit mcp=$mcpExit"
  }

  $approvedReview = Invoke-ApprovalProof -Suffix "approve-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())" -Action approve -AgentToken $agentToken -AdminToken $adminToken
  $rejectedReview = Invoke-ApprovalProof -Suffix "reject-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())" -Action reject -AgentToken $agentToken -AdminToken $adminToken
  if ($approvedReview.execution_status -ne 'completed' -or $rejectedReview.execution_status -ne 'rejected') {
    throw 'production approval proof did not persist both terminal decisions'
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
    if ($readinessExit -eq 0) {
      # Windows PowerShell 5.1 parses UTF-8 scripts through the active system
      # code page. Discover the generated readiness artifact by its schema and
      # publish an ASCII alias so the proof summary does not depend on a
      # locale-sensitive Chinese filename.
      & python -X utf8 -c "from pathlib import Path; d=Path('apps/api/sandbox/reports'); rows=[(p.stat().st_mtime,p) for p in d.glob('*.json') if 'readiness_score' in p.read_text(encoding='utf-8') and 'completion_claim_allowed' in p.read_text(encoding='utf-8')]; p=max(rows)[1]; (d/'current-readiness.json').write_text(p.read_text(encoding='utf-8'),encoding='utf-8')"
      if ($LASTEXITCODE -ne 0) { $readinessExit = $LASTEXITCODE }
    }
    if ($readinessExit -eq 0) {
      & python -X utf8 -c "import json,sys; from pathlib import Path; d=json.loads(Path('apps/api/sandbox/reports/current-readiness.json').read_text(encoding='utf-8')); sys.exit(0 if d.get('production_ready') is True and d.get('evaluation_ready') is True else 1)"
      $readinessExit = $LASTEXITCODE
    }
    & node scripts/project-self-review.mjs --output apps/api/sandbox/reports *> (Join-Path (Get-Location) 'apps/api/sandbox/reports/production-proof-8013.self-review.log')
    $selfReviewExit = $LASTEXITCODE
    if ($readinessExit -ne 0 -or $selfReviewExit -ne 0) {
      throw "production readiness evidence failed: readiness=$readinessExit self_review=$selfReviewExit"
    }
  }

  $fullRegressionText = if ($FullRegression) { 'true' } else { 'false' }
  & python -X utf8 -c "import json; from pathlib import Path; from apps.api.agent_supervisor.domains.runtime.server_security import load_environment_file; load_environment_file(); from apps.api.agent_supervisor.domains.reports.gateway_evidence import gateway_code_fingerprint,gateway_source_fingerprint; p=json.loads(Path('apps/api/sandbox/reports/current-gateway-probe-8013.json').read_text(encoding='utf-8')); a=json.loads(Path('apps/api/sandbox/reports/current-gateway-agent-run-8013.json').read_text(encoding='utf-8')); m=json.loads(Path('apps/api/sandbox/reports/current-mcp-probe-8013.json').read_text(encoding='utf-8')); full_regression='$fullRegressionText' == 'true'; result={'server_pid': $($proc.Id), 'full_regression': full_regression, 'probe_exit': $probeExit, 'agent_boundary_exit': $agentBoundaryExit, 'agent_exit': $agentExit, 'mcp_exit': $mcpExit, 'probe_passed': p['contract']['passed'], 'agent_verdict': a['summary']['evidence_verdict'], 'mcp_verdict': m['summary']['evidence_verdict'], 'mcp_operator_evidence_passed': m['summary']['operator_evidence_passed'], 'code_fingerprint_matches_proof_context': p['gateway_code_fingerprint'] == gateway_code_fingerprint(), 'source_fingerprint_matches_proof_context': p['gateway_source_fingerprint'] == gateway_source_fingerprint(), 'mcp_source_fingerprint_matches_proof_context': m['gateway_source_fingerprint'] == gateway_source_fingerprint(), 'approval_approved_and_completed': '$($approvedReview.execution_status)' == 'completed', 'approval_rejected': '$($rejectedReview.execution_status)' == 'rejected', 'approval_hashes_valid': '$($approvedReview.hash_valid)' == 'True' and '$($rejectedReview.hash_valid)' == 'True', 'cases': a['summary']['case_count'], 'tool_calls': a['summary']['provider_tool_call_count'], 'managed': a['summary']['managed_execution_count'], 'server_receipts': a['summary']['server_observed_receipt_count'], 'public_routes': a['summary']['network_verified_external_provider_evidence_count'], 'mcp_visible_tools': m['summary']['visible_tool_count'], 'output': 'apps/api/sandbox/reports/current-gateway-probe-8013.json; apps/api/sandbox/reports/current-gateway-agent-run-8013.json; apps/api/sandbox/reports/production-agent-boundary-run-8013.json; apps/api/sandbox/reports/current-mcp-probe-8013.json'}; readiness_path=Path('apps/api/sandbox/reports/current-readiness.json'); readiness=json.loads(readiness_path.read_text(encoding='utf-8')) if full_regression and readiness_path.exists() else {}; summary=readiness.get('summary',{}); result.update({'overall_status': readiness.get('overall_status'), 'readiness_score': readiness.get('readiness_score'), 'production_ready': readiness.get('production_ready'), 'production_claim_allowed': readiness.get('production_claim_allowed'), 'gateway_ready': readiness.get('gateway_ready'), 'evaluation_ready': readiness.get('evaluation_ready'), 'completion_claim_allowed': readiness.get('completion_claim_allowed'), 'passed_count': summary.get('passed_count'), 'warning_count': summary.get('warning_count'), 'blocker_count': summary.get('blocker_count'), 'production_gap_count': len(readiness.get('production_gaps',[])), 'blocker_ids': [item.get('id') for item in readiness.get('blockers',[])], 'mcp_adapter_status': readiness.get('readiness_domains',{}).get('mcp_adapter',{}).get('status'), 'readiness_output': str(readiness_path)} if readiness else {}); print(json.dumps(result,ensure_ascii=False))"
} finally {
  if ($proc -and -not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    [void]$proc.WaitForExit(10000)
  }
  if ($proc -and -not $proc.HasExited) { throw 'production proof server did not stop' }
  if ($proc -and $proc.HasExited) {
    $activeDir = Join-Path $runtimeDir '.runtime-active'
    Get-ChildItem -LiteralPath $activeDir -Filter "$($proc.Id)-*.json" -File -ErrorAction SilentlyContinue |
      Remove-Item -Force -ErrorAction SilentlyContinue
  }
  Remove-Item Env:AGENT_SUPERVISOR_API_HOST, Env:AGENT_SUPERVISOR_API_PORT, Env:AGENT_SUPERVISOR_AUTH_DISABLED, Env:AGENT_SUPERVISOR_SECURITY_PROFILE, Env:AGENT_SUPERVISOR_AUDIT_HMAC_KEY, Env:AGENT_SUPERVISOR_AUDIT_HMAC_KEY_ID, Env:AGENT_SUPERVISOR_API_TOKEN_ADMIN, Env:AGENT_SUPERVISOR_AGENT_TOKENS_JSON, Env:AGENT_SUPERVISOR_PROXY_REQUIRE_SERVER_OBSERVED_RECEIPTS, Env:AGENT_SUPERVISOR_PROVIDER_DNS_MODE, Env:AGENT_SUPERVISOR_PROVIDER_DOH_URL, Env:REAL_MODEL_EVALUATION_PROVIDER, Env:AGENT_SUPERVISOR_REAL_MODEL_EVALUATION_AGENT_ID, Env:AGENT_SUPERVISOR_RUNTIME_DIR, Env:MCP_GATEWAY_ENABLED, Env:MCP_GATEWAY_GUARD_ENABLED, Env:MCP_GATEWAY_UPSTREAM_COMMAND, Env:MCP_GATEWAY_SESSION_ISOLATION, Env:MCP_GATEWAY_RESOURCE_LIMITS_ENABLED, Env:MCP_GATEWAY_NETWORK_MODE, Env:MCP_GATEWAY_ALLOW_SIDE_EFFECT_NOTIFICATIONS, Env:MCP_GATEWAY_REQUEST_STATE_SECRET, Env:PROOF_AGENT_TOKEN, Env:PROOF_ADMIN_TOKEN, Env:PROOF_POLICY_SETTINGS_JSON -ErrorAction SilentlyContinue
}
