$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

$env:PYTHONUTF8 = "1"
$env:AGENT_SUPERVISOR_API_HOST = "127.0.0.1"
$env:AGENT_SUPERVISOR_API_PORT = "8012"

# Keep an explicit .env security choice authoritative.  The previous launcher
# unconditionally forced local authentication off, which made a repository
# configured with AGENT_SUPERVISOR_AUTH_DISABLED=false silently run in a
# different security mode.  A clean local checkout without .env still gets the
# convenient loopback default; adding .env=false enables the real Token path.
$authConfigured = $false
$existingAuth = Get-Item Env:AGENT_SUPERVISOR_AUTH_DISABLED -ErrorAction SilentlyContinue
if ($existingAuth -and $existingAuth.Value) {
  $authConfigured = $true
}
$envPath = Join-Path $RepoRoot ".env"
if (-not $authConfigured -and (Test-Path $envPath)) {
  $authLine = Get-Content $envPath | Where-Object { $_ -match '^\s*AGENT_SUPERVISOR_AUTH_DISABLED\s*=' } | Select-Object -First 1
  if ($authLine) {
    $authValue = ($authLine -split "=", 2)[1].Trim().Trim('"').Trim("'")
    if ($authValue) {
      $env:AGENT_SUPERVISOR_AUTH_DISABLED = $authValue
      $authConfigured = $true
    }
  }
}
if (-not $authConfigured -and -not (Get-Item Env:AGENT_SUPERVISOR_AUTH_DISABLED -ErrorAction SilentlyContinue)) {
  $env:AGENT_SUPERVISOR_AUTH_DISABLED = "true"
}

Write-Host "智安哨本地运行环境启动中..."

if (-not (Test-Path "apps\console\dist\index.html")) {
  Write-Host "未检测到前端构建产物，正在构建控制台页面..."
  npm run console:build
}

Start-Job -ScriptBlock {
  Start-Sleep -Seconds 3
  Start-Process "http://127.0.0.1:8012"
} | Out-Null

Write-Host "浏览器将打开 http://127.0.0.1:8012"
Write-Host "关闭本窗口即可停止本地服务。"
python -X utf8 -m apps.api.dev_server
