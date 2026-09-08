$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

$env:PYTHONUTF8 = "1"
$env:AGENT_SUPERVISOR_API_HOST = "127.0.0.1"
$env:AGENT_SUPERVISOR_API_PORT = "8012"

# This is the single-machine launcher. Keep the local console login-free even
# when an older ignored .env still contains AUTH_DISABLED=false. Protected
# authentication remains available through an explicit direct server launch.
$env:AGENT_SUPERVISOR_AUTH_DISABLED = "true"

Write-Host "智垒本地运行环境启动中..."

function Test-LocalPortAvailable {
  param(
    [Parameter(Mandatory = $true)]
    [string]$HostAddress,
    [Parameter(Mandatory = $true)]
    [int]$Port
  )

  $listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Parse($HostAddress),
    $Port
  )
  try {
    $listener.Start()
    return $true
  } catch [System.Net.Sockets.SocketException] {
    return $false
  } finally {
    $listener.Stop()
  }
}

if (-not (Test-LocalPortAvailable -HostAddress $env:AGENT_SUPERVISOR_API_HOST -Port ([int]$env:AGENT_SUPERVISOR_API_PORT))) {
  throw "本地端口 $($env:AGENT_SUPERVISOR_API_PORT) 已被占用，智垒未启动。请先关闭占用该端口的程序后重试。"
}

# The API serves the production console bundle. Always rebuild it before a
# local start so source edits, deleted modules and authentication changes can
# never be hidden by an older dist directory.
Write-Host "正在构建最新控制台页面..."
npm run console:build
if ($LASTEXITCODE -ne 0) {
  throw "控制台构建失败，已停止启动；请先修复上方构建错误。"
}

$consoleUrl = "http://127.0.0.1:8012"
$statusUrl = "$consoleUrl/api/public/status"
$browserJob = $null
$pythonCommand = $env:AGENT_SUPERVISOR_PYTHON
$pythonArguments = @()
if (-not $pythonCommand) {
  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  if ($pyLauncher) {
    $pythonCommand = $pyLauncher.Source
    $pythonArguments = @("-3")
  }
}
if (-not $pythonCommand) {
  $pythonLauncher = Get-Command python -ErrorAction Stop
  $pythonCommand = $pythonLauncher.Source
}
try {
  $browserJob = Start-Job -ArgumentList $consoleUrl, $statusUrl -ScriptBlock {
    param($url, $healthUrl)
    for ($attempt = 0; $attempt -lt 120; $attempt += 1) {
      try {
        $response = Invoke-WebRequest -Uri $healthUrl -TimeoutSec 2 -UseBasicParsing
        $payload = $response.Content | ConvertFrom-Json
        if ($response.StatusCode -eq 200 -and $payload.ok -eq $true -and $payload.service -eq "agent-security-supervisor") {
          Start-Process $url
          return
        }
      } catch {
        Start-Sleep -Milliseconds 500
      }
    }
  }

  Write-Host "服务就绪后浏览器将打开 $consoleUrl"
  Write-Host "关闭本窗口即可停止本地服务。"
  & $pythonCommand @pythonArguments -X utf8 -m apps.api.dev_server
  $serverExitCode = $LASTEXITCODE
} finally {
  if ($browserJob) {
    Stop-Job -Job $browserJob -ErrorAction SilentlyContinue
    Remove-Job -Job $browserJob -Force -ErrorAction SilentlyContinue
  }
}

if ($serverExitCode -ne 0) {
  exit $serverExitCode
}
