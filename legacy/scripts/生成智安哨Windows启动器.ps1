$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

$Python = $env:PYTHON
if (-not $Python) {
  $Python = "python"
}

Write-Host "Building console..."
npm run console:build

Write-Host "Checking PyInstaller..."
& $Python -m PyInstaller --version | Out-Null

$ReleaseRoot = "apps\api\sandbox\release"
$DistPath = Join-Path $ReleaseRoot "dist"
$WorkPath = Join-Path $ReleaseRoot "build"
$SpecPath = Join-Path $ReleaseRoot "spec"
$ConsoleDist = Resolve-Path "apps\console\dist"
$ApiConfig = Resolve-Path "apps\api\agent_supervisor\config"
$SandboxFixtures = Resolve-Path "apps\api\sandbox\fixtures"

New-Item -ItemType Directory -Force -Path $ReleaseRoot | Out-Null
New-Item -ItemType Directory -Force -Path $DistPath | Out-Null
Remove-Item (Join-Path $DistPath "*.exe") -Force -ErrorAction SilentlyContinue

Write-Host "Building zhian-supervisor-launcher.exe..."
& $Python -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --name "zhian-supervisor-launcher" `
  --distpath $DistPath `
  --workpath $WorkPath `
  --specpath $SpecPath `
  --add-data "$ConsoleDist;apps\console\dist" `
  --add-data "$ApiConfig;apps\api\agent_supervisor\config" `
  --add-data "$SandboxFixtures;apps\api\sandbox\fixtures" `
  --collect-submodules "uvicorn" `
  --collect-submodules "httptools" `
  --collect-submodules "watchfiles" `
  --collect-submodules "websockets" `
  apps\api\portable_server.py

if ($LASTEXITCODE -ne 0) {
  throw "PyInstaller 打包失败，退出码：$LASTEXITCODE"
}

Write-Host "Done: $DistPath\zhian-supervisor-launcher.exe"
