[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateRange(0, 8760)]
    [int]$MinimumAgeHours = 24
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoPrefix = $repoRoot + [IO.Path]::DirectorySeparatorChar
$cutoff = (Get-Date).AddHours(-$MinimumAgeHours)

$protectedPaths = @(
    (Join-Path $repoRoot ".git"),
    (Join-Path $repoRoot ".env"),
    (Join-Path $repoRoot "apps\api\runtime\operational"),
    (Join-Path $repoRoot "apps\api\runtime\backups"),
    (Join-Path $repoRoot "docs\media"),
    (Join-Path $repoRoot "apps\console\dist"),
    (Join-Path $repoRoot "apps\console\node_modules")
)

function Assert-WorkspacePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "清理目标超出项目目录：$fullPath"
    }
    foreach ($protectedPath in $protectedPaths) {
        if ($fullPath.Equals($protectedPath, [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($protectedPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "清理目标进入受保护目录：$fullPath"
        }
    }
    return $fullPath
}

$candidates = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()

Get-ChildItem -LiteralPath $repoRoot -Force |
    Where-Object {
        $_.Name -like ".tmp-*" -or
        $_.Name -like "gateway-*.png" -or
        $_.Name -in @(".coverage", ".trae", "session.md", "test-results", "playwright-report")
    } |
    ForEach-Object { $candidates.Add($_) }

@(
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".playwright-mcp",
    "verification",
    "apps\console\.playwright-mcp"
) | ForEach-Object {
    $path = Join-Path $repoRoot $_
    if (Test-Path -LiteralPath $path) {
        $candidates.Add((Get-Item -LiteralPath $path -Force))
    }
}

# Quality and browser output is reproducible and must stay separate from the
# operational database and backups. Only named generated directories are eligible.
@(
    "apps\api\runtime\quality\mypy",
    "apps\api\runtime\quality\ruff",
    "apps\api\runtime\quality\pytest",
    "apps\api\runtime\quality\.coverage",
    "apps\api\runtime\quality\baseline-worktree",
    "apps\api\runtime\quality\favicon-check",
    "apps\api\runtime\quality\live-closure-real",
    "apps\api\runtime\e2e"
) | ForEach-Object {
    $path = Join-Path $repoRoot $_
    if (Test-Path -LiteralPath $path) {
        $candidates.Add((Get-Item -LiteralPath $path -Force))
    }
}

Get-ChildItem -LiteralPath (Join-Path $repoRoot "apps\api\runtime\quality") -Directory -Filter "preview-*" -Force -ErrorAction SilentlyContinue |
    ForEach-Object { $candidates.Add($_) }

foreach ($sourceRoot in @("apps\api\agent_supervisor", "apps\api\tests")) {
    $sourcePath = Join-Path $repoRoot $sourceRoot
    if (Test-Path -LiteralPath $sourcePath) {
        Get-ChildItem -LiteralPath $sourcePath -Directory -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache") } |
            ForEach-Object { $candidates.Add($_) }
    }
}

$apiCachePath = Join-Path $repoRoot "apps\api\__pycache__"
if (Test-Path -LiteralPath $apiCachePath) {
    $candidates.Add((Get-Item -LiteralPath $apiCachePath -Force))
}

$rootNodeModulesPath = Join-Path $repoRoot "node_modules"
if (Test-Path -LiteralPath $rootNodeModulesPath) {
    $rootNodeModulesChildren = @(Get-ChildItem -LiteralPath $rootNodeModulesPath -Force)
    if (-not $rootNodeModulesChildren.Count -or
        ($rootNodeModulesChildren.Count -eq 1 -and $rootNodeModulesChildren[0].Name -eq ".vite")) {
        $candidates.Add((Get-Item -LiteralPath $rootNodeModulesPath -Force))
    }
}

$eligible = @(
    $candidates |
        Where-Object {
            $_.LastWriteTime -lt $cutoff -and
            -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
        } |
        Sort-Object FullName -Unique
)

if (-not $eligible.Count) {
    Write-Host "没有符合条件的本地残留。"
    exit 0
}

foreach ($item in $eligible) {
    $fullPath = Assert-WorkspacePath -Path $item.FullName
    $relativePath = [IO.Path]::GetRelativePath($repoRoot, $fullPath)
    if ($Apply) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
        Write-Host "已清理：$relativePath"
    } else {
        Write-Host "待清理：$relativePath"
    }
}

if (-not $Apply) {
    Write-Host "当前是预览模式；确认列表后添加 -Apply 执行清理。"
}
