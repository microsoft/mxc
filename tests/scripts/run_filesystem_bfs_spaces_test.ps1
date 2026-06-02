# Tests that BFS paths with spaces (e.g. "C:\Users\Public\wxc bfs test") are
# quoted correctly when passed to bfscfg.exe.

param(
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $BinDir) {
    if ($Release) {
        $BinDir = Join-Path $RepoRoot "src\target\release"
    } else {
        $BinDir = Join-Path $RepoRoot "src\target\debug"
    }
}

$wxcExe = Join-Path $BinDir "wxc-exec.exe"
$testConfig = Join-Path $RepoRoot "tests\configs\filesystem_bfs_spaces_test.json"
$testDir = "C:\Users\Public\wxc bfs test"

if (-not (Test-Path $wxcExe)) {
    Write-Host "ERROR: wxc-exec.exe not found at $wxcExe" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' from src/ first." -ForegroundColor Yellow
    exit 1
}

try {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null

    Write-Host "Running BFS spaces-in-path test..."
    & $wxcExe --debug $testConfig
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "FAILED: wxc-exec exited with code $exitCode" -ForegroundColor Red
        exit $exitCode
    }

    Write-Host "PASSED: BFS path with spaces handled correctly" -ForegroundColor Green
} finally {
    if (Test-Path $testDir) {
        Remove-Item -Recurse -Force $testDir
    }
}
