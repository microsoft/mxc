# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# BFS filesystem test runner.
# The contained command creates its own fixture under C:\Users\Public.
# The runner only removes stale artifacts after the test.
#
# Usage:
#   .\run_filesystem_bfs_test.ps1              # debug build
#   .\run_filesystem_bfs_test.ps1 -Release     # release build

param(
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $BinDir) {
    if ($Release) {
        $BinDir = Join-Path $RepoRoot "src\target\release"
    } else {
        $BinDir = Join-Path $RepoRoot "src\target\debug"
    }
}

$WxcExec = Join-Path $BinDir "wxc-exec.exe"
$TestConfig = Join-Path $RepoRoot "tests\configs\filesystem_bfs_test.json"

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

$TestDirs = @(
    "C:\Users\Public\mxc_bfs_allowed",
    "C:\ProgramData\mxc_bfs_outside"
)

try {
    Write-Host "Running BFS filesystem test..." -ForegroundColor Cyan
    & $WxcExec --debug $TestConfig
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "FAILED: wxc-exec exited with code $exitCode" -ForegroundColor Red
        exit $exitCode
    }

    Write-Host "PASSED: BFS filesystem test" -ForegroundColor Green
} finally {
    foreach ($dir in $TestDirs) {
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        }
    }
}
