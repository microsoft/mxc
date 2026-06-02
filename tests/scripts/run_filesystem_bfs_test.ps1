# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# BFS filesystem test runner.
# Creates temporary directories required by the test config, runs the test,
# and cleans up regardless of outcome.
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

$TempDirs = @(
    "C:\temp\wxc_test_allowed",
    "C:\temp\wxc_test_denied"
)

try {
    foreach ($dir in $TempDirs) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    Write-Host "Running BFS filesystem test..." -ForegroundColor Cyan
    & $WxcExec --debug $TestConfig
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "FAILED: wxc-exec exited with code $exitCode" -ForegroundColor Red
        exit $exitCode
    }

    Write-Host "PASSED: BFS filesystem test" -ForegroundColor Green
} finally {
    foreach ($dir in $TempDirs) {
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        }
    }
}
