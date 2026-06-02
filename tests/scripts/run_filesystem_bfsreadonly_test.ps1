# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# BFS filesystem read-only test runner.
# Creates a temporary directory with a test input file, runs the test,
# and cleans up regardless of outcome.
#
# Usage:
#   .\run_filesystem_bfsreadonly_test.ps1              # debug build
#   .\run_filesystem_bfsreadonly_test.ps1 -Release     # release build

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
$TestConfig = Join-Path $RepoRoot "tests\configs\filesystem_bfs_readonly_test.json"

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

$TestDir = "C:\temp\wxc_test_allowedreadonly"

try {
    New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
    Set-Content -Path (Join-Path $TestDir "test_input.txt") -Value "Test Input"

    Write-Host "Running BFS filesystem read-only test..." -ForegroundColor Cyan
    & $WxcExec --debug $TestConfig
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "FAILED: wxc-exec exited with code $exitCode" -ForegroundColor Red
        exit $exitCode
    }

    Write-Host "PASSED: BFS filesystem read-only test" -ForegroundColor Green
} finally {
    if (Test-Path $TestDir) {
        Remove-Item -Recurse -Force $TestDir -ErrorAction SilentlyContinue
    }
}
