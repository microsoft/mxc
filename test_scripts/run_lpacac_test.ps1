# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Less-Privileged AppContainer (LPAC) test runner.
#
# Usage:
#   .\run_lpacac_test.ps1              # debug build
#   .\run_lpacac_test.ps1 -Release     # release build

param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

if ($Release) {
    $BinDir = Join-Path $RepoRoot "src\target\release"
} else {
    $BinDir = Join-Path $RepoRoot "src\target\debug"
}

$WxcExec = Join-Path $BinDir "wxc-exec.exe"
$TestConfig = Join-Path $RepoRoot "test_configs\basic_lpac.json"

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

Write-Host "Running LPAC AppContainer test..." -ForegroundColor Cyan
& $WxcExec --debug $TestConfig
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    Write-Host "FAILED: wxc-exec exited with code $exitCode" -ForegroundColor Red
    exit $exitCode
}

Write-Host "PASSED: LPAC AppContainer test" -ForegroundColor Green
