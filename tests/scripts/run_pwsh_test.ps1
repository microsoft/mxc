# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# PowerShell Set-Location test runner.
#
# Usage:
#   .\run_pwsh_test.ps1              # debug build
#   .\run_pwsh_test.ps1 -Release     # release build

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
$TestConfig = Join-Path $RepoRoot "tests\configs\pwsh_setlocation.json"

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

Write-Host "Running PowerShell Set-Location test..." -ForegroundColor Cyan
& $WxcExec --debug $TestConfig
$exitCode = $LASTEXITCODE

if ($exitCode -ne 0) {
    Write-Host "FAILED: wxc-exec exited with code $exitCode" -ForegroundColor Red
    exit $exitCode
}

Write-Host "PASSED: PowerShell Set-Location test" -ForegroundColor Green
