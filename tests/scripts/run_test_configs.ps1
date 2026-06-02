# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Runs wxc-test-driver against all test configs.
# Creates temporary directories required by various test configs, runs the
# test driver, and cleans up regardless of outcome.
#
# Usage:
#   .\run_test_configs.ps1              # debug build
#   .\run_test_configs.ps1 -Release     # release build

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

$TestDriver = Join-Path $BinDir "wxc-test-driver.exe"
$TestConfigsDir = Join-Path $RepoRoot "tests\configs"

if (-not (Test-Path $TestDriver)) {
    Write-Host "ERROR: wxc-test-driver.exe not found at $TestDriver" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

$TempDirs = @(
    "C:\temp\wxc_test_allowed",
    "C:\temp\wxc_test_allowedreadonly",
    "C:\temp\wxc_test_denied"
)

try {
    foreach ($dir in $TempDirs) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Set-Content -Path "C:\temp\wxc_test_allowedreadonly\test_input.txt" -Value "Test Input"

    Write-Host "Running wxc-test-driver against tests/configs..." -ForegroundColor Cyan
    & $TestDriver $TestConfigsDir
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "FAILED: wxc-test-driver exited with code $exitCode" -ForegroundColor Red
        exit $exitCode
    }

    Write-Host "PASSED: all test configs" -ForegroundColor Green
} finally {
    foreach ($dir in $TempDirs) {
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        }
    }
}
