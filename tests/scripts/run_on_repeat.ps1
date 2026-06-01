# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Stress-test runner — loops core tests multiple times.
#
# Usage:
#   .\run_on_repeat.ps1                          # 10 iterations, debug build
#   .\run_on_repeat.ps1 -Iterations 5            # 5 iterations
#   .\run_on_repeat.ps1 -Release                 # release build
#   .\run_on_repeat.ps1 -Iterations 3 -Release   # 3 iterations, release build

param(
    [int]$Iterations = 10,
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = "Stop"

$TestScripts = @(
    "run_basicprocess_test.ps1",
    "run_filesystem_bfs_test.ps1",
    "run_filesystem_bfsreadonly_test.ps1",
    "run_lpacac_test.ps1"
)

$passThrough = @()
if ($Release) { $passThrough += "-Release" }
if ($BinDir) { $passThrough += "-BinDir"; $passThrough += $BinDir }

for ($n = 1; $n -le $Iterations; $n++) {
    Write-Host "=== Pass $n of $Iterations ===" -ForegroundColor Cyan
    foreach ($script in $TestScripts) {
        $scriptPath = Join-Path $PSScriptRoot $script
        pwsh -File $scriptPath @passThrough
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED: $script on pass $n (exit code $LASTEXITCODE)" -ForegroundColor Red
            exit $LASTEXITCODE
        }
    }
}

Write-Host "All $Iterations passes completed successfully." -ForegroundColor Green
