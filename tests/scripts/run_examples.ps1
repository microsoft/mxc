# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Runs wxc-test-driver against example configs.
# Creates temporary directories required by examples, runs the test driver,
# and cleans up regardless of outcome.
#
# Usage:
#   .\run_examples.ps1              # debug build
#   .\run_examples.ps1 -Release     # release build

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
$ExamplesDir = Join-Path $RepoRoot "tests\examples"

if (-not (Test-Path $TestDriver)) {
    Write-Host "ERROR: wxc-test-driver.exe not found at $TestDriver" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

$TempDirs = @(
    "C:\temp\wxc_sandbox",
    "C:\temp\wxc_combined_test"
)

try {
    foreach ($dir in $TempDirs) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    Write-Host "Running wxc-test-driver against examples..." -ForegroundColor Cyan
    & $TestDriver $ExamplesDir
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "FAILED: wxc-test-driver exited with code $exitCode" -ForegroundColor Red
        exit $exitCode
    }

    Write-Host "PASSED: all examples" -ForegroundColor Green
} finally {
    foreach ($dir in $TempDirs) {
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        }
    }
}
