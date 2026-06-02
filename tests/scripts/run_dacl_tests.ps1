# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# DACL manager focused test runner.
#
# Runs the `filesystem_dacl::` test suite — the unit tests plus the
# integration tests that mutate filesystem ACLs on per-test temp
# directories. The integration tests scope `MXC_DACL_STATE_DIR` to a
# per-test tempdir via a process-internal RAII helper (serialized
# within a process by a static mutex), so they are part of the default
# `cargo test --workspace` suite and require no elevation. This script
# remains as a convenience for running them with verbose output and
# without the surrounding workspace tests.
#
# Usage:
#   .\run_dacl_tests.ps1                # release build (default)
#   .\run_dacl_tests.ps1 -Debug         # debug build
#   .\run_dacl_tests.ps1 -TestThreads 1 # explicit serialization

[CmdletBinding()]
param(
    [switch]$Debug,
    [int]$TestThreads = 1
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$SrcDir = Join-Path $RepoRoot "src"

Push-Location $SrcDir
try {
    $profileArgs = @()
    if (-not $Debug) {
        $profileArgs += "--release"
    }

    Write-Host "Building wxc_common..." -ForegroundColor Cyan
    & cargo build -p wxc_common @profileArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: cargo build failed" -ForegroundColor Red
        exit $LASTEXITCODE
    }

    Write-Host "Running filesystem_dacl tests..." -ForegroundColor Cyan
    & cargo test -p wxc_common @profileArgs filesystem_dacl:: -- `
        --test-threads=$TestThreads --nocapture
    $exit = $LASTEXITCODE
}
finally {
    Pop-Location
}

if ($exit -ne 0) {
    Write-Host "FAILED: filesystem_dacl tests exit code $exit" -ForegroundColor Red
    exit $exit
}

Write-Host "PASSED: filesystem_dacl tests" -ForegroundColor Green
