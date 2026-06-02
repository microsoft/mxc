# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Run network proxy test configs through wxc-test-driver.
# The test driver starts its own built-in test proxy via --proxy.

param(
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$SrcDir = Join-Path $RepoRoot "src"
$TestConfigs = Join-Path $RepoRoot "tests\configs"

if (-not $BinDir) {
    # Build once
    if ($Release) {
        Write-Host "Building in release mode..." -ForegroundColor Yellow
        Push-Location (Join-Path $RepoRoot "src")
        cargo build --release
        Pop-Location
        $BinDir = Join-Path $RepoRoot "src\target\release"
    } else {
        Write-Host "Building in debug mode..." -ForegroundColor Yellow
        Push-Location (Join-Path $RepoRoot "src")
        cargo build
        Pop-Location
        $BinDir = Join-Path $RepoRoot "src\target\debug"
    }
} else {
    Write-Host "Using prebuilt binaries from $BinDir" -ForegroundColor Yellow
}

$ProxyConfigs = @(
    "proxy_builtin_test.json"
)

$TestDriverExe = Join-Path $BinDir "wxc-test-driver.exe"

foreach ($configFile in $ProxyConfigs) {
    $configPath = Join-Path $TestConfigs $configFile
    if (-not (Test-Path $configPath)) {
        Write-Host "SKIPPED (not found): $configPath" -ForegroundColor Yellow
        continue
    }

    Write-Host "`nRunning: $configFile" -ForegroundColor Cyan

    if (Test-Path $TestDriverExe) {
        & $TestDriverExe $configPath --debug --proxy
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED: $configFile (exit code $LASTEXITCODE)" -ForegroundColor Red
            exit $LASTEXITCODE
        }
    } else {
        if ($BinDir) {
            Write-Host "WARNING: wxc-test-driver.exe not found at $TestDriverExe — falling back to cargo run" -ForegroundColor Yellow
        }
        $cargoArgs = @("run", "-p", "wxc_test_driver")
        if ($Release) { $cargoArgs += "--release" }
        $cargoArgs += @("--", $configPath, "--debug", "--proxy")

        Push-Location $SrcDir
        try {
            cargo @cargoArgs
            if ($LASTEXITCODE -ne 0) {
                Write-Host "FAILED: $configFile (exit code $LASTEXITCODE)" -ForegroundColor Red
                exit $LASTEXITCODE
            }
        } finally {
            Pop-Location
        }
    }
}

Write-Host "`nProxy tests complete." -ForegroundColor Green