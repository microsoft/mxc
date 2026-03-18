# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Run network proxy test configs through wxc-test-driver.
# The test driver starts its own built-in test proxy via --proxy.

param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$TestDriverCrate = Join-Path $RepoRoot "src\wxc_test_driver"
$TestConfigs = Join-Path $RepoRoot "test_configs"

# Build once
if ($Release) {
    Write-Host "Building in release mode..." -ForegroundColor Yellow
    Push-Location (Join-Path $RepoRoot "src")
    cargo build --release
    Pop-Location
} else {
    Write-Host "Building in debug mode..." -ForegroundColor Yellow
    Push-Location (Join-Path $RepoRoot "src")
    cargo build
    Pop-Location
}

$ProxyConfigs = @(
    "proxy_localhost_test.json"
)

foreach ($configFile in $ProxyConfigs) {
    $configPath = Join-Path $TestConfigs $configFile
    if (-not (Test-Path $configPath)) {
        Write-Host "SKIPPED (not found): $configPath" -ForegroundColor Yellow
        continue
    }

    Write-Host "`nRunning: $configFile" -ForegroundColor Cyan
    $cargoArgs = @("run")
    if ($Release) { $cargoArgs += "--release" }
    $cargoArgs += @("--", $configPath, "--debug", "--proxy")

    Push-Location $TestDriverCrate
    try {
        cargo @cargoArgs
    } finally {
        Pop-Location
    }
}

Write-Host "`nProxy tests complete." -ForegroundColor Green