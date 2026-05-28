# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# PLM capability test runner.
#
# Runs ui_screenshot_test.json under wxc-exec --audit and verifies that the
# adjusted config produced by stop_plm_logging.ps1 contains:
#   1. A 'graphicsCapture' capability in processContainer.capabilities, and
#   2. ui.disable == $false.
#
# Usage:
#   .\run_PLM_capability_tests.ps1              # debug build
#   .\run_PLM_capability_tests.ps1 -Release     # release build

param(
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

if (-not $BinDir) {
    if ($Release) {
        $BinDir = Join-Path $RepoRoot "src\target\release"
    } else {
        $BinDir = Join-Path $RepoRoot "src\target\debug"
    }
}

$WxcExec    = Join-Path $BinDir "wxc-exec.exe"
$TestConfig = Join-Path $RepoRoot "test_configs\ui_screenshot_test.json"
$LogDir     = "C:\temp\wxc_logs"
$AdjustedConfigPath = Join-Path $LogDir "adjusted_ui_screenshot_test.json"

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $TestConfig)) {
    Write-Host "ERROR: test config not found at $TestConfig" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
if (Test-Path $AdjustedConfigPath) {
    Remove-Item -Force $AdjustedConfigPath
}

$TempDirs = @(
    $LogDir
)

try {
    Write-Host "Running PLM capability test (ui_screenshot_test.json)..." -ForegroundColor Cyan
    & $WxcExec --debug $TestConfig --audit --log-dir $LogDir --adjusted-config-path $AdjustedConfigPath

    if (-not (Test-Path $AdjustedConfigPath)) {
        Write-Host "FAILED: adjusted config not produced at $AdjustedConfigPath" -ForegroundColor Red
        exit 1
    }

    $adjusted = Get-Content $AdjustedConfigPath -Raw | ConvertFrom-Json
    $failures = New-Object 'System.Collections.Generic.List[string]'

    # 1. Capability check: processContainer.capabilities must contain 'graphicsCapture'.
    $caps = @()
    if ($adjusted.PSObject.Properties['processContainer'] -and
        $adjusted.processContainer -and
        $adjusted.processContainer.PSObject.Properties['capabilities']) {
        $caps = @($adjusted.processContainer.capabilities)
    }

    $hasGraphicsCapture = $false
    foreach ($c in $caps) {
        if ([string]$c -ieq 'graphicsCapture') { $hasGraphicsCapture = $true; break }
    }

    if ($hasGraphicsCapture) {
        Write-Host "  PASS: processContainer.capabilities contains 'graphicsCapture'" -ForegroundColor Green
    } else {
        $failures.Add("processContainer.capabilities is missing 'graphicsCapture' (got: [$($caps -join ', ')])")
    }

    # 2. UI check: ui.disable must be explicitly false.
    $uiDisable = $null
    if ($adjusted.PSObject.Properties['ui'] -and
        $adjusted.ui -and
        $adjusted.ui.PSObject.Properties['disable']) {
        $uiDisable = [bool]$adjusted.ui.disable
    }

    if ($uiDisable -eq $false -and $null -ne $uiDisable) {
        Write-Host "  PASS: ui.disable is false" -ForegroundColor Green
    } else {
        $failures.Add("ui.disable is not false (got: '$uiDisable')")
    }

    if ($failures.Count -gt 0) {
        Write-Host "FAILED: PLM capability test" -ForegroundColor Red
        foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Yellow }
        Write-Host "  adjusted config: $AdjustedConfigPath" -ForegroundColor Yellow
        exit 1
    }

    Write-Host "PASSED: PLM capability test" -ForegroundColor Green
} finally {
    foreach ($dir in $TempDirs) {
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        }
    }
}
