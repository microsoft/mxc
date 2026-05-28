# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# PLM filesystem test runner.
# Creates temporary directories required by the test config, runs the test,
# and cleans up regardless of outcome.
#
# Usage:
#   .\run_filesystem_PLM_test.ps1              # debug build
#   .\run_filesystem_PLM_test.ps1 -Release     # release build

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

$WxcExec = Join-Path $BinDir "wxc-exec.exe"
$TestConfig = Join-Path $RepoRoot "test_configs\filesystem_plm_test.json"
$ExpectedOutput = "test_configs\adjusted_filesystem_plm_test.json"


if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

$TempDirs = @(
    "C:\temp\wxc_test_denied",
    "C:\temp\wxc_test_read",
    "C:\temp\wxc_test_readwrite",
    "C:\temp\wxc_logs"
)

$TempFiles = @(
    "C:\temp\wxc_test_denied\test_deny_read.txt",
    "C:\temp\wxc_test_denied\test_deny_write.txt",
    "C:\temp\wxc_test_read\test_readonly.txt",
    "C:\temp\wxc_test_readwrite\test_readonly_readwrite.txt"
)

try {
    foreach ($dir in $TempDirs) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    foreach ($file in $TempFiles) {
        New-Item -ItemType File -Path $file -Force | Out-Null
    }
    $adjustedConfigPath = Join-Path "C:\temp\wxc_logs" "adjusted_filesystem_plm_test.json"
    Write-Host "Running BFS filesystem test..." -ForegroundColor Cyan
    & $WxcExec --debug $TestConfig --audit --log-dir "C:\temp\wxc_logs" --adjusted-config-path $adjustedConfigPath

    # Verify the adjusted config produced by audit mode matches the expected
    # output checked into the repo. Compare by normalizing both files through
    # the JSON parser so insignificant formatting differences are ignored.
    
    if (-not (Test-Path $adjustedConfigPath)) {
        Write-Host "FAILED: adjusted config not produced at $adjustedConfigPath" -ForegroundColor Red
        exit 1
    }
    $ExpectedOutputPath = Join-Path $RepoRoot $ExpectedOutput
    if (-not (Test-Path $ExpectedOutputPath)) {
        Write-Host "FAILED: expected output not found at $ExpectedOutputPath" -ForegroundColor Red
        exit 1
    }

    $expectedJson = (Get-Content $ExpectedOutputPath  -Raw | ConvertFrom-Json) | ConvertTo-Json -Depth 100
    $actualJson   = (Get-Content $adjustedConfigPath -Raw | ConvertFrom-Json) | ConvertTo-Json -Depth 100
    #expected json is defined before call to wxc-exec

    if ($actualJson -ne $expectedJson) {
        Write-Host "FAILED: adjusted config does not match expected output" -ForegroundColor Red
        Write-Host "  actual:   $adjustedConfigPath" -ForegroundColor Yellow
        Write-Host "  expected: $ExpectedOutputPath" -ForegroundColor Yellow
        $diff = Compare-Object ($actualJson -split "`n") ($expectedJson -split "`n")
        if ($diff) { $diff | Format-Table -AutoSize | Out-String | Write-Host }
        exit 1
    }

    Write-Host "PASSED: BFS filesystem test" -ForegroundColor Green
} finally {
    foreach ($dir in $TempDirs) {
        if (Test-Path $dir) {
            Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        }
    }
}
