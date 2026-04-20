# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# WSLC (WSL Container) E2E test runner.
# Requires: Windows 11, WSL2 enabled, WSLC SDK installed, pre-pulled images.
# Cannot run in GitHub Actions CI (needs WSL2 + WSLC runtime).
#
# Usage:
#   .\run_wslc_all_tests.ps1              # release build (default)
#   .\run_wslc_all_tests.ps1 -Debug       # debug build
#
# Prerequisites for tar import tests:
#
#   1. Rootfs tar (wslc_tar_import_rootfs.json):
#      docker pull alpine:latest
#      docker run --name alpine-tmp alpine:latest true
#      docker export alpine-tmp -o C:\workspace\alpine.tar
#      docker rm alpine-tmp
#
#   2. Docker image archive (wslc_tar_import_docker_save.json):
#      docker save alpine:latest -o C:\workspace\alpine-docker-save.tar
#
# Notes:
#   - wslc_custom_registry.json requires network access to mcr.microsoft.com
#   - Tar import tests are skipped if the tar files are not present

param(
    [switch]$Debug
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$TestConfigs = Join-Path $RepoRoot "test_configs"

# Find binary
$Target = "x86_64-pc-windows-msvc"
if ($Debug) {
    $BinDir = Join-Path $RepoRoot "src\target\$Target\debug"
} else {
    $BinDir = Join-Path $RepoRoot "src\target\$Target\release"
}

$WxcExec = Join-Path $BinDir "wxc-exec.exe"
if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build --features wslc $(if (-not $Debug) { '--release ' })--target $Target' first." -ForegroundColor Yellow
    exit 1
}

# Helper: run a single WSLC test config
function Run-WslcTest {
    param(
        [string]$ConfigFile,
        [int]$ExpectedExit = 0,
        [string]$OutputContains = ""
    )

    $configPath = Join-Path $TestConfigs $ConfigFile
    if (-not (Test-Path $configPath)) {
        Write-Host "  $ConfigFile ... " -NoNewline
        Write-Host "SKIP (file not found)" -ForegroundColor Yellow
        return @{ Name = $ConfigFile; Pass = $true; Skipped = $true; Reason = "File not found" }
    }

    Write-Host "  $ConfigFile ... " -NoNewline

    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $WxcExec --experimental --debug $configPath 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevPref

    $pass = $true
    $reason = ""

    if ($exitCode -ne $ExpectedExit) {
        $pass = $false
        $reason = "Expected exit $ExpectedExit, got $exitCode"
    }

    if ($pass -and $OutputContains -and $output -notmatch [regex]::Escape($OutputContains)) {
        $pass = $false
        $reason = "Output missing '$OutputContains'"
    }

    if ($pass) {
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host "    Reason: $reason" -ForegroundColor Red
        $meaningful = $output -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 5
        foreach ($line in $meaningful) {
            Write-Host "    > $($line.TrimEnd())" -ForegroundColor Gray
        }
    }

    return @{ Name = $ConfigFile; Pass = $pass; Skipped = $false; Reason = $reason }
}

# Banner
Write-Host "`nWSLC E2E Tests" -ForegroundColor Cyan
Write-Host "==============" -ForegroundColor Cyan
Write-Host "Binary: $WxcExec`n" -ForegroundColor Gray

# Run tests
[System.Collections.ArrayList]$results = @()

Write-Host "--- Basic Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-WslcTest "wslc_env_vars.json" -OutputContains "MY_VAR="))
$null = $results.Add((Run-WslcTest "wslc_exit_code.json" -ExpectedExit 42 -OutputContains "About to exit with code 42"))
$null = $results.Add((Run-WslcTest "wslc_stderr.json" -OutputContains "stdout message"))
$null = $results.Add((Run-WslcTest "wslc_large_output.json"))

Write-Host "`n--- Filesystem Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-WslcTest "wslc_filesystem.json" -OutputContains "Filesystem test passed"))
$null = $results.Add((Run-WslcTest "wslc_readonly_mount.json" -OutputContains "Read succeeded"))

Write-Host "`n--- Network Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-WslcTest "wslc_network_isolated.json"))

Write-Host "`n--- Image Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-WslcTest "wslc_python_hello.json" -OutputContains "Hello from Python"))
$null = $results.Add((Run-WslcTest "wslc_python_stdlib.json"))
$null = $results.Add((Run-WslcTest "wslc_custom_registry.json" -OutputContains "Image pulled from MCR"))
$null = $results.Add((Run-WslcTest "wslc_tar_import_rootfs.json" -OutputContains "Hello from tar-imported image"))
$null = $results.Add((Run-WslcTest "wslc_tar_import_docker_save.json" -OutputContains "Hello from docker-save image"))

# Summary
$passed = ($results | Where-Object { $_.Pass -and -not $_.Skipped }).Count
$failed = ($results | Where-Object { -not $_.Pass -and -not $_.Skipped }).Count
$skipped = ($results | Where-Object { $_.Skipped }).Count
$total = $results.Count
$executed = $passed + $failed

Write-Host "`n==============" -ForegroundColor Cyan
if ($failed -eq 0) {
    Write-Host "$passed/$total passed$(if ($skipped -gt 0) { ", $skipped skipped" })" -ForegroundColor Green
} else {
    Write-Host "$passed/$executed passed, $failed FAILED$(if ($skipped -gt 0) { " ($skipped skipped)" }):" -ForegroundColor Red
    $results | Where-Object { -not $_.Pass -and -not $_.Skipped } | ForEach-Object {
        Write-Host "  FAIL: $($_.Name) - $($_.Reason)" -ForegroundColor Red
    }
}

exit $(if ($failed -gt 0) { 1 } else { 0 })
