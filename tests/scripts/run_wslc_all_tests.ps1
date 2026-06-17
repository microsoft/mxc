# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# WSLC (WSL Container) E2E test runner.
# Requires: Windows 11, WSL2 enabled, WSLC SDK installed, pre-pulled images.
# Cannot run in GitHub Actions CI (needs WSL2 + WSLC runtime).
#
# Usage:
#   .\run_wslc_all_tests.ps1              # release build (default), pulls images first
#   .\run_wslc_all_tests.ps1 -Debug       # debug build
#   .\run_wslc_all_tests.ps1 -SkipSetup   # skip pre-pull (assume cache is warm)
#
# Image pre-pull:
#   This script invokes scripts\setup-wslc.ps1 as a preflight to populate the
#   WSLC image cache. MXC's runner no longer auto-pulls images at run time
#   (see issue #165), so the cache must be warmed before any test that
#   references a registry image. Pass -SkipSetup to bypass.
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
    [switch]$Debug,
    [string]$WxcExecPath,
    [switch]$SkipSetup
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$TestConfigs = Join-Path $RepoRoot "tests\configs"

# Find binary -- prefer explicit path, then probe target-specific and default dirs.
$Target = "x86_64-pc-windows-msvc"
$Profile = if ($Debug) { "debug" } else { "release" }

if ($WxcExecPath) {
    $WxcExec = $WxcExecPath
} else {
    $CandidatePaths = @(
        (Join-Path $RepoRoot "src\target\$Target\$Profile\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$Profile\wxc-exec.exe")
    )
    $WxcExec = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found." -ForegroundColor Red
    Write-Host "Searched:" -ForegroundColor Yellow
    foreach ($p in $CandidatePaths) { Write-Host "  - $p" -ForegroundColor Yellow }
    Write-Host "Build with: cargo build --features wslc $(if (-not $Debug) { '--release ' })--target $Target" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExecPath explicitly." -ForegroundColor Yellow
    exit 1
}

# Preflight: ensure the WSLC image cache is populated. The runner no longer
# auto-pulls (see scripts\setup-wslc.ps1 and #165). Skipping is supported for
# the common case where the caller has already pre-pulled or wants to test
# a hermetic environment.
if (-not $SkipSetup) {
    $SetupScript = Join-Path $RepoRoot "scripts\setup-wslc.ps1"
    if (Test-Path $SetupScript) {
        Write-Host "Pre-pulling WSLC images (pass -SkipSetup to skip)..." -ForegroundColor Cyan
        # Pull every image referenced by the wslc_*.json test configs except
        # the tar-import variants (those are imported at run time from the
        # caller-supplied tar file, not pulled from a registry).
        $images = @(
            "alpine:latest",
            "python:3.12-alpine",
            "mcr.microsoft.com/cbl-mariner/base/core:2.0",
            "ghcr.io/linuxserver/baseimage-alpine:3.21",
            "quay.io/fedora/fedora-minimal:latest"
        )
        & $SetupScript -WxcExecPath $WxcExec -Image $images -Force
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARN: setup-wslc.ps1 reported failures; continuing with tests anyway." -ForegroundColor Yellow
        }
        Write-Host ""
    } else {
        Write-Host "WARN: $SetupScript not found; assuming images are pre-pulled." -ForegroundColor Yellow
    }
}

# Helper: run a single WSLC test config
function Run-WslcTest {
    param(
        [string]$ConfigFile,
        [int]$ExpectedExit = 0,
        [string]$OutputContains = "",
        [string]$OutputMatches = "",
        [scriptblock]$PostExitCheck = $null
    )

    $configPath = Join-Path $TestConfigs $ConfigFile
    if (-not (Test-Path $configPath)) {
        Write-Host "  $ConfigFile ... " -NoNewline
        Write-Host "SKIP (file not found)" -ForegroundColor Yellow
        return @{ Name = $ConfigFile; Pass = $true; Skipped = $true; Reason = "File not found" }
    }

    # Skip if the config references a tar file that doesn't exist locally
    $configJson = Get-Content $configPath -Raw | ConvertFrom-Json
    $tarPath = $configJson.experimental.wslc.imageTarPath
    if ($tarPath -and -not (Test-Path $tarPath)) {
        Write-Host "  $ConfigFile ... " -NoNewline
        Write-Host "SKIP (tar not found: $tarPath)" -ForegroundColor Yellow
        return @{ Name = $ConfigFile; Pass = $true; Skipped = $true; Reason = "Tar file not found: $tarPath" }
    }

    Write-Host "  $ConfigFile ... " -NoNewline

    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $wxcArgs = @("--experimental")
    if ($Debug) {
        $wxcArgs += "--debug"
    }
    $wxcArgs += $configPath
    $output = & $WxcExec @wxcArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevPref

    # Access violation (0xC0000005) or other hard crashes corrupt WSL runtime
    # state, causing subsequent WslcCreateSession calls to fail with
    # ERROR_SHARING_VIOLATION. Recover by restarting WSL.
    $isCrash = ($exitCode -lt -1000000000) -or ($exitCode -eq -2147483645)
    if ($isCrash) {
        Write-Host "" # newline before recovery message
        Write-Host "    [recovery] Process crashed (exit $exitCode) -- restarting WSL..." -ForegroundColor Yellow
        $null = wsl --shutdown 2>&1
        Start-Sleep 15
    }

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

    # OutputMatches is a regex pattern (no escaping).
    if ($pass -and $OutputMatches -and $output -notmatch $OutputMatches) {
        $pass = $false
        $reason = "Output did not match regex '$OutputMatches'"
    }

    # PostExitCheck runs after exit/output gates pass. Receives ($id, $output)
    # and must return truthy. Use for externally-observable state assertions.
    if ($pass -and $PostExitCheck) {
        $containerId = $configJson.containerId
        try {
            $checkResult = & $PostExitCheck $containerId $output
            if (-not $checkResult) {
                $pass = $false
                $reason = "PostExitCheck returned false"
            }
        } catch {
            $pass = $false
            $reason = "PostExitCheck threw: $_"
        }
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

    # Brief delay between tests to let the WSLC runtime fully release
    # session resources (mounts, networking) before the next test starts.
    Start-Sleep 2

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
# wslc_filesystem.json also asserts cpuCount + memoryMb enforcement via nproc and /proc/meminfo.
$null = $results.Add((Run-WslcTest "wslc_filesystem.json" `
    -OutputMatches "(?s)PASS: filesystem mount visible.*PASS: cpuCount enforced.*PASS: memoryMb enforced"))
$null = $results.Add((Run-WslcTest "wslc_readonly_mount.json" -OutputContains "Read succeeded"))

Write-Host "`n--- Network Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-WslcTest "wslc_network_isolated.json"))

Write-Host "`n--- Image Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-WslcTest "wslc_python_hello.json" -OutputContains "Hello from Python"))
$null = $results.Add((Run-WslcTest "wslc_python_stdlib.json"))
$null = $results.Add((Run-WslcTest "wslc_custom_registry.json" -OutputContains "Image pulled from MCR"))
$null = $results.Add((Run-WslcTest "wslc_custom_registry_ghcr.json" -OutputContains "Image pulled from GHCR"))
$null = $results.Add((Run-WslcTest "wslc_custom_registry_quay.json" -OutputContains "Image pulled from Quay"))
$null = $results.Add((Run-WslcTest "wslc_tar_import_rootfs.json" -OutputContains "Hello from tar-imported image"))
$null = $results.Add((Run-WslcTest "wslc_tar_import_docker_save.json" -OutputContains "Hello from docker-save image"))

Write-Host "`n--- Timeout Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-WslcTest "wslc_timeout.json" -ExpectedExit -1 -OutputContains "Starting long task"))

Write-Host "`n--- Lifecycle Tests ---" -ForegroundColor Cyan
# Smoke tests only: assert config parses and payload runs. WSLC's session
# teardown reaps session-scoped containers regardless of AutoRemove, so
# destroyOnExit has no externally observable effect via `wslc list`.
# True semantic verification requires a runner-side log assertion (TODO).
$null = $results.Add((Run-WslcTest "wslc_destroy_on_exit_true.json" `
    -OutputContains "PASS: container ran (destroyOnExit=true)"))
$null = $results.Add((Run-WslcTest "wslc_destroy_on_exit_false.json" `
    -OutputContains "PASS: container ran (destroyOnExit=false)"))

# Summary
$passed = @($results | Where-Object { $_.Pass -and -not $_.Skipped }).Count
$failed = @($results | Where-Object { -not $_.Pass -and -not $_.Skipped }).Count
$skipped = @($results | Where-Object { $_.Skipped }).Count
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
