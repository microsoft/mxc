# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs all NanVix E2E tests. Requires WHP and NanVix binaries next to wxc-exec.exe.

.DESCRIPTION
    - Checks if Windows Hypervisor Platform is available
    - Locates wxc-exec.exe (built with --features microvm)
    - Verifies NanVix binaries are present
    - Runs each test config, validates exit codes
    - Reports pass/fail summary

.PARAMETER WxcExePath
    Path to wxc-exec.exe. Defaults to ..\src\target\debug\wxc-exec.exe

.PARAMETER ConfigDir
    Path to test configs directory. Defaults to ..\test_configs

.EXAMPLE
    .\run_nanvix_tests.ps1
    .\run_nanvix_tests.ps1 -WxcExePath C:\build\wxc-exec.exe
#>

param(
    [string]$WxcExePath = "..\src\target\debug\wxc-exec.exe",
    [string]$ConfigDir = "..\test_configs"
)

$ErrorActionPreference = "Stop"

# -- WHP check ---------------------------------------------------------------

function Test-WhpAvailable {
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName "HypervisorPlatform" -ErrorAction SilentlyContinue
        return ($feature -and $feature.State -eq "Enabled")
    } catch {
        return $false
    }
}

Write-Host "`n=== NanVix E2E Tests ===" -ForegroundColor Cyan

if (-not (Test-WhpAvailable)) {
    Write-Host "SKIP: Windows Hypervisor Platform (WHP) is not enabled." -ForegroundColor Yellow
    Write-Host "      Enable it with: Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform"
    exit 0
}

# -- Locate wxc-exec.exe -----------------------------------------------------

if (-not (Test-Path $WxcExePath)) {
    Write-Host "ERROR: wxc-exec.exe not found at: $WxcExePath" -ForegroundColor Red
    Write-Host "       Build with: cd src && cargo build --features microvm"
    exit 1
}

$wxcExe = Resolve-Path $WxcExePath

# -- Verify NanVix binaries --------------------------------------------------

$requiredBinaries = @("nanvixd.exe", "kernel.elf", "python.elf", "cpython-ramfs.img")
$binDir = Split-Path $wxcExe
$missing = $requiredBinaries | Where-Object { -not (Test-Path (Join-Path $binDir $_)) }

if ($missing) {
    Write-Host "ERROR: Missing NanVix binaries in ${binDir}:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "       - $_" }
    Write-Host "       Build with: cd src && cargo build --features microvm"
    exit 1
}

Write-Host "wxc-exec: $wxcExe"
Write-Host "binaries: $binDir"

# -- Test definitions ---------------------------------------------------------
# Format: config name, expected exit code

$tests = @(
    @{ Config = "nanvix_hello.json";        ExpectedExit = 0;  Description = "Hello world" },
    @{ Config = "nanvix_exit_code.json";    ExpectedExit = 42; Description = "Exit code propagation" },
    @{ Config = "nanvix_multiline.json";    ExpectedExit = 0;  Description = "Multi-line script (fibonacci)" },
    @{ Config = "nanvix_stdlib.json";       ExpectedExit = 0;  Description = "Stdlib (json, math, hashlib)" },
    @{ Config = "nanvix_large_output.json"; ExpectedExit = 0;  Description = "Large stdout (1000 lines)" },
    @{ Config = "nanvix_error.json";        ExpectedExit = 1;  Description = "Python exception" },
    @{ Config = "nanvix_timeout.json";      ExpectedExit = -1; Description = "Timeout kills VM" }
)

# -- Run tests ----------------------------------------------------------------

$passed = 0
$failed = 0
$results = @()

foreach ($test in $tests) {
    $configPath = Join-Path $ConfigDir $test.Config
    if (-not (Test-Path $configPath)) {
        Write-Host "  SKIP $($test.Config) (file not found)" -ForegroundColor Yellow
        continue
    }

    Write-Host "`n--- $($test.Description) ($($test.Config)) ---" -ForegroundColor White

    $process = Start-Process -FilePath $wxcExe `
        -ArgumentList "--debug", $configPath `
        -NoNewWindow -PassThru -Wait

    $actualExit = $process.ExitCode
    $expectedExit = $test.ExpectedExit

    if ($actualExit -eq $expectedExit) {
        Write-Host "  PASS (exit=$actualExit)" -ForegroundColor Green
        $passed++
        $results += @{ Test = $test.Config; Status = "PASS"; Exit = $actualExit }
    } else {
        Write-Host "  FAIL (expected exit=$expectedExit, got exit=$actualExit)" -ForegroundColor Red
        $failed++
        $results += @{ Test = $test.Config; Status = "FAIL"; Exit = $actualExit }
    }
}

# -- Summary ------------------------------------------------------------------

$total = $passed + $failed
Write-Host "`n=== Results ===" -ForegroundColor Cyan
if ($total -eq 0) {
    Write-Host "  ERROR: No tests were executed. Check -ConfigDir path." -ForegroundColor Red
    exit 1
}
Write-Host "  Passed: $passed / $total"
if ($failed -gt 0) {
    Write-Host "  Failed: $failed / $total" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "    - $($_.Test) (exit=$($_.Exit))" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "  All NanVix E2E tests passed!" -ForegroundColor Green
    exit 0
}
