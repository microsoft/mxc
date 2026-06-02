# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs MicroVM E2E tests. Requires WHP and Nanvix binaries next to wxc-exec.exe.

.DESCRIPTION
    - Locates wxc-exec.exe (built with --features microvm)
    - Verifies Nanvix binaries are present
    - Runs each test config via wxc-exec, validates exit codes and stdout content
    - Reports pass/fail summary with per-test performance timing
    - Writes microvm-perf-results.json for CI artifact consumption

.PARAMETER Release
    Use release build (default: debug)

.PARAMETER BinDir
    Explicit binary directory. Overrides -Release logic when provided.

.PARAMETER ConfigDir
    Path to test configs directory. Defaults to <repo-root>\tests\configs

.EXAMPLE
    .\run_microvm_tests.ps1
    .\run_microvm_tests.ps1 -Release
    .\run_microvm_tests.ps1 -BinDir C:\build\output
#>

param(
    [switch]$Release,
    [string]$BinDir,
    [string]$ConfigDir
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

if (-not $ConfigDir) {
    $ConfigDir = Join-Path $RepoRoot "tests\configs"
}

$WxcExePath = Join-Path $BinDir "wxc-exec.exe"

# -- WHP check (local runs only) ---------------------------------------------
# In CI, the workflow checks WHP and fails before reaching this script.
# For local runs, check here and skip gracefully if WHP is unavailable.

if (-not $env:CI) {
    function Test-WhpAvailable {
        if (-not (Test-Path "$env:SystemRoot\System32\WinHvPlatform.dll")) {
            return $false
        }
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            return ($cs -and $cs.HypervisorPresent)
        } catch {
            return $false
        }
    }

    if (-not (Test-WhpAvailable)) {
        Write-Host "SKIP: Windows Hypervisor Platform (WHP) is not available." -ForegroundColor Yellow
        Write-Host "      Enable it with: Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform"
        exit 0
    }
}

Write-Host "`n=== MicroVM E2E Tests ===" -ForegroundColor Cyan

# -- Locate wxc-exec.exe -----------------------------------------------------

if (-not (Test-Path $WxcExePath)) {
    Write-Host "ERROR: wxc-exec.exe not found at: $WxcExePath" -ForegroundColor Red
    Write-Host "       Build with: cd src && cargo build --features microvm"
    exit 1
}

$wxcExe = Resolve-Path $WxcExePath

# -- Verify MicroVM binaries --------------------------------------------------

$requiredBinaries = @("nanvixd.exe", "kernel.elf", "python3.12", "nanvix_rootfs.img")
$binDir = Split-Path $wxcExe
$missing = $requiredBinaries | Where-Object { -not (Test-Path (Join-Path $binDir $_)) }

if ($missing) {
    Write-Host "ERROR: Missing MicroVM binaries in ${binDir}:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "       - $_" }
    Write-Host "       Build with: cd src && cargo build --features microvm"
    exit 1
}

Write-Host "wxc-exec: $wxcExe"
Write-Host "binaries: $binDir"

# -- Test definitions ---------------------------------------------------------

$tests = @(
    @{ Config = "microvm_hello.json";        ExpectedExit = 0;  Description = "Hello world";                    OutputContains = "sum=100" },
    @{ Config = "microvm_exit_code.json";    ExpectedExit = 42; Description = "Exit code propagation" },
    @{ Config = "microvm_multiline.json";    ExpectedExit = 0;  Description = "Multi-line script (fibonacci)";  OutputContains = "fib(" },
    @{ Config = "microvm_stdlib.json";       ExpectedExit = 0;  Description = "Stdlib (json, math, hashlib)";   OutputContains = "pi" },
    @{ Config = "microvm_large_output.json"; ExpectedExit = 0;  Description = "Large stdout (1000 lines)";      OutputContains = "line 999" },
    @{ Config = "microvm_error.json";        ExpectedExit = 1;  Description = "Python exception";               OutputContains = "ValueError" },
    @{ Config = "microvm_timeout.json";      ExpectedExit = -1; Description = "Timeout kills VM" }
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

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    $process = Start-Process -FilePath $wxcExe `
        -ArgumentList "--debug", "--experimental", $configPath `
        -PassThru -Wait `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile
    $sw.Stop()

    $actualExit = $process.ExitCode
    $expectedExit = $test.ExpectedExit
    $elapsedMs = $sw.ElapsedMilliseconds
    $stdout = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
    Remove-Item $stdoutFile, $stderrFile -ErrorAction SilentlyContinue

    $pass = ($actualExit -eq $expectedExit)
    $reason = ""

    if (-not $pass) {
        $reason = "expected exit=$expectedExit, got exit=$actualExit"
    }

    # Check stdout content if OutputContains is specified
    if ($pass -and $test.OutputContains) {
        $combined = "$stdout`n$stderr"
        if ($combined -notmatch [regex]::Escape($test.OutputContains)) {
            $pass = $false
            $reason = "output missing '$($test.OutputContains)'"
        }
    }

    if ($pass) {
        Write-Host "  PASS (exit=$actualExit, ${elapsedMs}ms)" -ForegroundColor Green
        $passed++
        $results += @{ Test = $test.Config; Status = "PASS"; Exit = $actualExit; WallTimeMs = $elapsedMs; Description = $test.Description }
    } else {
        Write-Host "  FAIL ($reason, ${elapsedMs}ms)" -ForegroundColor Red
        $combined = "$stdout`n$stderr"
        $combined -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 3 | ForEach-Object {
            Write-Host "    > $($_.TrimEnd())" -ForegroundColor Gray
        }
        $failed++
        $results += @{ Test = $test.Config; Status = "FAIL"; Exit = $actualExit; WallTimeMs = $elapsedMs; Description = $test.Description }
    }
}

# -- Performance summary ------------------------------------------------------

Write-Host "`n=== Performance ===" -ForegroundColor Cyan
Write-Host ("  {0,-35} {1,10} {2,8}" -f "Test", "Time (ms)", "Status")
Write-Host ("  {0,-35} {1,10} {2,8}" -f "----", "---------", "------")
foreach ($r in $results) {
    $color = if ($r.Status -eq "PASS") { "Green" } else { "Red" }
    Write-Host ("  {0,-35} {1,10} {2,8}" -f $r.Description, $r.WallTimeMs, $r.Status) -ForegroundColor $color
}

# Write JSON results for CI artifact consumption
$perfOutput = @{
    commit    = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    timestamp = (Get-Date -Format "o")
    results   = $results | ForEach-Object {
        @{
            test         = $_.Test
            description  = $_.Description
            wall_time_ms = $_.WallTimeMs
            exit_code    = $_.Exit
            status       = $_.Status
        }
    }
}
$perfJsonPath = Join-Path $ConfigDir "..\microvm-perf-results.json"
$perfOutput | ConvertTo-Json -Depth 3 | Set-Content $perfJsonPath -Encoding UTF8
Write-Host "`n  Performance results written to: $perfJsonPath"

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
    Write-Host "  All MicroVM E2E tests passed!" -ForegroundColor Green
    exit 0
}
