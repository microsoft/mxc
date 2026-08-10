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

.PARAMETER NanvixBin
    Offline mode. Directory of pre-fetched NanVix binaries to stage next to
    wxc-exec.exe instead of relying on a --features microvm build. Contents are
    checksum-verified; snapshots inside it are ignored (see
    docs/nanvix-microvm/nanvix.md). Off unless explicitly passed.

.PARAMETER ColdStart
    Give each test a fresh NANVIX_HOME so the VM cold-boots every run instead of
    reusing a warm-start snapshot. Off by default.

.EXAMPLE
    .\run_microvm_tests.ps1
    .\run_microvm_tests.ps1 -Release
    .\run_microvm_tests.ps1 -BinDir C:\build\output
    .\run_microvm_tests.ps1 -NanvixBin $env:NANVIX_BIN
    .\run_microvm_tests.ps1 -ColdStart
#>

param(
    [switch]$Release,
    [string]$BinDir,
    [string]$ConfigDir,
    [string]$NanvixBin,
    [switch]$ColdStart
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

# -- Offline mode -------------------------------------------------------------

# Stage pre-fetched binaries next to wxc-exec.exe. The runner resolves them from
# its own directory only, so NANVIX_BIN cannot be used in place.
if ($NanvixBin) {
    if (-not (Test-Path $NanvixBin)) {
        Write-Host "ERROR: NANVIX_BIN directory not found: $NanvixBin" -ForegroundColor Red
        exit 1
    }

    $checksumsPath = Join-Path $RepoRoot "src\backends\nanvix\binaries\checksums.json"
    $checksums = (Get-Content $checksumsPath -Raw | ConvertFrom-Json).windows
    Write-Host "Offline mode: staging NanVix binaries from $NanvixBin" -ForegroundColor Cyan

    foreach ($rel in @("nanvixd.exe", "nanvix_rootfs.img", "python3.initrd", "bin\kernel.elf")) {
        $source = Join-Path $NanvixBin $rel
        if (-not (Test-Path $source)) {
            Write-Host "ERROR: $rel missing from $NanvixBin" -ForegroundColor Red
            exit 1
        }

        $expected = $checksums.($rel | Split-Path -Leaf)
        $actual = (Get-FileHash -Path $source -Algorithm SHA256).Hash
        if ($actual -ne $expected) {
            Write-Host "ERROR: checksum mismatch for ${rel}: expected $expected, got $actual" -ForegroundColor Red
            exit 1
        }

        $destination = Join-Path $BinDir $rel
        New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
        Copy-Item $source $destination -Force
        Write-Host "  $rel staged and verified"
    }

    # Snapshots in NANVIX_BIN are not covered by checksums.json, so they are
    # never staged; drop any stale ones so no unverified image is warm-booted.
    Remove-Item (Join-Path $BinDir "snapshots") -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Verify MicroVM binaries --------------------------------------------------

# Local runs get these from `cargo build --features microvm`, which stages them
# next to wxc-exec.exe. CI gets them from scripts/ci/prepare-windows-host.ps1,
# which downloads and checksum-verifies the pinned release, so this check is a
# guard for the local path. Snapshots are excluded: they are a warm-start cache
# the runner generates on demand, not a shipped artifact.
$requiredBinaries = @(
    "nanvixd.exe",
    "nanvix_rootfs.img",
    "python3.initrd",
    "bin\kernel.elf"
)
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

    # A fresh NANVIX_HOME per test means no snapshot is carried over, so the VM
    # cold-boots every run. The runner's 60s boot grace covers the extra time.
    $nanvixHome = $null
    $previousNanvixHome = $env:NANVIX_HOME
    if ($ColdStart) {
        $nanvixHome = Join-Path ([System.IO.Path]::GetTempPath()) "mxc-nanvix-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Force -Path $nanvixHome | Out-Null
        $env:NANVIX_HOME = $nanvixHome
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $wxcExe `
            -ArgumentList "--debug", "--experimental", $configPath `
            -PassThru -Wait `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile
    } finally {
        $sw.Stop()
        if ($nanvixHome) {
            if ($null -eq $previousNanvixHome) {
                Remove-Item Env:\NANVIX_HOME -ErrorAction SilentlyContinue
            } else {
                $env:NANVIX_HOME = $previousNanvixHome
            }
            # Snapshots are large; do not let them accumulate across tests.
            Remove-Item $nanvixHome -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

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

    # Check stdout content if OutputContains is specified. Not every test
    # defines the key, and StrictMode makes a missing hashtable key throw, so
    # test for its presence rather than accessing it directly.
    if ($pass -and $test.ContainsKey('OutputContains')) {
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
