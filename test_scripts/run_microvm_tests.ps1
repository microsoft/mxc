# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs all MicroVM E2E tests. Requires WHP and Nanvix binaries next to wxc-exec.exe.

.DESCRIPTION
    - Checks if Windows Hypervisor Platform is available
    - Locates wxc-exec.exe (built with --features microvm)
    - Verifies Nanvix binaries are present
    - Runs each test config, validates exit codes
    - Reports pass/fail summary

.PARAMETER WxcExePath
    Path to wxc-exec.exe. Defaults to ..\src\target\debug\wxc-exec.exe

.PARAMETER ConfigDir
    Path to test configs directory. Defaults to ..\test_configs

.EXAMPLE
    .\run_microvm_tests.ps1
    .\run_microvm_tests.ps1 -WxcExePath C:\build\wxc-exec.exe
#>

param(
    [string]$WxcExePath = "..\src\target\debug\wxc-exec.exe",
    [string]$ConfigDir = "..\test_configs",
    [string]$CliPath = "..\cli"
)

$ErrorActionPreference = "Stop"

# -- WHP check ---------------------------------------------------------------

function Test-WhpAvailable {
    # Fast check: verify the WHP API DLL exists and the hypervisor is running.
    # Avoids Get-WindowsOptionalFeature which requires elevation and can hang.
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

Write-Host "`n=== MicroVM E2E Tests ===" -ForegroundColor Cyan

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

# -- Verify MicroVM binaries --------------------------------------------------

$requiredBinaries = @("nanvixd.exe", "kernel.elf", "python.elf", "cpython-ramfs.img")
$binDir = Split-Path $wxcExe
$missing = $requiredBinaries | Where-Object { -not (Test-Path (Join-Path $binDir $_)) }

if ($missing) {
    Write-Host "ERROR: Missing MicroVM binaries in ${binDir}:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "       - $_" }
    Write-Host "       Build with: cd src && cargo build --features microvm"
    exit 1
}

# -- Verify CLI is built -----------------------------------------------------

$cliEntryPoint = Join-Path (Resolve-Path $CliPath) "dist\cli.js"
if (-not (Test-Path $cliEntryPoint)) {
    Write-Host "ERROR: CLI not built. Expected: $cliEntryPoint" -ForegroundColor Red
    Write-Host "       Build with: cd cli && npm install && npm run build"
    exit 1
}

Write-Host "wxc-exec: $wxcExe"
Write-Host "binaries: $binDir"
Write-Host "cli:      $cliEntryPoint"

# -- Test definitions ---------------------------------------------------------
# Format: config name, expected exit code

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

    # Read the script command from the config JSON
    $configJson = Get-Content $configPath -Raw | ConvertFrom-Json
    $scriptCode = $configJson.process.commandLine
    $containment = if ($configJson.containment) { $configJson.containment } else { "nanvix" }

    # Write script to a temp file (avoids multi-line argument mangling)
    $scriptFile = [System.IO.Path]::GetTempFileName()
    Set-Content $scriptFile $scriptCode -NoNewline -Encoding UTF8

    # Build a minimal SandboxPolicy JSON for the CLI
    $policyJson = '{"version":"0.4.0-alpha"}'

    $cliArgs = @(
        "dist/cli.js", "run-sdk",
        "--script-file", $scriptFile,
        "--policy", $policyJson,
        "--containment", $containment,
        "--experimental",
        "--debug"
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    $process = Start-Process -FilePath "node" `
        -ArgumentList $cliArgs `
        -WorkingDirectory (Resolve-Path $CliPath) `
        -PassThru -Wait `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile
    $sw.Stop()

    $actualExit = $process.ExitCode
    $expectedExit = $test.ExpectedExit
    $elapsedMs = $sw.ElapsedMilliseconds
    $stdout = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
    Remove-Item $stdoutFile, $stderrFile, $scriptFile -ErrorAction SilentlyContinue

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
        if ($stderr) {
            $stderr -split "`n" | Select-Object -Last 5 | ForEach-Object {
                Write-Host "    > $($_.TrimEnd())" -ForegroundColor Gray
            }
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
