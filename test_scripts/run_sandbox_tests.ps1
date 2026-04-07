# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs all Windows Sandbox E2E tests with performance measurement.

.DESCRIPTION
    - Checks if Windows Sandbox feature is enabled
    - Locates wxc-exec.exe and wxc-sandbox-daemon.exe
    - Starts the sandbox daemon as a background process
    - Runs each test config, validates exit codes and output
    - Captures per-test wall-clock timing
    - Writes sandbox-perf-results.json for CI artifact consumption
    - Reports pass/fail summary with performance table

.PARAMETER WxcExePath
    Path to wxc-exec.exe. Defaults to ..\src\target\debug\wxc-exec.exe

.PARAMETER ConfigDir
    Path to test configs directory. Defaults to ..\test_configs

.PARAMETER Release
    Use release build binaries instead of debug.

.EXAMPLE
    .\run_sandbox_tests.ps1
    .\run_sandbox_tests.ps1 -Release
    .\run_sandbox_tests.ps1 -WxcExePath C:\build\wxc-exec.exe -ConfigDir C:\configs
#>
param(
    [string]$WxcExePath = "",
    [string]$ConfigDir = "",
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

# Resolve paths
if (-not $ConfigDir) {
    $ConfigDir = Join-Path $RepoRoot "test_configs"
}
if (-not $WxcExePath) {
    $profile = if ($Release) { "release" } else { "debug" }
    $WxcExePath = Join-Path $RepoRoot "src\target\$profile\wxc-exec.exe"
}

$BinDir = Split-Path $WxcExePath
$Daemon = Join-Path $BinDir "wxc-sandbox-daemon.exe"

# -- Preflight ----------------------------------------------------------------

Write-Host "`n=== Windows Sandbox E2E Tests ===" -ForegroundColor Cyan

if (-not (Test-Path $WxcExePath)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExePath" -ForegroundColor Red
    Write-Host "       Build with: cd src && cargo build" -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path $Daemon)) {
    Write-Host "ERROR: wxc-sandbox-daemon.exe not found at $Daemon" -ForegroundColor Red
    exit 1
}

$sandboxFeature = dism /online /get-featureinfo /featurename:Containers-DisposableClientVM 2>&1 |
    Select-String "State"
if ($sandboxFeature -notmatch "Enabled") {
    Write-Host "SKIP: Windows Sandbox feature is not enabled." -ForegroundColor Yellow
    Write-Host "      Enable with: dism /online /enable-feature /featurename:Containers-DisposableClientVM /all"
    exit 0
}

Write-Host "wxc-exec: $WxcExePath"
Write-Host "daemon:   $Daemon"
Write-Host "configs:  $ConfigDir"

# -- Test definitions ---------------------------------------------------------

$tests = @(
    @{ Config = "sandbox_echo.json";            ExpectedExit = 0;  Description = "Echo (cmd.exe)";          OutputContains = "Hello from sandbox!" },
    @{ Config = "basic_sandbox.json";           ExpectedExit = 0;  Description = "Python hello world";      OutputContains = "executed successfully" },
    @{ Config = "sandbox_powershell.json";      ExpectedExit = 0;  Description = "PowerShell";              OutputContains = "PowerShell works" },
    @{ Config = "sandbox_powershell_env.json";  ExpectedExit = 0;  Description = "PowerShell environment";  OutputContains = "ComputerName=" },
    @{ Config = "sandbox_stderr.json";          ExpectedExit = 0;  Description = "stderr relay";            OutputContains = "stdout-message" },
    @{ Config = "sandbox_exit_code.json";       ExpectedExit = 42; Description = "Exit code propagation";   OutputContains = "" },
    @{ Config = "sandbox_timeout.json";         ExpectedExit = -1; Description = "Timeout kills process";   OutputContains = "" },
    @{ Config = "sandbox_echo.json";            ExpectedExit = 0;  Description = "Multi-exec #1 (echo)";    OutputContains = "Hello from sandbox!" },
    @{ Config = "sandbox_echo.json";            ExpectedExit = 0;  Description = "Multi-exec #2 (echo)";    OutputContains = "Hello from sandbox!" },
    @{ Config = "sandbox_echo.json";            ExpectedExit = 0;  Description = "Multi-exec #3 (echo)";    OutputContains = "Hello from sandbox!" }
)

# -- Cleanup & start daemon ---------------------------------------------------

Write-Host "`nCleaning up stale sandbox processes..." -ForegroundColor Yellow
Get-Process -Name "wxc-sandbox-daemon","WindowsSandbox*" -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Remove-Item "$env:TEMP\wxc-sandbox-rendezvous\*" -ErrorAction SilentlyContinue
Start-Sleep 5

Write-Host "Starting sandbox daemon..." -ForegroundColor Yellow
$daemonProc = Start-Process -FilePath $Daemon -ArgumentList "wxc-sandbox","300000" `
    -PassThru -NoNewWindow -RedirectStandardError "$env:TEMP\wxc-sandbox-daemon.log"
Start-Sleep 2

if ($daemonProc.HasExited) {
    Write-Host "ERROR: Daemon exited immediately. Check $env:TEMP\wxc-sandbox-daemon.log" -ForegroundColor Red
    exit 1
}
Write-Host "Daemon started (PID $($daemonProc.Id))`n" -ForegroundColor Green

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

    Write-Host "  $($test.Description) ($($test.Config))... " -NoNewline

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & $WxcExePath --debug --experimental $configPath 2>&1 | Out-String
    $actualExit = $LASTEXITCODE
    $sw.Stop()
    $elapsedMs = $sw.ElapsedMilliseconds

    # Decode any base64 lines in the output
    $decoded = $output
    $lines = $output -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    foreach ($line in $lines) {
        if ($line -match "^[A-Za-z0-9+/]{4,}[A-Za-z0-9+/=]*$") {
            try {
                $text = [System.Text.Encoding]::UTF8.GetString(
                    [System.Convert]::FromBase64String($line))
                $decoded += "`n" + $text
            } catch { }
        }
    }

    # Validate
    $ok = $true
    $expectedExit = $test.ExpectedExit

    # For timeout test, accept any non-zero exit
    if ($test.Description -match "Timeout") {
        if ($actualExit -eq 0) { $ok = $false }
    } else {
        if ($actualExit -ne $expectedExit) { $ok = $false }
    }

    if ($ok -and $test.OutputContains -and $decoded -notmatch [regex]::Escape($test.OutputContains)) {
        $ok = $false
    }

    $status = if ($ok) { "PASS" } else { "FAIL" }
    if ($ok) {
        Write-Host "PASS (${elapsedMs}ms)" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "FAIL (exit=$actualExit, ${elapsedMs}ms)" -ForegroundColor Red
        $failed++
    }

    $results += @{
        Test         = $test.Config
        Description  = $test.Description
        WallTimeMs   = $elapsedMs
        Exit         = $actualExit
        Status       = $status
    }
}

# -- Performance summary ------------------------------------------------------

Write-Host "`n=== Performance ===" -ForegroundColor Cyan
Write-Host ("  {0,-40} {1,10} {2,8}" -f "Test", "Time (ms)", "Status")
Write-Host ("  {0,-40} {1,10} {2,8}" -f "----", "---------", "------")
foreach ($r in $results) {
    $color = if ($r.Status -eq "PASS") { "Green" } else { "Red" }
    Write-Host ("  {0,-40} {1,10} {2,8}" -f $r.Description, $r.WallTimeMs, $r.Status) -ForegroundColor $color
}

# Write JSON results for CI artifact
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
$perfJsonPath = Join-Path $RepoRoot "sandbox-perf-results.json"
$perfOutput | ConvertTo-Json -Depth 3 | Set-Content $perfJsonPath -Encoding UTF8
Write-Host "`n  Performance results written to: $perfJsonPath"

# -- Cleanup ------------------------------------------------------------------

Write-Host "`nStopping daemon..." -ForegroundColor Yellow
if (-not $daemonProc.HasExited) {
    Stop-Process -Id $daemonProc.Id -Force -ErrorAction SilentlyContinue
}
Get-Process -Name "WindowsSandbox*" -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

Write-Host "Daemon log: $env:TEMP\wxc-sandbox-daemon.log" -ForegroundColor Gray

# -- Summary ------------------------------------------------------------------

$total = $passed + $failed
Write-Host "`n=== Results ===" -ForegroundColor Cyan
if ($total -eq 0) {
    Write-Host "  ERROR: No tests were executed." -ForegroundColor Red
    exit 1
}
Write-Host "  Passed: $passed / $total"
if ($failed -gt 0) {
    Write-Host "  Failed: $failed / $total" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "    - $($_.Description) ($($_.Test), exit=$($_.Exit))" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "  All Sandbox E2E tests passed!" -ForegroundColor Green
    exit 0
}
