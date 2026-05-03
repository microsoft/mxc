# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs IsolationSession E2E tests. Requires a Windows host with the
    in-proc Windows.AI.IsolationSession IsoSessionOps APIs available
    (IsoSessionApp.dll registered, Feature_IsoBrokerSessionApis enabled,
    and Feature_IsoBrokerCommandLineSessions enabled for the Composable
    config-id path).

.DESCRIPTION
    - Locates wxc-exec.exe (built with --features isolation_session)
    - Runs each test config via wxc-exec, validates exit codes and stdout
      content
    - Reports pass/fail summary

    This script must run INTERACTIVELY on the test host. The IsoEnvBroker
    cohort check rejects network-logon tokens, so PSSession-driven
    invocations fail with Access Denied. Copy wxc-exec.exe, the test
    configs, and this script to the host, then run it directly in
    cmd.exe or PowerShell on that host.

.PARAMETER WxcExePath
    Path to wxc-exec.exe. Default probes target-specific then default
    release dirs relative to the repo root.

.PARAMETER ConfigDir
    Path to the test_configs directory. Defaults to ..\test_configs.

.EXAMPLE
    .\run_isolation_session_tests.ps1
    .\run_isolation_session_tests.ps1 -WxcExePath C:\test\wxc-exec.exe -ConfigDir C:\test
#>

param(
    [string]$WxcExePath,
    [string]$ConfigDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

if (-not $ConfigDir) {
    $ConfigDir = Join-Path $RepoRoot "test_configs"
}

# Locate wxc-exec.exe — explicit path > host-arch target dir > other-arch
# target dir > default release dir. Detect the host arch so we look for the
# matching build first, but also probe the other Windows target so a
# cross-built binary is still discoverable.
$HostTarget = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    'aarch64-pc-windows-msvc'
} else {
    'x86_64-pc-windows-msvc'
}
$OtherTarget = if ($HostTarget -eq 'aarch64-pc-windows-msvc') {
    'x86_64-pc-windows-msvc'
} else {
    'aarch64-pc-windows-msvc'
}

if ($WxcExePath) {
    $WxcExec = $WxcExePath
} else {
    # Probe release first so a release build is preferred when both flavors exist.
    $CandidatePaths = @(
        (Join-Path $RepoRoot "src\target\$HostTarget\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$OtherTarget\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$HostTarget\debug\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$OtherTarget\debug\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\debug\wxc-exec.exe")
    )
    $WxcExec = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found." -ForegroundColor Red
    Write-Host "Searched:" -ForegroundColor Yellow
    foreach ($p in $CandidatePaths) { Write-Host "  - $p" -ForegroundColor Yellow }
    Write-Host "Build with: cargo build --release --features isolation_session --target $HostTarget" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExecPath explicitly." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nIsolationSession E2E Tests" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host "Binary: $WxcExec" -ForegroundColor Gray
Write-Host "Configs: $ConfigDir`n" -ForegroundColor Gray

# Helper: run one IsolationSession test config.
function Run-IsolationSessionTest {
    param(
        [string]$ConfigFile,
        [int]$ExpectedExit = 0,
        [string[]]$OutputContains = @()
    )

    $configPath = Join-Path $ConfigDir $ConfigFile
    if (-not (Test-Path $configPath)) {
        Write-Host "  $ConfigFile ... " -NoNewline
        Write-Host "SKIP (file not found)" -ForegroundColor Yellow
        return @{ Name = $ConfigFile; Pass = $true; Skipped = $true; Reason = "File not found" }
    }

    Write-Host "  $ConfigFile ... " -NoNewline

    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $WxcExec --experimental $configPath 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevPref

    $pass = $true
    $reason = ""

    if ($exitCode -ne $ExpectedExit) {
        $pass = $false
        $reason = "Expected exit $ExpectedExit, got $exitCode"
    }

    if ($pass -and $OutputContains) {
        foreach ($needle in $OutputContains) {
            if ($output -notmatch [regex]::Escape($needle)) {
                $pass = $false
                $reason = "Output missing '$needle'"
                break
            }
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

    return @{ Name = $ConfigFile; Pass = $pass; Skipped = $false; Reason = $reason }
}

[System.Collections.ArrayList]$results = @()

Write-Host "--- Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-IsolationSessionTest "isolation_session_hello.json" `
    -OutputContains @("MYVAR=IsolationSessionTest", "CWD=C:\mxc_workdir_test", "-IEB-")))
$null = $results.Add((Run-IsolationSessionTest "isolation_session_exit42.json" `
    -ExpectedExit 42))
# stderr separation: agent writes MARKER_STDOUT to stdout and MARKER_STDERR to stderr.
# Both reach this script's captured output via wxc-exec's `2>&1` merge above; the assertion
# proves stderr is being relayed (not dropped) on the non-ConPTY plain-pipes path.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_stderr.json" `
    -OutputContains @("MARKER_STDOUT", "MARKER_STDERR")))

# Summary
$passed = ($results | Where-Object { $_.Pass -and -not $_.Skipped }).Count
$failed = ($results | Where-Object { -not $_.Pass -and -not $_.Skipped }).Count
$skipped = ($results | Where-Object { $_.Skipped }).Count
$total = $results.Count
$executed = $passed + $failed

Write-Host "`n==========================" -ForegroundColor Cyan
if ($failed -eq 0) {
    Write-Host "$passed/$total passed$(if ($skipped -gt 0) { ", $skipped skipped" })" -ForegroundColor Green
} else {
    Write-Host "$passed/$executed passed, $failed FAILED$(if ($skipped -gt 0) { " ($skipped skipped)" }):" -ForegroundColor Red
    $results | Where-Object { -not $_.Pass -and -not $_.Skipped } | ForEach-Object {
        Write-Host "  FAIL: $($_.Name) - $($_.Reason)" -ForegroundColor Red
    }
}

exit $(if ($failed -gt 0) { 1 } else { 0 })
