# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Verifies BaseContainer network default actions using stable schema 0.7.0-alpha.
#
# Usage:
#   .\run_base_container_network_tests.ps1          # prefer debug, fall back to release
#   .\run_base_container_network_tests.ps1 -Release # prefer release, fall back to debug

param(
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$WxcExec = if ($BinDir) {
    Join-Path $BinDir "wxc-exec.exe"
} else {
    $DebugWxcExec = Join-Path $RepoRoot "src\target\debug\wxc-exec.exe"
    $ReleaseWxcExec = Join-Path $RepoRoot "src\target\release\wxc-exec.exe"

    if ($Release) {
        $Candidates = @($ReleaseWxcExec, $DebugWxcExec)
    } else {
        $Candidates = @($DebugWxcExec, $ReleaseWxcExec)
    }

    $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

$TestConfigs = @(
    @{
        Name = "allow"
        Path = Join-Path $RepoRoot "tests\configs\base_container_network_allow.json"
        ExpectedAction = "allow"
        ExpectedMarker = "OK:network_allow"
    },
    @{
        Name = "deny"
        Path = Join-Path $RepoRoot "tests\configs\base_container_network_deny.json"
        ExpectedAction = "deny"
        ExpectedMarker = "OK:network_deny"
    }
)

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    if ($BinDir) {
        Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    } else {
        Write-Host "ERROR: wxc-exec.exe not found in src\target\debug or src\target\release" -ForegroundColor Red
    }
    Write-Host "Run 'cargo build' or 'cargo build --release' first." -ForegroundColor Yellow
    exit 1
}

Write-Host "Using wxc-exec: $WxcExec" -ForegroundColor Gray

foreach ($test in $TestConfigs) {
    if (-not (Test-Path $test.Path)) {
        Write-Host "ERROR: config not found at $($test.Path)" -ForegroundColor Red
        exit 1
    }
}

$probeInfo = New-Object System.Diagnostics.ProcessStartInfo
$probeInfo.FileName = $WxcExec
$probeInfo.Arguments = "--probe --config `"$($TestConfigs[0].Path)`""
$probeInfo.RedirectStandardOutput = $true
$probeInfo.RedirectStandardError = $true
$probeInfo.UseShellExecute = $false
$probeInfo.CreateNoWindow = $true

$probeProcess = [System.Diagnostics.Process]::Start($probeInfo)
$probeStdoutTask = $probeProcess.StandardOutput.ReadToEndAsync()
$probeStderrTask = $probeProcess.StandardError.ReadToEndAsync()
if (-not $probeProcess.WaitForExit(15000)) {
    try {
        $probeProcess.Kill()
        $probeProcess.WaitForExit()
    } catch {
    }
    Write-Host "FAILED: BaseContainer capability probe timed out" -ForegroundColor Red
    exit 1
}

$probeStdout = $probeStdoutTask.GetAwaiter().GetResult()
$probeStderr = $probeStderrTask.GetAwaiter().GetResult()

if ($probeProcess.ExitCode -ne 0) {
    Write-Host "FAILED: BaseContainer capability probe exited with code $($probeProcess.ExitCode)" -ForegroundColor Red
    Write-Host $probeStderr
    exit 1
}

try {
    $probe = $probeStdout | ConvertFrom-Json
} catch {
    Write-Host "FAILED: BaseContainer capability probe returned malformed JSON" -ForegroundColor Red
    Write-Host $probeStdout
    exit 1
}

if ($probe.tier -ne "base-container") {
    Write-Host "SKIPPED: BaseContainer is not usable on this host (selected tier: $($probe.tier))" -ForegroundColor Yellow
    exit 0
}

foreach ($test in $TestConfigs) {
    Write-Host "Running BaseContainer network $($test.Name) test..." -ForegroundColor Cyan

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $WxcExec --debug $test.Path 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    Write-Host $output

    if ($output -notmatch "(?im)selected isolation tier:\s*base-container") {
        Write-Host "FAILED: $($test.Name) config did not run on the base-container tier" -ForegroundColor Red
        exit 1
    }

    $actionPattern = "(?im)network_policy\.egress\.default_action:\s*$($test.ExpectedAction)\s*$"
    if ($output -notmatch $actionPattern) {
        Write-Host "FAILED: expected egress default action '$($test.ExpectedAction)'" -ForegroundColor Red
        exit 1
    }

    if ($exitCode -ne 0) {
        Write-Host "FAILED: $($test.Name) config exited with code $exitCode" -ForegroundColor Red
        exit $exitCode
    }

    if ($output -notmatch [regex]::Escape($test.ExpectedMarker)) {
        Write-Host "FAILED: expected marker '$($test.ExpectedMarker)'" -ForegroundColor Red
        exit 1
    }

    Write-Host "PASSED: BaseContainer network $($test.Name)" -ForegroundColor Green
}

Write-Host "PASSED: all BaseContainer network tests" -ForegroundColor Green
