# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs the mxc-sdk Rust IsolationSession integration tests.

.DESCRIPTION
    Executes the packaged Rust test binary serially, requires the
    IsolationSession backend to be available, and translates the libtest
    summary into the N/M format consumed by the OS lab result parser.

.PARAMETER TestExePath
    Path to mxc-sdk-isolation-session-tests.exe. Defaults to the packaged
    inproc directory next to test_scripts.
#>

param(
    [string]$TestExePath = (
        Join-Path (Split-Path -Parent $PSScriptRoot) `
            'inproc\mxc-sdk-isolation-session-tests.exe')
)

$ErrorActionPreference = 'Stop'

Write-Host 'IsolationSession In-Process SDK Tests' -ForegroundColor Cyan
Write-Host '=====================================' -ForegroundColor Cyan
Write-Host "Binary: $TestExePath" -ForegroundColor Gray

if (-not (Test-Path -LiteralPath $TestExePath -PathType Leaf)) {
    Write-Host '0/1 passed' -ForegroundColor Red
    Write-Host "FAILED: in-process test executable not found: $TestExePath" `
        -ForegroundColor Red
    exit 1
}

$oldRequired = $env:MXC_ISO_TESTS_REQUIRED
$previousPreference = $ErrorActionPreference
$testOutput = @()
$testExitCode = -1
try {
    $env:MXC_ISO_TESTS_REQUIRED = '1'
    $ErrorActionPreference = 'Continue'
    $testOutput = @(& $TestExePath --test-threads=1 --nocapture 2>&1)
    $testExitCode = $LASTEXITCODE
}
catch {
    $testOutput += "Failed to launch in-process tests: $($_.Exception.Message)"
}
finally {
    $ErrorActionPreference = $previousPreference
    $env:MXC_ISO_TESTS_REQUIRED = $oldRequired
}

$testOutput | ForEach-Object { Write-Host $_ }
$summary = [regex]::Match(
    ($testOutput -join "`n"),
    'test result: \w+\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;')

if (-not $summary.Success) {
    Write-Host '0/1 passed' -ForegroundColor Red
    Write-Host (
        'FAILED: in-process test executable did not emit a recognizable ' +
        "libtest summary (exit $testExitCode)") -ForegroundColor Red
    exit 1
}

$passed = [int]$summary.Groups[1].Value
$failed = [int]$summary.Groups[2].Value
$ignored = [int]$summary.Groups[3].Value
$executed = $passed + $failed

if ($testExitCode -eq 0 -and $failed -eq 0 -and $executed -gt 0) {
    Write-Host (
        "$passed/$executed passed" +
        $(if ($ignored -gt 0) { ", $ignored ignored" })) `
        -ForegroundColor Green
    exit 0
}

$reportedTotal = [Math]::Max(1, $executed)
Write-Host (
    "$passed/$reportedTotal passed, $failed FAILED, $ignored ignored") `
    -ForegroundColor Red
exit 1
