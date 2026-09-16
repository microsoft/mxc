# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Purpose: Test that we reject launching process containment sandbox if the env is totally empty (require some vars: LOCALAPPDATA / SystemRoot)

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-1130")
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null

# Config
$configJson = @"
{
    "version": "0.8.0-alpha",
    "containment": "processcontainer",
    "process": {
        "env": $((ConvertTo-Json -InputObject @("SystemRoot=$env:SystemRoot", "TEMP=$WorkDirectory", "TMP=$WorkDirectory") -Compress))
    }
}
"@

# Command
$commandLine = "$env:SystemRoot\System32\cmd.exe /d /c echo COMMAND_EXECUTED"

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

# Run
Write-Host "Issue #1130: sparse explicit environment on the legacy SBOX path" -ForegroundColor Cyan
$output = (& $WxcExec --config-base64 $base64 2>&1 | Out-String)
$output | Write-Host

$exitCode = $LASTEXITCODE
$rejectedBeforeLaunch = $exitCode -ne 0 `
    -and $output.Contains("missing the required variable(s): LOCALAPPDATA") `
    -and -not $output.Contains("COMMAND_EXECUTED") `
    -and -not $output.Contains("CreateProcessInSandbox failed")
Complete-RegressionTest -Passed $rejectedBeforeLaunch -SuccessMessage "The sparse environment was rejected before SBOX launch with an actionable missing-variable error." -FailureMessage "Expected a pre-launch LOCALAPPDATA rejection without executing the command; exit code was $exitCode."
