# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Purpose: Verify BaseContainer rejects a sparse explicit environment before launching the child.

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

$configJson = @"
{
    "version": "0.8.0-alpha",
    "containment": "processcontainer",
    "process": {
        "env": $((ConvertTo-Json -InputObject @("SystemRoot=$env:SystemRoot", "TEMP=$WorkDirectory", "TMP=$WorkDirectory") -Compress))
    }
}
"@

$commandLine = "$env:SystemRoot\System32\cmd.exe /d /c echo COMMAND_EXECUTED"

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

Write-Host "Issue #1130: sparse explicit environment on the PSEC BaseContainer path" -ForegroundColor Cyan
$output = (& $WxcExec --config-base64 $base64 2>&1 | Out-String)
$output | Write-Host

$exitCode = $LASTEXITCODE
$rejectedBeforeLaunch = $exitCode -ne 0 `
    -and $output.Contains("missing the required variable(s): LOCALAPPDATA") `
    -and -not $output.Contains("COMMAND_EXECUTED") `
    -and -not $output.Contains("CreateProcessSecurityEnvironment failed") `
    -and -not $output.Contains("CreateProcessW failed")
Complete-RegressionTest -Passed $rejectedBeforeLaunch -SuccessMessage "The sparse environment was rejected before the PSEC launch with an actionable missing-variable error." -FailureMessage "Expected a pre-launch LOCALAPPDATA rejection without executing the command; exit code was $exitCode."
