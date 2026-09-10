# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        "cwd": $($WorkDirectory | ConvertTo-Json -Compress),
        "env": $((ConvertTo-Json -InputObject @("SystemRoot=$env:SystemRoot", "TEMP=$WorkDirectory", "TMP=$WorkDirectory") -Compress)),
        "timeout": 5000
    },
    "filesystem": {
        "readwritePaths": $((ConvertTo-Json -InputObject @($WorkDirectory) -Compress))
    },
    "fallback": {
        "allowDaclMutation": true
    },
    "processContainer": {
        "leastPrivilege": true,
        "capabilities": []
    },
    "ui": {
        "disable": false,
        "clipboard": "none",
        "injection": false
    }
}
"@

# Command
$commandLine = "$env:SystemRoot\System32\cmd.exe /d /c echo COMMAND_EXECUTED"

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

# Run
Write-Host "Issue #1130: sparse explicit environment on the legacy SBOX path" -ForegroundColor Cyan
Write-Host "Expected bug: error 203 and no COMMAND_EXECUTED marker." -ForegroundColor Yellow
& $WxcExec --config-base64 $base64

$exitCode = $LASTEXITCODE
Complete-RegressionTest -Passed ($exitCode -eq 0) -SuccessMessage "The sparse environment launched successfully." -FailureMessage "The sparse environment launch exited with code $exitCode." -FailureExitCode $exitCode
