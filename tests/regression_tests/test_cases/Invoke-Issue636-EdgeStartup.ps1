# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$EdgeExe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

if (-not (Test-Path -LiteralPath $EdgeExe -PathType Leaf)) {
    throw "Edge was not found at '$EdgeExe'. Pass -EdgeExe explicitly."
}
$edgeRoot = Split-Path -Parent $EdgeExe
$scratch = Join-Path $env:TEMP "mxc-issue-636-edge-profile"
New-Item -ItemType Directory -Force -Path $scratch | Out-Null

# Config
$configJson = @"
{
    "version": "0.7.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($edgeRoot | ConvertTo-Json -Compress),
        "timeout": 10000
    },
    "filesystem": {
        "readonlyPaths": $((ConvertTo-Json -InputObject @($edgeRoot) -Compress)),
        "readwritePaths": $((ConvertTo-Json -InputObject @($scratch) -Compress))
    },
    "fallback": {
        "allowDaclMutation": true
    },
    "ui": {
        "disable": false
    }
}
"@

# Command
$commandLine = "`"$EdgeExe`" --user-data-dir=`"$scratch`" --no-first-run --new-window about:blank"

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

Write-Host "Issue #636: launching Edge with an isolated writable profile." -ForegroundColor Cyan

# Run
& $WxcExec --config-base64 $base64
$exitCode = $LASTEXITCODE
Complete-RegressionTest -Passed ($exitCode -eq 0) -SuccessMessage "The Edge configuration launched successfully." -FailureMessage "The Edge configuration exited with code $exitCode." -FailureExitCode $exitCode
