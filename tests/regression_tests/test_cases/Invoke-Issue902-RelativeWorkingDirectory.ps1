# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-902")
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

$subdirectory = Join-Path $WorkDirectory "sub"
New-Item -ItemType Directory -Force -Path $subdirectory | Out-Null

# Config
$configJson = @"
{
    "version": "0.8.0-alpha",
    "containment": "process",
    "process": {
        "cwd": "sub",
        "timeout": 30000
    },
    "filesystem": {
        "readwritePaths": $((ConvertTo-Json -InputObject @($WorkDirectory) -Compress))
    },
    "fallback": {
        "allowDaclMutation": true
    }
}
"@

# Command
$commandLine = "cmd.exe /D /C cd"

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

Push-Location $WorkDirectory
try {
    Write-Host "Issue #902: relative process.cwd is resolved against host state." -ForegroundColor Cyan
    Write-Host "Expected bug: succeeds and prints '$subdirectory'. Healthy behavior rejects relative cwd." -ForegroundColor Yellow

    # Run
    & $WxcExec --config-base64 $base64
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

Complete-RegressionTest -Passed ($exitCode -ne 0) -SuccessMessage "The relative working directory was rejected." -FailureMessage "The relative working directory was accepted."
