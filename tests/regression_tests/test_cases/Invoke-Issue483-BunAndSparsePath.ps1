# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$BunExe,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-483")
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"
$bun = Resolve-RegressionExecutable $BunExe "bun.exe"
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null

function Invoke-BunCase {
    # Config
    $configJson = @"
{
    "version": "0.8.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($WorkDirectory | ConvertTo-Json -Compress),
        "timeout": 30000
    },
    "filesystem": {
        "readonlyPaths": $((ConvertTo-Json -InputObject @((Split-Path -Parent $bun), $env:SystemRoot) -Compress)),
        "readwritePaths": $((ConvertTo-Json -InputObject @($WorkDirectory) -Compress))
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
    $commandLine = "`"$bun`" -e `"console.log('mxc smoke')`""

    $json = Add-RegressionCommandLine $configJson $commandLine
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    Write-Host "Issue #483: Bun initialization" -ForegroundColor Cyan

    # Run
    & $WxcExec --config-base64 $base64 | Out-Host
    return $LASTEXITCODE
}

$bunExitCode = Invoke-BunCase
Complete-RegressionTest -Passed ($bunExitCode -eq 0) -SuccessMessage "Bun initialized and completed successfully." -FailureMessage "Bun exited with code $bunExitCode; the reported failure code is 66." -FailureExitCode $bunExitCode
