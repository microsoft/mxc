# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-1102")
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"
$whereExe = Join-Path $env:SystemRoot "System32\where.exe"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null

function Invoke-PathCase([string]$Name, [string[]]$Environment) {
    $environmentProperty = if ($null -eq $Environment) {
        ""
    } else {
        ",`n        `"env`": $((ConvertTo-Json -InputObject $Environment -Compress))"
    }

    # Config
    $configJson = @"
{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($WorkDirectory | ConvertTo-Json -Compress),
        "timeout": 30000$environmentProperty
    },
    "filesystem": {
        "readonlyPaths": $((ConvertTo-Json -InputObject @($env:SystemRoot) -Compress)),
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
    $commandLine = "`"$whereExe`" cmd.exe"

    $json = Add-RegressionCommandLine $configJson $commandLine
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    Write-Host "`n$Name" -ForegroundColor Cyan

    # Run
    & $WxcExec --config-base64 $base64
    [pscustomobject]@{ Case = $Name; ExitCode = $LASTEXITCODE }
}

$default = Invoke-PathCase "Default environment" $null
$sparse = Invoke-PathCase "Unrelated explicit variable only" @("FOO=bar")
$default
$sparse
Write-Host "Issue #1102 reproduces when the default case succeeds and FOO=bar loses PATH or required Windows variables." -ForegroundColor Yellow
$reproduced = $default.ExitCode -eq 0 -and $sparse.ExitCode -ne 0
Complete-RegressionTest -Passed $reproduced -SuccessMessage "The default environment succeeded and the sparse environment failed." -FailureMessage "The expected environment behavior was not observed."
