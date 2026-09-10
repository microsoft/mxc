# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-785")
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$isolatedWxc = Join-Path $WorkDirectory "wxc-exec.exe"
Copy-Item -LiteralPath $WxcExec -Destination $isolatedWxc -Force

# Config
$configJson = @"
{
    "version": "0.8.0-alpha",
    "containment": "processcontainer",
    "process": {
        "timeout": 30000
    },
    "processContainer": {
        "leastPrivilege": true,
        "captureDenials": {
            "mode": "block",
            "outputPath": $((Join-Path $WorkDirectory "denials.json") | ConvertTo-Json -Compress)
        }
    },
    "fallback": {
        "allowDaclMutation": true
    }
}
"@

# Command
$commandLine = "cmd.exe /d /c echo capture"

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

Write-Host "Issue #785: probe/runtime disagreement with captureDenials and no sibling plm.exe." -ForegroundColor Cyan
& $isolatedWxc --probe --config-base64 $base64
$probeExit = $LASTEXITCODE

# Run
& $isolatedWxc --config-base64 $base64
$runExit = $LASTEXITCODE

[pscustomobject]@{ ProbeExitCode = $probeExit; RunExitCode = $runExit }
Write-Host "Issue reproduces when probe succeeds but execution fails." -ForegroundColor Yellow
$reproduced = $probeExit -eq 0 -and $runExit -ne 0
Complete-RegressionTest -Passed $reproduced -SuccessMessage "The probe/runtime disagreement reproduced." -FailureMessage "The expected probe/runtime disagreement was not observed."
