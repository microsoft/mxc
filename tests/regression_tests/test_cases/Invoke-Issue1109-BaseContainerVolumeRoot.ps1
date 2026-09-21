# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:USERPROFILE "Downloads\mxc-issue-1109")
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
Set-Content -LiteralPath (Join-Path $WorkDirectory "sentinel.txt") -Value "host-sentinel"

function Invoke-Case([string]$Name, [string[]]$ReadOnlyPaths) {
    # Config
$configJson = @"
{
    "version": "0.8.0-alpha",
    "containment": "process",
    "process": {
        "cwd": $($WorkDirectory | ConvertTo-Json -Compress),
        "timeout": 30000
    },
    "filesystem": {
        "readwritePaths": $((ConvertTo-Json -InputObject @($WorkDirectory) -Compress)),
        "readonlyPaths": $((ConvertTo-Json -InputObject $ReadOnlyPaths -Compress)),
        "deniedPaths": []
    }
}
"@

    # Command
    $commandLine = "cmd.exe /D /S /C `"dir && type sentinel.txt && echo sandbox-write>from-sandbox-$Name.txt`""

    $json = Add-RegressionCommandLine $configJson $commandLine
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

    Write-Host "`n$Name probe (must report base-container):" -ForegroundColor Cyan
    & $WxcExec --probe --config-base64 $base64
    Write-Host "$Name execution:" -ForegroundColor Cyan

    # Run
    & $WxcExec --config-base64 $base64
    [pscustomobject]@{ Case = $Name; ExitCode = $LASTEXITCODE }
}

$withoutRoot = Invoke-Case "without-volume-root" @()
$volumeRoot = [IO.Path]::GetPathRoot($WorkDirectory)
$withRoot = Invoke-Case "with-volume-root" @($volumeRoot)

$withoutRoot
$withRoot
Write-Host "Issue #1109 reproduces when the first case fails and the volume-root control succeeds." -ForegroundColor Yellow
$reproduced = $withoutRoot.ExitCode -ne 0 -and $withRoot.ExitCode -eq 0
Complete-RegressionTest -Passed $reproduced -SuccessMessage "The volume-root control changed the result as expected." -FailureMessage "The expected volume-root grant behavior was not observed."
