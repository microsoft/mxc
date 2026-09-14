# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [Parameter(Mandatory)]
    [string]$WorkDirectory
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

$systemRoot = [IO.Path]::GetPathRoot($env:SystemRoot)
$workRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($WorkDirectory))
if ($workRoot -eq $systemRoot) {
    throw "Issue #825 requires a directory on a non-system NTFS volume."
}
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null

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
        "readonlyPaths": []
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
$commandLine = "powershell.exe -NoProfile -NonInteractive -Command `"Write-Output ('ProcessCwd=' + [Environment]::CurrentDirectory); Write-Output ('PSLocation=' + (Get-Location).Path)`""

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

# Run
Write-Host "Issue #825: compare ProcessCwd and PSLocation." -ForegroundColor Cyan
Write-Host "Expected bug: ProcessCwd is '$WorkDirectory' while PSLocation is on the system drive." -ForegroundColor Yellow
& $WxcExec --config-base64 $base64
$exitCode = $LASTEXITCODE
Complete-RegressionTest -Passed ($exitCode -eq 0) -SuccessMessage "The PowerShell location probe completed successfully." -FailureMessage "The PowerShell location probe exited with code $exitCode." -FailureExitCode $exitCode
