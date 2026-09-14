# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$PackageName = "Microsoft.WindowsNotepad"
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

$package = Get-AppxPackage $PackageName | Select-Object -First 1
if (-not $package) { throw "Package '$PackageName' is not installed for the current user." }

$exe = Get-ChildItem -LiteralPath $package.InstallLocation -Recurse -Filter Notepad.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $exe) { throw "No Notepad.exe was found under '$($package.InstallLocation)'." }

# Config
$configJson = @"
{
    "version": "0.8.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($package.InstallLocation | ConvertTo-Json -Compress),
        "timeout": 10000
    },
    "filesystem": {
        "readonlyPaths": $((ConvertTo-Json -InputObject @($package.InstallLocation) -Compress))
    },
    "fallback": {
        "allowDaclMutation": true
    },
    "ui": {
        "disable": false,
        "clipboard": "none",
        "injection": false
    }
}
"@

# Command
$commandLine = "`"$exe`""

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

# Run
Write-Host "Issue #473: direct launch of packaged app '$PackageName'." -ForegroundColor Cyan
Write-Host "Expected current behavior: activation fails or exits immediately, often with a packaged_app diagnostic." -ForegroundColor Yellow
& $WxcExec --config-base64 $base64

$exitCode = $LASTEXITCODE
Complete-RegressionTest -Passed ($exitCode -eq 0) -SuccessMessage "The packaged application launched successfully." -FailureMessage "The packaged application exited with code $exitCode." -FailureExitCode $exitCode
