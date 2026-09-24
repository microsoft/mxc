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

function New-EncodedCwdConfig {
    param(
        [Parameter(Mandatory)]
        [string] $Version
    )

    $configJson = @"
{
    "version": "$Version",
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

    $json = Add-RegressionCommandLine $configJson "cmd.exe /D /C cd"
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
}

$strictConfig = New-EncodedCwdConfig "0.9.0-alpha"
$legacyConfig = New-EncodedCwdConfig "0.8.0-alpha"

Push-Location $WorkDirectory
try {
    Write-Host "Issue #902: current contracts reject relative process.cwd." -ForegroundColor Cyan
    $strictOutput = & $WxcExec --config-base64 $strictConfig 2>&1 | Out-String
    $strictExitCode = $LASTEXITCODE

    Write-Host "Issue #902 compatibility: v0.8 continues to accept relative process.cwd." -ForegroundColor Cyan
    $legacyOutput = & $WxcExec --config-base64 $legacyConfig 2>&1 | Out-String
    $legacyExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

$expectedLegacyDirectory = [System.IO.Path]::GetFullPath($subdirectory)
$strictRejected = $strictExitCode -ne 0 -and $strictOutput -match "process\.cwd"
$legacyAccepted = $legacyExitCode -eq 0 -and
    $legacyOutput -match [regex]::Escape($expectedLegacyDirectory)

if (-not $strictRejected) {
    Write-Host "Current contract did not reject relative process.cwd:`n$strictOutput" -ForegroundColor Red
}
if (-not $legacyAccepted) {
    Write-Host "v0.8 request did not run in '$expectedLegacyDirectory':`n$legacyOutput" -ForegroundColor Red
}

Complete-RegressionTest `
    -Passed ($strictRejected -and $legacyAccepted) `
    -SuccessMessage "Current contracts reject relative process.cwd and v0.8 retains compatibility." `
    -FailureMessage "Working-directory validation or compatibility did not match the contract."
