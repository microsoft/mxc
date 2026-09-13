# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$BashExe = "$env:ProgramFiles\Git\bin\bash.exe"
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

if (-not (Test-Path -LiteralPath $BashExe -PathType Leaf)) {
    throw "Git Bash or MSYS2 bash was not found at '$BashExe'. Pass -BashExe explicitly."
}

$gitRoot = Split-Path -Parent (Split-Path -Parent $BashExe)

# Config
$configJson = @"
{
    "version": "0.8.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($gitRoot | ConvertTo-Json -Compress),
        "timeout": 30000
    },
    "filesystem": {
        "readonlyPaths": $((ConvertTo-Json -InputObject @($gitRoot, $env:SystemRoot) -Compress)),
        "readwritePaths": []
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
$commandLine = "`"$BashExe`" --version"

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

Write-Host "Issue #1061: MSYS2/Cygwin access to \BaseNamedObjects" -ForegroundColor Cyan
& $WxcExec --probe --config-base64 $base64

# Run
& $WxcExec --config-base64 $base64
$exitCode = $LASTEXITCODE
Write-Host "Expected bug: bash initialization fails, commonly with exit 0xC0000142." -ForegroundColor Yellow
Complete-RegressionTest -Passed ($exitCode -eq 0) -SuccessMessage "Git Bash initialized successfully." -FailureMessage "Git Bash exited with code $exitCode." -FailureExitCode $exitCode
