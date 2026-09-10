# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-694"),
    [string]$GoExe
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"
$GoExe = Resolve-RegressionExecutable $GoExe "go.exe"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$sourceMaterial = Join-Path $PSScriptRoot "data\Issue694-GetFinalPathNameByHandle.go"
$source = Join-Path $WorkDirectory "mytest.go"
$probe = Join-Path $WorkDirectory "mytest.exe"
$inputFile = Join-Path $WorkDirectory "config.json"

Copy-Item -LiteralPath $sourceMaterial -Destination $source -Force
& $GoExe build -o $probe $source
if ($LASTEXITCODE -ne 0) { throw "Failed to build the issue author's Go probe." }
Set-Content -LiteralPath $inputFile -Value "{}" -Encoding utf8

# Config
$configJson = @"
{
    "version": "0.6.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($WorkDirectory | ConvertTo-Json -Compress),
        "timeout": 30000
    },
    "filesystem": {
        "readwritePaths": $((ConvertTo-Json -InputObject @($WorkDirectory) -Compress))
    },
    "fallback": {
        "allowDaclMutation": true
    },
    "processContainer": {
        "leastPrivilege": false
    }
}
"@

# Command
$commandLine = "`"$probe`""

$json = Add-RegressionCommandLine $configJson $commandLine
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

Write-Host "Issue #694: GetFinalPathNameByHandle with VOLUME_NAME_DOS." -ForegroundColor Cyan
Write-Host "Expected bug: VOLUME_NAME_DOS reports Access is denied while VOLUME_NAME_NT succeeds." -ForegroundColor Yellow
$probeOutput = & $WxcExec --probe --config-base64 $base64
$probeOutput | Out-Host
$probeExitCode = $LASTEXITCODE
if ($probeExitCode -ne 0) {
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "Tier probe exited with code $probeExitCode." -FailureExitCode $probeExitCode
}

$selectedTier = ($probeOutput | ConvertFrom-Json).tier
if ($selectedTier -ne "appcontainer-dacl") {
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "Issue #694 requires appcontainer-dacl, but the selected tier was '$selectedTier'. Build with force-tier-testing and set MXC_FORCE_TIER=appcontainer-dacl."
}

# Run
& $WxcExec --config-base64 $base64 2>&1 | Tee-Object -Variable runOutput | Out-Host
$exitCode = $LASTEXITCODE
$outputText = $runOutput | Out-String
$dosSucceeded = $outputText -match "(?m)^VOLUME_NAME_DOS:"
$ntSucceeded = $outputText -match "(?m)^VOLUME_NAME_NT:"
$apiFailed = $outputText -match "(?m)^(CreateFile|VOLUME_NAME_(DOS|NT)) error:"
$passed = $exitCode -eq 0 -and $dosSucceeded -and $ntSucceeded -and -not $apiFailed

Complete-RegressionTest -Passed $passed -SuccessMessage "DOS and NT final-path resolution both succeeded." -FailureMessage "The final-path probe reported an API failure or omitted a success marker." -FailureExitCode $exitCode
