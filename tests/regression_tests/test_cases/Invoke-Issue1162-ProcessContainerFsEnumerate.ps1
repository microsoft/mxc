# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-1162"),
    [switch]$CheckPrerequisites
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"
$cmdExe = Join-Path $env:SystemRoot "System32\cmd.exe"
$systemDriveRoot = [IO.Path]::GetPathRoot($env:SystemRoot)
$enumerateDirectory = Join-Path $WorkDirectory "enumerate-only"
$scratchDirectory = Join-Path $WorkDirectory "scratch"
$sentinelName = "visible-but-not-readable.txt"
$sentinelPath = Join-Path $enumerateDirectory $sentinelName
$listingPath = Join-Path $scratchDirectory "listing.txt"
$contentPath = Join-Path $scratchDirectory "content.txt"

New-Item -ItemType Directory -Force -Path $enumerateDirectory, $scratchDirectory | Out-Null
Set-Content -LiteralPath $sentinelPath -Value "CONTENT_MUST_REMAIN_UNREADABLE"

$configJson = @"
{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($scratchDirectory | ConvertTo-Json -Compress),
        "timeout": 30000
    },
    "filesystem": {
        "readonlyPaths": $((ConvertTo-Json -InputObject @($systemDriveRoot, $env:SystemRoot) -Compress)),
        "readwritePaths": $((ConvertTo-Json -InputObject @($scratchDirectory) -Compress))
    },
    "processContainer": {
        "filesystem": {
            "enumeratePaths": $((ConvertTo-Json -InputObject @($enumerateDirectory) -Compress))
        }
    },
    "fallback": {
        "allowDaclMutation": false
    },
    "ui": {
        "disable": false
    }
}
"@

$enumerateCommandLine = "`"$cmdExe`" /d /c dir /b `"$enumerateDirectory`" > `"$listingPath`" 2>&1"
$enumerateJson = Add-RegressionCommandLine $configJson $enumerateCommandLine
$enumerateBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($enumerateJson))

Write-Host "Issue #1162: ProcessContainer PSEC fs_enumerate." -ForegroundColor Cyan
$probeOutput = & $WxcExec --probe --config-base64 $enumerateBase64
$probeExitCode = $LASTEXITCODE
$probeOutput | Out-Host
$probe = $probeOutput | ConvertFrom-Json
if (-not $probe.probes.baseContainerSupportsEnumeratePaths) {
    Write-Host "SKIPPED: This host does not advertise ProcessContainer filesystem enumeration support." -ForegroundColor Yellow
    exit 77
}
if ($CheckPrerequisites) {
    if ($probeExitCode -ne 0) {
        Write-Error "The host advertises filesystem enumeration support, but the request probe failed."
        exit $probeExitCode
    }
    exit 0
}
if ($probeExitCode -ne 0) {
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "The fs_enumerate config was rejected during probing." -FailureExitCode $probeExitCode
}

$selectedTier = $probe.tier
if ($selectedTier -ne "base-container") {
    Complete-RegressionTest -Passed $false -SuccessMessage "Unused" -FailureMessage "Issue #1162 requires base-container, but the selected tier was '$selectedTier'."
}

& $WxcExec --config-base64 $enumerateBase64
$enumerateExitCode = $LASTEXITCODE
$listing = if (Test-Path -LiteralPath $listingPath) {
    Get-Content -LiteralPath $listingPath -Raw
} else {
    ""
}

$readCommandLine = "`"$cmdExe`" /d /c type `"$sentinelPath`" > `"$contentPath`" 2>&1"
$readJson = Add-RegressionCommandLine $configJson $readCommandLine
$readBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($readJson))
& $WxcExec --config-base64 $readBase64
$readExitCode = $LASTEXITCODE
$content = if (Test-Path -LiteralPath $contentPath) {
    Get-Content -LiteralPath $contentPath -Raw
} else {
    ""
}
$enumerationSucceeded = $listing -match "(?m)^$([regex]::Escape($sentinelName))\r?$"
$contentReadWasDenied = $readExitCode -ne 0 -and $content -notmatch "CONTENT_MUST_REMAIN_UNREADABLE"
$passed = $enumerateExitCode -eq 0 -and $enumerationSucceeded -and $contentReadWasDenied

Complete-RegressionTest -Passed $passed -SuccessMessage "BaseContainer enumerated the requested directory without gaining file-content read access." -FailureMessage "Expected enumeration-only access; enumerate exit code was $enumerateExitCode, listing success was $enumerationSucceeded, read exit code was $readExitCode, content remained unreadable was $contentReadWasDenied." -FailureExitCode $enumerateExitCode
