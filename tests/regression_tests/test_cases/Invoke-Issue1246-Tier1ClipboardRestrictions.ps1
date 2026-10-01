# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP "mxc-issue-1246")
)

$ErrorActionPreference = "Stop"
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Resolve-RegressionExecutable.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Complete-RegressionTest.ps1")
. (Join-Path (Split-Path -Parent $PSScriptRoot) "inc\Add-RegressionCommandLine.ps1")

$WxcExec = Resolve-RegressionExecutable $WxcExec "wxc-exec.exe"

New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$sourceMaterial = Join-Path $PSScriptRoot "data\Issue1246-ClipboardProbe.cs"
$source = Join-Path $WorkDirectory "Issue1246-ClipboardProbe.cs"
$probe = Join-Path $WorkDirectory "Issue1246-ClipboardProbe.exe"
$windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    throw "Windows PowerShell is required to compile the clipboard probe: $windowsPowerShell"
}
Copy-Item -LiteralPath $sourceMaterial -Destination $source -Force
if (Test-Path -LiteralPath $probe) {
    Remove-Item -LiteralPath $probe -Force
}
$escapedSource = $source.Replace("'", "''")
$escapedProbe = $probe.Replace("'", "''")
$compileCommand = "Add-Type -Path '$escapedSource' -OutputAssembly '$escapedProbe' -OutputType ConsoleApplication"
& $windowsPowerShell -NoProfile -NonInteractive -Command $compileCommand
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $probe -PathType Leaf)) {
    throw "Failed to compile the issue #1246 clipboard probe with inbox Windows PowerShell."
}

function Invoke-ClipboardCase {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet("all", "none")]
        [string]$Clipboard,
        [Parameter(Mandatory)]
        [ValidateSet("container", "desktop")]
        [string]$Isolation,
        [Parameter(Mandatory)]
        [bool]$ExpectAllowed
    )

    $readToken = "MXC-ISSUE-1246-$Name-READ-$([guid]::NewGuid().ToString('N'))"
    $writeToken = "MXC-ISSUE-1246-$Name-WRITE-$([guid]::NewGuid().ToString('N'))"
    $configJson = @"
{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {
        "cwd": $($WorkDirectory | ConvertTo-Json -Compress),
        "timeout": 5000
    },
    "filesystem": {
        "readwritePaths": $((ConvertTo-Json -InputObject @($WorkDirectory) -Compress))
    },
    "fallback": {
        "allowDaclMutation": false
    },
    "ui": {
        "disable": false,
        "clipboard": "$Clipboard",
        "injection": false
    },
    "processContainer": {
        "ui": {
            "isolation": "$Isolation",
            "desktopSystemControl": false,
            "systemSettings": "none",
            "ime": false
        }
    }
}
"@

    $commandLine = "`"$probe`" sandbox $readToken $writeToken"
    $json = Add-RegressionCommandLine $configJson $commandLine
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

    Write-Host "`n$Name`: clipboard=$Clipboard, isolation=$Isolation" -ForegroundColor Cyan
    $probeOutput = & $WxcExec --probe --config-base64 $base64
    $probeExitCode = $LASTEXITCODE
    $probeOutput | Out-Host
    if ($probeExitCode -ne 0) {
        return [pscustomobject]@{
            Name = $Name
            Passed = $false
            Detail = "Tier probe exited with code $probeExitCode."
        }
    }

    $selectedTier = ($probeOutput | ConvertFrom-Json).tier
    if ($selectedTier -ne "base-container") {
        return [pscustomobject]@{
            Name = $Name
            Passed = $false
            Detail = "Expected Tier 1 (base-container), but the selected tier was '$selectedTier'."
        }
    }

    & $probe write $readToken
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{
            Name = $Name
            Passed = $false
            Detail = "The host could not seed the interactive clipboard."
        }
    }
    & $probe matches $readToken
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{
            Name = $Name
            Passed = $false
            Detail = "The host could not read back the seeded clipboard token."
        }
    }

    & $WxcExec --config-base64 $base64 2>&1 | Tee-Object -Variable runOutput | Out-Host
    $exitCode = $LASTEXITCODE
    $outputText = $runOutput | Out-String
    $readAllowed = $outputText -match "(?m)^READCLIPBOARD=allowed\r?$"
    $readBlocked = $outputText -match "(?m)^READCLIPBOARD=blocked\r?$"
    $readInconclusive = $outputText -match "(?m)^READCLIPBOARD=inconclusive\r?$"
    $writeAllowed = $outputText -match "(?m)^WRITECLIPBOARD=allowed\r?$"
    $writeBlocked = $outputText -match "(?m)^WRITECLIPBOARD=blocked\r?$"
    $writeInconclusive = $outputText -match "(?m)^WRITECLIPBOARD=inconclusive\r?$"
    $writeTokenObserved = $false
    $writeTokenCheckExitCode = "not-run"
    $writeTokenCheckConclusive = $true
    if ($ExpectAllowed) {
        & $probe matches $writeToken 2>$null
        $writeTokenCheckExitCode = $LASTEXITCODE
        $writeTokenObserved = $writeTokenCheckExitCode -eq 0
        $writeTokenCheckConclusive = $writeTokenCheckExitCode -ne 2
    }

    $passed = if ($ExpectAllowed) {
        $exitCode -eq 0 -and $readAllowed -and $writeAllowed -and $writeTokenCheckConclusive -and $writeTokenObserved
    } else {
        $exitCode -eq 0 -and $readBlocked -and $writeBlocked
    }

    [pscustomobject]@{
        Name = $Name
        Passed = $passed
        Detail = "exit=$exitCode, readAllowed=$readAllowed, readBlocked=$readBlocked, readInconclusive=$readInconclusive, writeAllowed=$writeAllowed, writeBlocked=$writeBlocked, writeInconclusive=$writeInconclusive, writeTokenObserved=$writeTokenObserved, writeTokenCheckExitCode=$writeTokenCheckExitCode"
    }
}

Write-Host "Issue #1246: Tier 1 clipboard policy enforcement and permissive control." -ForegroundColor Cyan
Write-Host "This test temporarily uses the interactive clipboard with unique read and write tokens." -ForegroundColor Yellow
$blockedCase = Invoke-ClipboardCase -Name "restricted" -Clipboard "none" -Isolation "container" -ExpectAllowed $false
$allowedCase = Invoke-ClipboardCase -Name "permissive-control" -Clipboard "all" -Isolation "desktop" -ExpectAllowed $true
$passed = $blockedCase.Passed -and $allowedCase.Passed
$detail = "$($blockedCase.Name): $($blockedCase.Detail); $($allowedCase.Name): $($allowedCase.Detail)"

Complete-RegressionTest -Passed $passed -SuccessMessage "Tier 1 blocked both clipboard data paths under none/container and allowed both under all/desktop." -FailureMessage "Issue #1246 clipboard policy matrix failed: $detail"
