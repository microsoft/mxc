# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$BinDir)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')
$wxc = Join-Path (Resolve-Path -LiteralPath $BinDir).Path 'wxc-exec.exe'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$probeScript = Join-Path $PSScriptRoot 'lib\processcontainer_policy_probe.ps1'
foreach ($file in $wxc, $powershell, $probeScript) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required enumeration prerequisite not found: $file" }
}
$scratch = Join-Path $env:TEMP ("mxc-native-enumerate-" + [guid]::NewGuid().ToString('N'))
$paths = @('', 'rw', 'enumerate', 'unlisted') | ForEach-Object {
    (New-Item -ItemType Directory -Path (Join-Path $scratch $_) -Force).FullName
}
$secret = 'NATIVE_ENUM_CONTENT_SENTINEL'
Set-Content -LiteralPath (Join-Path $scratch 'enumerate\seed.txt') -Value $secret -NoNewline
Set-Content -LiteralPath (Join-Path $scratch 'unlisted\seed.txt') -Value 'NATIVE_ENUM_CONTROL_SENTINEL' -NoNewline
Write-Host "Enumeration test artifacts: $scratch"
if ([IO.File]::ReadAllText((Join-Path $scratch 'enumerate\seed.txt')) -cne $secret -or
    [IO.Directory]::GetFiles((Join-Path $scratch 'unlisted')).Count -ne 1) {
    throw 'The host enumeration/content controls are not usable.'
}
$security = Get-NativeFixtureSecuritySnapshot -Paths $paths
try {
    $hostResult = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
        -Name 'host-probe' -Arguments @('--probe')
    if ($hostResult.ExitCode -ne 0) { throw "Host probe failed: $($hostResult.Stderr)" }
    $facts = ($hostResult.Stdout | ConvertFrom-Json).probes
    if (-not $facts.baseContainerApiPresent -or $facts.baseContainerSupportsEnumeratePaths -isnot [bool]) {
        throw 'Focused enumeration validation requires a valid native PSEC capability probe.'
    }
    $command = @($powershell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $probeScript, 'enumerate', $scratch)
    $request = @{
        version = '1.0.0'
        containment = 'processcontainer'
        process = @{
            commandLine = (($command | ForEach-Object { '"' + $_ + '"' }) -join ' ')
            cwd = (Join-Path $scratch 'rw')
            timeout = 30000
        }
        filesystem = @{
            readwritePaths = @((Join-Path $scratch 'rw'))
            readonlyPaths = @($env:SystemRoot, (Split-Path $probeScript -Parent))
        }
        ui = @{ disable = $false }
        processContainer = @{
            ui = @{ isolation = 'container' }
            filesystem = @{ enumeratePaths = @((Join-Path $scratch 'enumerate')) }
        }
    }
    $path = Join-Path $scratch 'enumerate.json'
    $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
    $probeResult = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
        -Name 'request-probe' -Arguments @('--probe', '--config', $path)
    if ($probeResult.ExitCode -ne 0) { throw "Request probe failed: $($probeResult.Stderr)" }
    $probe = $probeResult.Stdout | ConvertFrom-Json
    if ($probe.probes.baseContainerSupportsEnumeratePaths -isnot [bool] -or
        $probe.probes.baseContainerSupportsEnumeratePaths -cne $facts.baseContainerSupportsEnumeratePaths) {
        throw 'Request and host enumeration capability facts disagree.'
    }
    $tier = if ($probe.PSObject.Properties['tier']) { $probe.tier } else { $null }
    $errorText = if ($probe.PSObject.Properties['error']) { $probe.error } else { $null }
    $augmentation = if ($probe.PSObject.Properties['needsDaclAugmentation']) { $probe.needsDaclAugmentation } else { $null }
    $rejection = 'Windows ProcessContainer requires native PSEC enumeration-only access support for this request'
    if ($facts.baseContainerSupportsEnumeratePaths) {
        if ($tier -cne 'base-container' -or $augmentation -isnot [bool] -or $augmentation -or $errorText) {
            throw 'The supported enumeration request did not probe as native PSEC without DACL augmentation.'
        }
    } elseif ($tier -or $probe.PSObject.Properties['needsDaclAugmentation'] -or $errorText -cne $rejection) {
        throw 'The unsupported enumeration request was not rejected with its capability-specific reason.'
    }
    Write-Host 'PASSED: enumeration host/request probe agreement'

    $result = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
        -Name 'enumerate' -Arguments @($path)
    if ($facts.baseContainerSupportsEnumeratePaths) {
        if ($result.ExitCode -ne 0 -or $result.Stdout.Trim() -cne 'NATIVE_POLICY_OK' -or
            $result.Log -notmatch '"tier":"base-container"') {
            throw "Enumeration enforcement failed: exit=$($result.ExitCode); stdout=$($result.Stdout); stderr=$($result.Stderr). See $scratch."
        }
        Write-Host 'PASSED: listing allowed; content read, write, and ungranted listing denied'
    } elseif ($result.ExitCode -ne 1 -or -not $result.Stderr.Contains($rejection) -or
        $result.Log -match '"event":"mxc.ProcessExited"' -or $result.Stdout -match 'NATIVE_POLICY_OK') {
        throw "Unsupported enumeration was not refused before workload execution. See $scratch."
    } else {
        Write-Host 'PASSED: unsupported enumeration rejected before workload execution'
    }
    if ("$($result.Stdout)`n$($result.Stderr)".Contains($secret)) {
        throw 'Enumeration-only access disclosed file content.'
    }
} finally {
    Assert-NativeFixtureSecurity -Name 'focused enumeration' -Snapshot $security
}
