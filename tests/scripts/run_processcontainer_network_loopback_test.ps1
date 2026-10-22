# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$BinDir)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\LoopbackAnchor.ps1')
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')
$wxc = Join-Path (Resolve-Path -LiteralPath $BinDir).Path 'wxc-exec.exe'
if (-not (Test-Path -LiteralPath $wxc -PathType Leaf)) { throw "Executor not found: $wxc" }
$scratch = Join-Path $env:TEMP ("mxc-native-loopback-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
Write-Host "Loopback test artifacts: $scratch"
$hostProbe = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
    -Name 'host-probe' -Arguments @('--probe')
if ($hostProbe.ExitCode -ne 0 -or -not ($hostProbe.Stdout | ConvertFrom-Json).probes.baseContainerApiPresent) {
    throw 'Focused loopback validation requires native PSEC.'
}

$anchor = Start-LoopbackAnchor -Body 'MXC-NATIVE-LOOPBACK'
if ($null -eq $anchor) { throw 'Could not bind the loopback control listener.' }
try {
    $control = Invoke-WebRequest -Uri $anchor.Url -NoProxy -TimeoutSec 5
    if ($control.Content -cne $anchor.Body) { throw 'The host could not reach its loopback control.' }
    foreach ($case in @(
        @{ Name = 'omitted-host-loopback-denies'; Allow = $false },
        @{ Name = 'explicit-host-loopback-denies'; Allow = $false; Ingress = 'deny'; Loopback = 'deny' },
        @{ Name = 'host-loopback-allows-ingress-allow'; Allow = $true; Ingress = 'allow'; Loopback = 'allow' },
        @{ Name = 'host-loopback-allows-ingress-deny'; Allow = $true; Ingress = 'deny'; Loopback = 'allow' }
    )) {
        $request = @{
            version = '1.0.0'
            containment = 'processcontainer'
            process = @{
                commandLine = Get-LoopbackAnchorCommand -Url $anchor.Url -TimeoutSec 5
                cwd = $scratch
                timeout = 30000
            }
            filesystem = @{ readwritePaths = @($scratch); readonlyPaths = @($env:SystemRoot) }
            network = @{ egress = @{ default = 'allow' } }
            ui = @{ disable = $false }
        }
        if ($case.ContainsKey('Loopback')) {
            $request.network.ingress = @{ default = $case.Ingress; hostLoopback = $case.Loopback }
        }
        $path = Join-Path $scratch "$($case.Name).json"
        $request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
        $result = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
            -Name $case.Name -Arguments @($path)
        if ($result.Log -notmatch '"tier":"base-container"') {
            throw "$($case.Name) did not select native ProcessContainer."
        }
        if ($case.Allow) {
            $passed = $result.ExitCode -eq 0 -and $result.Stdout.Trim() -ceq $anchor.Body
        } else {
            $passed = $result.ExitCode -in 7, 28 -and $result.Stderr -match 'curl: \((7|28)\)'
        }
        if (-not $passed) {
            throw "$($case.Name) failed: exit=$($result.ExitCode); stdout=$($result.Stdout); stderr=$($result.Stderr). See $scratch."
        }
        Write-Host "PASSED: $($case.Name)"
    }
} finally {
    Stop-LoopbackAnchor $anchor
}
