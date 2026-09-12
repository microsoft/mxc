# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_network_rejections_test.ps1
#
# Policies a non-PSEC tier must refuse rather than silently drop.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_network_rejections_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = all passed, 1 = a failure or zero assertions, 78 = fatal.

[CmdletBinding()]
param(
    # -ContextJson carries the context the entry script already resolved.
    # Anything passed explicitly overrides it, so a standalone run works too.
    [string]$ContextJson,
    [string]$ResultsJson,
    [string]$RequireTier,
    [switch]$SkipNetwork,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 8f — the documented reject surface.
#
# Every case here must be refused during validation, before any container
# exists. These resolve without network, privilege, or fixtures — the same
# property that makes run_seatbelt_rejections_test.sh the cheapest suite in
# the tree. A policy that is "enforced" by the workload failing afterwards is
# not enforcement, so each case asserts the run failed AND the workload never
# produced its marker.
# -----------------------------------------------------------------------
function Phase-NetworkRejections {
    Section 'Phase 8f: documented network reject surface'

    $marker = 'REJECT-PROBE-RAN'
    $cmd = "$env:SystemRoot\System32\cmd.exe /c echo $marker"
    $rw = Join-Path $ScratchRoot 'rw'

    # Shapes the typed generator deliberately cannot produce, authored raw.
    $rawBase = {
        param($id, $network, $extra)
        $o = [ordered]@{
            version     = $Script:SchemaVersion
            containerId = "MxcWinPC-$id"
            containment = 'processcontainer'
            process     = [ordered]@{ commandLine = $cmd; timeout = 20000 }
            filesystem  = [ordered]@{ readwritePaths = @($rw); readonlyPaths = @($env:SystemRoot) }
            ui          = [ordered]@{ disable = $false }
        }
        if ($network) { $o['network'] = $network }
        if ($extra) { foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] } }
        return $o
    }

    $cases = @(
        @{
            Name   = 'egress rule with explicitly empty to[] is rejected (not broadened to wildcard)'
            Config = (New-RawConfig -Name 'rej-empty-to' -Object (& $rawBase 'rej-empty-to' ([ordered]@{
                        egress = [ordered]@{ default = 'deny'; allow = @([ordered]@{ to = @() }) }
                     }) $null))
            Why    = '0.8 spec: an explicit empty array is rejected rather than broadened into a wildcard'
        },
        @{
            Name   = 'egress rule with explicitly empty ports[] is rejected'
            Config = (New-RawConfig -Name 'rej-empty-ports' -Object (& $rawBase 'rej-empty-ports' ([ordered]@{
                        egress = [ordered]@{ default = 'deny'; allow = @([ordered]@{ ports = @() }) }
                     }) $null))
            Why    = 'same rule, ports side'
        },
        @{
            Name   = 'DNS name where a CIDR belongs is rejected'
            Config = (New-RawConfig -Name 'rej-dns-name' -Object (& $rawBase 'rej-dns-name' ([ordered]@{
                        egress = [ordered]@{ default = 'deny'; allow = @([ordered]@{ to = @([ordered]@{ cidr = 'example.com' }) }) }
                     }) $null))
            Why    = 'D3: IP literals and CIDRs only, no DNS names'
        },
        @{
            Name   = 'endPort without port is rejected'
            Config = (New-RawConfig -Name 'rej-endport' -Object (& $rawBase 'rej-endport' ([ordered]@{
                        egress = [ordered]@{ default = 'deny'; allow = @([ordered]@{ ports = @([ordered]@{ protocol = 'tcp'; endPort = 500 }) }) }
                     }) $null))
            Why    = 'endPort requires a numeric port'
        },
        @{
            Name   = 'non-loopback runtimeConfig.networkProxy is rejected'
            Config = (New-RawConfig -Name 'rej-proxy-remote' -Object (& $rawBase 'rej-proxy-remote' ([ordered]@{
                        egress  = [ordered]@{ default = 'deny' }
                        ingress = [ordered]@{ default = 'allow'; hostLoopback = 'allow' }
                     }) ([ordered]@{ runtimeConfig = [ordered]@{ networkProxy = 'http://proxy.example.com:8080' } })))
            Why    = 'MXC must reject a networkProxy endpoint that is not loopback'
        },
        @{
            Name   = 'mixing legacy defaultPolicy with directional egress is rejected'
            Config = (New-RawConfig -Name 'rej-mixed-shapes' -Object (& $rawBase 'rej-mixed-shapes' ([ordered]@{
                        defaultPolicy = 'block'
                        egress        = [ordered]@{ default = 'allow' }
                     }) $null))
            Why    = 'the legacy and directional shapes are alternatives; combining them has no defined meaning'
        }
    )

    foreach ($case in $cases) {
        $log = Join-Path $ScratchRoot ('logs\' + (Split-Path -Leaf $case.Config) + '.log')
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $case.Config -LogPath $log -TimeoutSec 30
        $ranAnyway = [bool]("$($r.Stdout)" -match $marker)
        $logText = $(if (Test-Path $log) { Get-Content $log -Raw -ErrorAction SilentlyContinue } else { '' })
        Record-Result -Phase 'P8f' -Name $case.Name `
            -Pass ((Test-WasRejected -Run $r -Log $logText) -and (-not $ranAnyway)) `
            -Detail "exit=$($r.ExitCode); timedOut=$($r.TimedOut); workloadRan=$ranAnyway; $($case.Why)"
    }

    # Positive control. Every case above asserts "this config failed", which is
    # also true on a host where NOTHING runs — so without a control the whole
    # phase reports green having proven nothing about the reject surface. The
    # control is the same fixture with no offending field: it must succeed and
    # print the marker. If it does not, the six negatives above are
    # unattributable and this phase says so explicitly.
    $ctlPath = New-RawConfig -Name 'rej-positive-control' `
        -Object (& $rawBase 'rej-positive-control' ([ordered]@{
            egress  = [ordered]@{ default = 'allow' }
            ingress = [ordered]@{ default = 'deny'; hostLoopback = 'deny' }
        }) $null)
    $ctlLog = Join-Path $ScratchRoot 'logs\rej-positive-control.log'
    $ctl = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $ctlPath -LogPath $ctlLog -TimeoutSec 30
    $ctlRan = [bool]("$($ctl.Stdout)" -match $marker)
    Record-Result -Phase 'P8f' -Name 'positive control: the same fixture without an offending field RUNS' `
        -Pass (($ctl.ExitCode -eq 0) -and $ctlRan) `
        -Detail ("exit=$($ctl.ExitCode); timedOut=$($ctl.TimedOut); workloadRan=$ctlRan; " +
                 'without this, the six rejections above are indistinguishable from a host on which nothing launches')
}

Invoke-WpcPhase -Key 'NetworkRejections' -Body { Phase-NetworkRejections }
Complete-WpcChild

