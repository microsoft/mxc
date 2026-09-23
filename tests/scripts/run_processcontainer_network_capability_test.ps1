# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# egress/ingress default -> AppContainer capability mapping.
#
# Runs standalone, or under run_processcontainer_all_tests.ps1.

[CmdletBinding()]
param(
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


# Phase 8a — the documented egress x ingress capability matrix.
# docs/process-container/networking.md §1 gives the mapping. The deny/allow
# row is the one combination the doc says a non-PSEC tier must REFUSE rather
# than approximate: privateNetworkClientServer is bidirectional, so accepting
# it there would grant inbound access the caller never asked for.
function Phase-NetworkCapabilityMatrix {
    Section 'Phase 8a: schema 0.8 egress/ingress capability matrix'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8a' -Name 'network capability matrix' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible

    $cases = @(
        @{ Egress = 'deny';  Ingress = 'deny'
           Verdict = 'BLOCKED'
           Name = 'egress=deny ingress=deny -> internet denied' }
        @{ Egress = 'allow'; Ingress = 'deny'
           Verdict = 'REACHED'
           Name = 'egress=allow ingress=deny -> internet REACHED (internetClient granted)' }
        # Accepted only on PSEC, where WFP still blocks egress; every other
        # tier must reject the config outright.
        @{ Egress = 'deny';  Ingress = 'allow'
           Verdict = 'BLOCKED'
           RejectUnlessPsec = $true
           Name = 'egress=deny ingress=allow -> accepted on PSEC, egress still blocked by WFP' }
        @{ Egress = 'allow'; Ingress = 'allow'
           Verdict = 'REACHED'
           Name = 'egress=allow ingress=allow -> internet REACHED (both capabilities)' }
    )

    foreach ($case in $cases) {
        $name = "net-matrix-$($case.Egress)-$($case.Ingress)"
        $cfg = New-Config -Name $name -CommandLine (Get-AnchorFetchCommand) `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault $case.Egress -IngressDefault $case.Ingress `
            -HostLoopback 'deny' -TimeoutMs 30000
        $run = Invoke-NetRun -Name $name -ConfigPath $cfg
        $detail = "verdict=$($run.Verdict); exit=$($run.Result.ExitCode)"

        if ($case.ContainsKey('RejectUnlessPsec') -and -not $psec) {
            Record-Result -Phase 'P8a' `
                -Name "egress=$($case.Egress) ingress=$($case.Ingress) -> REJECTED on non-PSEC tier (bidirectional capability)" `
                -Pass (Test-WasRejected $run) `
                -Detail "$detail; timedOut=$($run.Result.TimedOut); tier=$($Script:ExpectedTier)"
            continue
        }

        Record-Result -Phase 'P8a' -Name $case.Name -Pass ($run.Verdict -eq $case.Verdict) -Detail $detail
    }
}

Invoke-WpcPhase -Key 'NetworkCapabilityMatrix' -Body { Phase-NetworkCapabilityMatrix }
Complete-WpcChild
