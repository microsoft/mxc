# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_network_model3_test.ps1
#
# The three documented spellings of a fully denied network.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_network_model3_test.ps1 -RequireTier base-container
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
# Phase 8b — model 3 has three spellings and they must be identical.
#
# docs/process-container/networking.md §Model 3 states that an explicit
# deny-everything block, an omitted `network` key, and `"network": {}` are
# equivalent. This is exactly the kind of property that rots silently: a
# parser change that makes an absent section mean "inherit" rather than
# "deny" opens a default-allow hole that no single-config test would catch,
# because each config in isolation still behaves plausibly.
# -----------------------------------------------------------------------
function Phase-NetworkModel3Equivalence {
    Section 'Phase 8b: model 3 — explicit deny == omitted network == empty network'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8b' -Name 'model 3 equivalence' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $cmd = Get-AnchorFetchCommand

    $cfgExplicit = New-Config -Name 'net-model3-explicit' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 30000
    $cfgOmitted = New-Config -Name 'net-model3-omitted' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly -TimeoutMs 30000
    $cfgEmpty = New-Config -Name 'net-model3-empty' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly -EmptyNetwork -TimeoutMs 30000

    $explicit = Invoke-NetRun -Name 'net-model3-explicit' -ConfigPath $cfgExplicit
    $omitted  = Invoke-NetRun -Name 'net-model3-omitted'  -ConfigPath $cfgOmitted
    $empty    = Invoke-NetRun -Name 'net-model3-empty'    -ConfigPath $cfgEmpty

    Record-Result -Phase 'P8b' -Name 'explicit deny/deny/deny blocks egress' `
        -Pass ($explicit.Verdict -eq 'BLOCKED') -Detail "verdict=$($explicit.Verdict)"
    Record-Result -Phase 'P8b' -Name 'omitted network block blocks egress (default-deny, not inherit)' `
        -Pass ($omitted.Verdict -eq 'BLOCKED') -Detail "verdict=$($omitted.Verdict)"
    Record-Result -Phase 'P8b' -Name 'empty "network": {} blocks egress' `
        -Pass ($empty.Verdict -eq 'BLOCKED') -Detail "verdict=$($empty.Verdict)"
    Record-Result -Phase 'P8b' -Name 'all three model-3 spellings agree' `
        -Pass ((Test-VerdictsRan @($explicit, $omitted, $empty)) -and
               ($explicit.Verdict -eq $omitted.Verdict) -and ($omitted.Verdict -eq $empty.Verdict)) `
        -Detail "explicit=$($explicit.Verdict); omitted=$($omitted.Verdict); empty=$($empty.Verdict)"
}

Invoke-WpcPhase -Key 'NetworkModel3Equivalence' -Body { Phase-NetworkModel3Equivalence }
Complete-WpcChild

