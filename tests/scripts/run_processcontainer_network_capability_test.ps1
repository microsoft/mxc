# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_network_capability_test.ps1
#
# egress/ingress default -> AppContainer capability mapping.
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_network_capability_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = every assertion passed, 1 = at least one failed (or none
# ran), 78 = MXC-FATAL safety abort, which stops the whole suite.

[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$CargoRoot,
    [string]$WxcDebug,
    [string]$WxcRelease,
    [string]$UiProbeDebug,
    [string]$UiProbeRelease,
    [string]$ScratchRoot,
    [string]$ResultsJson,
    [string]$CargoLog,
    # Host capabilities probed once by the entry script and handed down, so
    # nineteen child processes do not each re-run --probe. Absent (a standalone
    # run) means probe the host here.
    [string]$CapsJson,
    # Not [ValidateSet]-decorated: the attribute binds to the variable, and
    # Initialize-WpcContext assigns through it. It validates the value instead.
    [string]$RequireTier,
    [string]$ExternalAnchorUrl,
    [string]$UnlistedDestinationUrl,
    [switch]$SkipNetwork,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts,
    # Set by the entry script, which owns the scratch tree and has already
    # populated it. A standalone run leaves this off and gets a freshly wiped
    # tree of its own.
    [switch]$ReuseScratch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 8a — the documented egress x ingress capability matrix.
#
# docs/process-container/networking.md §1 states the mapping exactly:
#
#   egress | ingress | capabilities                 | result
#   deny   | deny    | none                         | internet + private denied
#   allow  | deny    | internetClient               | internet out allowed
#   deny   | allow   | privateNetworkClientServer   | PSEC blocks out via WFP,
#                                                     permits private inbound;
#                                                     AppContainer fallback
#                                                     REJECTS (bidirectional)
#   allow  | allow   | both                         | both allowed
#
# The deny/allow row is the interesting one: it is the single combination the
# doc says a non-PSEC tier must REFUSE rather than approximate. A tier that
# quietly accepts it has granted bidirectional private-network access that the
# caller did not ask for, and nothing else in the suite would notice.
# -----------------------------------------------------------------------
function Phase-NetworkCapabilityMatrix {
    Section 'Phase 8a: schema 0.8 egress/ingress capability matrix'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8a' -Name 'network capability matrix' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible

    # --- deny/deny: no capabilities, everything denied.
    $cfgDD = New-Config -Name 'net-matrix-deny-deny' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 30000
    $dd = Invoke-NetRun -Name 'net-matrix-deny-deny' -ConfigPath $cfgDD
    Record-Result -Phase 'P8a' -Name 'egress=deny ingress=deny -> internet denied' `
        -Pass ($dd.Verdict -eq 'BLOCKED') `
        -Detail "verdict=$($dd.Verdict); exit=$($dd.Result.ExitCode)"

    # --- allow/deny: internetClient granted, internet reachable.
    $cfgAD = New-Config -Name 'net-matrix-allow-deny' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'allow' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 30000
    $ad = Invoke-NetRun -Name 'net-matrix-allow-deny' -ConfigPath $cfgAD
    Record-Result -Phase 'P8a' -Name 'egress=allow ingress=deny -> internet REACHED (internetClient granted)' `
        -Pass ($ad.Verdict -eq 'REACHED') `
        -Detail "verdict=$($ad.Verdict); exit=$($ad.Result.ExitCode)"
    # The capability is what makes the grant real. Assert the backend actually
    # named it, so a run that reached the anchor by some other route (a stale
    # firewall hole, an unenforced tier) is not scored as a working grant.
    Record-Result -Phase 'P8a' -Name 'egress=allow logs internetClient capability' `
        -Pass ([bool]((Remove-ConfigEcho $ad.Log) -match '(?i)internetClient')) `
        -Detail 'documented capability mapping for egress.default=allow'

    # --- deny/allow: the tier-dependent row.
    $cfgDA = New-Config -Name 'net-matrix-deny-allow' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'deny' -TimeoutMs 30000
    $da = Invoke-NetRun -Name 'net-matrix-deny-allow' -ConfigPath $cfgDA
    if ($psec) {
        Record-Result -Phase 'P8a' -Name 'egress=deny ingress=allow -> accepted on PSEC, egress still blocked by WFP' `
            -Pass ($da.Verdict -eq 'BLOCKED') `
            -Detail "verdict=$($da.Verdict); exit=$($da.Result.ExitCode)"
        Record-Result -Phase 'P8a' -Name 'egress=deny ingress=allow logs privateNetworkClientServer' `
            -Pass ([bool]((Remove-ConfigEcho $da.Log) -match '(?i)privateNetworkClientServer')) `
            -Detail 'documented capability mapping for ingress.default=allow'
    } else {
        # "The AppContainer fallback rejects this combination because the
        # capability is bidirectional." A run that merely fails late is not a
        # rejection: the container must never start.
        $rejected = Test-WasRejected $da
        Record-Result -Phase 'P8a' -Name 'egress=deny ingress=allow -> REJECTED on non-PSEC tier (bidirectional capability)' `
            -Pass $rejected `
            -Detail "verdict=$($da.Verdict); exit=$($da.Result.ExitCode); timedOut=$($da.Result.TimedOut); tier=$($Script:ExpectedTier)"
    }

    # --- allow/allow: both capabilities.
    $cfgAA = New-Config -Name 'net-matrix-allow-allow' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'allow' -IngressDefault 'allow' -HostLoopback 'deny' -TimeoutMs 30000
    $aa = Invoke-NetRun -Name 'net-matrix-allow-allow' -ConfigPath $cfgAA
    Record-Result -Phase 'P8a' -Name 'egress=allow ingress=allow -> internet REACHED (both capabilities)' `
        -Pass ($aa.Verdict -eq 'REACHED') `
        -Detail "verdict=$($aa.Verdict); exit=$($aa.Result.ExitCode)"
    $aaLog = Remove-ConfigEcho $aa.Log
    Record-Result -Phase 'P8a' -Name 'egress=allow ingress=allow logs both capabilities' `
        -Pass ([bool]($aaLog -match '(?i)internetClient') -and [bool]($aaLog -match '(?i)privateNetworkClientServer')) `
        -Detail 'documented capability mapping for allow/allow'
}

Invoke-WpcPhase -Key 'NetworkCapabilityMatrix' -Body { Phase-NetworkCapabilityMatrix }
Complete-WpcChild

