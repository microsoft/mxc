# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# network.ingress.hostLoopback enforcement.
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


# Phase 8d — host loopback.
#
# The shared spec (D2) blocks host loopback by default and states that an
# OMITTED `hostLoopback` is `deny`, not an inherit of `ingress.default`. That
# is the documented trap: `egress.default: allow` with no ingress section
# reaches the whole internet but not the host's own loopback. Both directions
# of getting this wrong are user-visible — an unreachable local dev server, or
# a loopback hole — and only a live run distinguishes them.
#
# BaseContainer must reach the host listener without a runtime proxy.
# AppContainer tiers must reject hostLoopback=allow.
function Phase-NetworkDirectHostLoopback {
    Section 'Phase 8d: direct host-loopback policy'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8d' -Name 'host loopback' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $listener = Start-LoopbackListener
    if (-not $listener) {
        Record-Result -Phase 'P8d' -Name 'host loopback listener' -Pass $false `
            -Detail 'could not bind a TcpListener on 127.0.0.1; cannot assert either direction'
        return
    }

    try {
        # Prerequisite: the HOST itself must reach its own listener, else every
        # "blocked" reading below is unattributable.
        $hostReach = $false
        try {
            $resp = Invoke-WebRequest -Uri $listener.Url -TimeoutSec 5 -UseBasicParsing
            $hostReach = ($resp.Content -match 'MXC-LOOPBACK-ANCHOR')
        } catch {}
        Record-Result -Phase 'P8d' -Name 'prerequisite: host reaches its own loopback anchor' `
            -Pass $hostReach -Detail $listener.Url
        if (-not $hostReach) { return }

        $fs = Get-NetFsGrants
        $cmd = Get-LoopbackFetchCommand -Url $listener.Url

        # The documented trap: egress allow, ingress section omitted entirely.
        $cfgTrap = New-Config -Name 'net-loopback-trap' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'allow' -TimeoutMs 25000
        $trap = Invoke-NetRun -Name 'net-loopback-trap' -ConfigPath $cfgTrap
        $trapBlocked = (-not $trap.Result.TimedOut) -and
            ($trap.Result.ExitCode -in @(7, 28)) -and
            ($trap.Result.Stderr -match 'curl: \((7|28)\)')
        Record-Result -Phase 'P8d' -Name 'omitted hostLoopback defaults to deny even under egress=allow' `
            -Pass $trapBlocked `
            -Detail "exit=$($trap.Result.ExitCode); stderr=$(Format-Snippet $trap.Result.Stderr); documented default-deny"

        # Explicit deny, spelled out.
        $cfgDeny = New-Config -Name 'net-loopback-deny' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'allow' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 25000
        $deny = Invoke-NetRun -Name 'net-loopback-deny' -ConfigPath $cfgDeny
        $denyBlocked = (-not $deny.Result.TimedOut) -and
            ($deny.Result.ExitCode -in @(7, 28)) -and
            ($deny.Result.Stderr -match 'curl: \((7|28)\)')
        Record-Result -Phase 'P8d' -Name 'explicit hostLoopback=deny blocks container -> host loopback' `
            -Pass $denyBlocked -Detail "exit=$($deny.Result.ExitCode); stderr=$(Format-Snippet $deny.Result.Stderr)"
        Record-Result -Phase 'P8d' -Name 'omitted and explicit hostLoopback=deny agree' `
            -Pass ($trapBlocked -and $denyBlocked) `
            -Detail "omittedExit=$($trap.Result.ExitCode); explicitExit=$($deny.Result.ExitCode)"

        # Loopback permission is independent of the private-network ingress default.
        foreach ($ingressDefault in @('allow', 'deny')) {
            $name = "net-loopback-allow-ingress-$ingressDefault"
            $cfgAllow = New-Config -Name $name -CommandLine $cmd `
                -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
                -EgressDefault 'allow' -IngressDefault $ingressDefault -HostLoopback 'allow' -TimeoutMs 25000
            $allow = Invoke-NetRun -Name $name -ConfigPath $cfgAllow

            if (Test-PsecEligible) {
                Record-Result -Phase 'P8d' -Name "hostLoopback=allow with ingress.default=$ingressDefault without a runtime proxy stays on BaseContainer" `
                    -Pass (Test-SelectedTier $allow.Log) `
                    -Detail "selectedTier=$(Get-SelectedTier $allow.Log); expected=base-container"
                Record-Result -Phase 'P8d' -Name "hostLoopback=allow with ingress.default=$ingressDefault without a runtime proxy reaches the host loopback anchor" `
                    -Pass (($allow.Result.Stdout.Trim() -eq 'MXC-LOOPBACK-ANCHOR') -and ($allow.Result.ExitCode -eq 0) -and -not $allow.Result.TimedOut) `
                    -Detail "exit=$($allow.Result.ExitCode); timedOut=$($allow.Result.TimedOut); stderr=$(Format-Snippet $allow.Result.Stderr); rejection is a regression, not a skip"
            } else {
                $rejected = Test-WasRejected $allow
                Record-Result -Phase 'P8d' -Name "non-PSEC tier rejects hostLoopback=allow with ingress.default=$ingressDefault" `
                    -Pass $rejected `
                    -Detail "verdict=$($allow.Verdict); exit=$($allow.Result.ExitCode); timedOut=$($allow.Result.TimedOut); tier=$($Script:ExpectedTier)"
            }
        }
    } finally {
        & $listener.Stop
    }
}

Invoke-WpcPhase -Key 'NetworkDirectHostLoopback' -Body { Phase-NetworkDirectHostLoopback }
Complete-WpcChild
