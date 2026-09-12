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
# `hostLoopback: "allow"` is PSEC-1.1-only; every other path must reject it
# rather than accept it with partial enforcement.
function Phase-NetworkHostLoopback {
    Section 'Phase 8d: host-loopback policy'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8d' -Name 'host loopback' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $listener = Start-LoopbackListener
    if (-not $listener) {
        Record-Result -Phase 'P8d' -Name 'host loopback listener' -Pass $false `
            -Detail 'could not bind an HttpListener on 127.0.0.1; cannot assert either direction'
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
        Record-Result -Phase 'P8d' -Name 'omitted hostLoopback defaults to deny even under egress=allow' `
            -Pass ($trap.Verdict -eq 'BLOCKED') `
            -Detail "verdict=$($trap.Verdict); documented default-deny, not an inherit of egress/ingress default"

        # Explicit deny, spelled out.
        $cfgDeny = New-Config -Name 'net-loopback-deny' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'allow' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 25000
        $deny = Invoke-NetRun -Name 'net-loopback-deny' -ConfigPath $cfgDeny
        Record-Result -Phase 'P8d' -Name 'explicit hostLoopback=deny blocks container -> host loopback' `
            -Pass ($deny.Verdict -eq 'BLOCKED') -Detail "verdict=$($deny.Verdict)"
        Record-Result -Phase 'P8d' -Name 'omitted and explicit hostLoopback=deny agree' `
            -Pass ((Test-VerdictsRan @($trap, $deny)) -and ($trap.Verdict -eq $deny.Verdict)) `
            -Detail "omitted=$($trap.Verdict); explicit=$($deny.Verdict)"

        # hostLoopback=allow. `ingress.default: allow` accompanies it because
        # the private-network capability is what the doc pairs with the
        # loopback grant; the specific value overrides the default for the
        # loopback path.
        $cfgAllow = New-Config -Name 'net-loopback-allow' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'allow' -IngressDefault 'allow' -HostLoopback 'allow' -TimeoutMs 25000
        $allow = Invoke-NetRun -Name 'net-loopback-allow' -ConfigPath $cfgAllow

        if (Test-PsecEligible) {
            # On a PSEC 1.1 host this must work. On a PSEC 1.0 host the
            # documented behavior is rejection — so either outcome is
            # defensible, but "accepted and silently unenforced" is not.
            $accepted = ($allow.Verdict -eq 'REACHED')
            $rejected = Test-WasRejected $allow
            Record-Result -Phase 'P8d' -Name 'hostLoopback=allow is either enforced or rejected, never silently dropped' `
                -Pass ($accepted -or $rejected) `
                -Detail "verdict=$($allow.Verdict); exit=$($allow.Result.ExitCode); timedOut=$($allow.Result.TimedOut); accepted=$accepted rejected=$rejected"
            if ($accepted) {
                Record-Result -Phase 'P8d' -Name 'hostLoopback=allow reaches the host loopback anchor (PSEC 1.1)' `
                    -Pass $true -Detail 'bidirectional host-loopback grant honored'
            } elseif ($rejected) {
                Record-Result -Phase 'P8d' -Name 'hostLoopback=allow rejected (PSEC 1.1 ingress contract unavailable)' `
                    -Status 'skip' -Detail "exit=$($allow.Result.ExitCode); documented fallback when contract 1.1 is absent"
            } else {
                # Neither enforced nor refused. Calling this a skip would name an
                # outcome that did not happen.
                Record-Result -Phase 'P8d' -Name 'hostLoopback=allow reaches the host loopback anchor (PSEC 1.1)' `
                    -Pass $false `
                    -Detail "verdict=$($allow.Verdict); exit=$($allow.Result.ExitCode); neither reached the anchor nor produced a typed rejection"
            }
        } else {
            $rejected = Test-WasRejected $allow
            Record-Result -Phase 'P8d' -Name 'non-PSEC tier rejects hostLoopback=allow' `
                -Pass $rejected `
                -Detail "verdict=$($allow.Verdict); exit=$($allow.Result.ExitCode); timedOut=$($allow.Result.TimedOut); tier=$($Script:ExpectedTier)"
        }
    } finally {
        & $listener.Stop
    }
}

Invoke-WpcPhase -Key 'NetworkHostLoopback' -Body { Phase-NetworkHostLoopback }
Complete-WpcChild

