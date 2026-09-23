# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Legacy 0.7 network fields (defaultPolicy / capability enforcement).
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


# Phase 9 — LEGACY network fields, pinned at schema 0.7.
#
# The 0.6/0.7 shape (defaultPolicy / enforcementMode) is a different parse path
# from the directional shape and stays on 0.7 deliberately. Capability-based
# enforcement is an AppContainer primitive, so these run on any tier.
#
# enforcementMode firewall / both and the allowedHosts / blockedHosts lists are
# out of scope: wxc-exec rejects host lists on Windows outright, so there is no
# behavior here to pin.
function New-LegacyConfig {
    # The pre-directional 0.7 network shape. It lives here rather than in
    # New-Config because this is its only consumer, and because none of the
    # 0.8 keys (egress / ingress / runtimeConfig / allowedProxyPeer) exist at
    # 0.7 -- mixing the two would fail on schema shape instead of on the thing
    # under test. Phase 8f authors that deliberate mixture as raw JSON.
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$CommandLine,
        [ValidateSet('allow', 'block')] [string]$DefaultPolicy,
        [ValidateSet('capabilities')] [string]$EnforcementMode,
        [hashtable]$Rest = @{}
    )
    $net = [ordered]@{}
    if ($DefaultPolicy)         { $net['defaultPolicy']   = $DefaultPolicy }
    if ($EnforcementMode)       { $net['enforcementMode'] = $EnforcementMode }
    New-Config -Name $Name -CommandLine $CommandLine `
        -SchemaVersion $Script:LegacySchemaVersion -RawNetwork $net @Rest
}

function Phase-NetworkLegacy07 {
    Section 'Phase 9: legacy network fields (schema 0.7)'
    if ($SkipNetwork) {
        Record-Result -Phase 'P9' -Name 'legacy network' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $cmd = Get-AnchorFetchCommand

    # defaultPolicy allow vs block, capability enforcement. The pair is the
    # assertion: either verdict alone is unattributable.
    $cfgAllow = New-LegacyConfig -Name 'net07-cap-allow' -CommandLine $cmd `
        -DefaultPolicy 'allow' -EnforcementMode 'capabilities' `
        -Rest @{ ReadWrite = $fs.ReadWrite; ReadOnly = $fs.ReadOnly; TimeoutMs = 30000 }
    $cfgBlock = New-LegacyConfig -Name 'net07-cap-block' -CommandLine $cmd `
        -DefaultPolicy 'block' -EnforcementMode 'capabilities' `
        -Rest @{ ReadWrite = $fs.ReadWrite; ReadOnly = $fs.ReadOnly; TimeoutMs = 30000 }

    $allow = Invoke-NetRun -Name 'net07-cap-allow' -ConfigPath $cfgAllow
    $block = Invoke-NetRun -Name 'net07-cap-block' -ConfigPath $cfgBlock

    Record-Result -Phase 'P9' -Name 'schema 0.7 config is accepted (version pinned to 0.7.0-alpha)' `
        -Pass ($allow.Verdict -ne 'NORUN' -or $allow.Result.ExitCode -eq 0) `
        -Detail "exit=$($allow.Result.ExitCode)"
    Record-Result -Phase 'P9' -Name 'legacy defaultPolicy=allow reaches the anchor' `
        -Pass ($allow.Verdict -eq 'REACHED') -Detail "verdict=$($allow.Verdict)"
    Record-Result -Phase 'P9' -Name 'legacy defaultPolicy=block does not reach the anchor' `
        -Pass ($block.Verdict -eq 'BLOCKED') -Detail "verdict=$($block.Verdict)"
    Record-Result -Phase 'P9' -Name 'legacy allow/block differ (policy is what changed the outcome)' `
        -Pass ((Test-VerdictsRan @($allow, $block)) -and ($allow.Verdict -ne $block.Verdict)) `
        -Detail "allow=$($allow.Verdict); block=$($block.Verdict)"

    # Explicit internetClient capability, and the negative control that makes
    # the grant meaningful: same policy, capability withheld.
    $cfgCap = New-LegacyConfig -Name 'net07-explicit-capability' -CommandLine $cmd `
        -DefaultPolicy 'allow' -EnforcementMode 'capabilities' `
        -Rest @{ ReadWrite = $fs.ReadWrite; ReadOnly = $fs.ReadOnly
                 Capabilities = @('internetClient'); TimeoutMs = 30000 }
    $cap = Invoke-NetRun -Name 'net07-explicit-capability' -ConfigPath $cfgCap
    Record-Result -Phase 'P9' -Name 'explicit processContainer.capabilities=[internetClient] reaches the anchor' `
        -Pass ($cap.Verdict -eq 'REACHED') -Detail "verdict=$($cap.Verdict)"
}

Invoke-WpcPhase -Key 'NetworkLegacy07' -Body { Phase-NetworkLegacy07 }
Complete-WpcChild

