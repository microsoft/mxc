# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Read-only --probe assertions: tier selection and capability reporting.
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


# Phase 1 — probes (read-only)
#
# Only T1 and T3 are in scope. The selected tier is the same for every policy
# shape: `base-container` when BaseContainer is usable, else
# `appcontainer-dacl`. The phase keys off $Script:ExpectedTier (derived from the
# empty-policy probe) rather than any OS-version assumption, so it runs
# unchanged on both T1-capable and T3-only hosts. needsDaclAugmentation is
# asserted via Get-ExpectedDaclAug (DACL tier always augments; BaseContainer
# augments only for denied paths).
function Phase-Probes {
    Section 'Phase 1: --probe (read-only)'

    $rw = Join-Path $ScratchRoot 'rw'
    $denied = Join-Path $ScratchRoot 'denied'

    $probeEmpty = Invoke-Probe -Wxc $WxcRelease -Phase 'P1' -Name 'probe-no-config'
    if ($probeEmpty) {
        $bcState = if ($Script:Caps.BaseContainerUsable) { 'usable' }
                   elseif ($probeEmpty.probes.baseContainerApiPresent) { 'present-but-disabled' }
                   else { 'absent' }
        Write-Host ("BaseContainer state on this host: {0} (apiPresent={1}); expected tier={2}" -f $bcState, $probeEmpty.probes.baseContainerApiPresent, $Script:ExpectedTier)

        Record-Result -Phase 'P1' -Name 'expected tier is a recognized value' -Pass ($Script:ExpectedTier -in @('base-container', 'appcontainer-dacl')) -Detail "expectedTier=$($Script:ExpectedTier)"
        # $Script:ExpectedTier is itself derived from an empty-policy probe, so
        # this shows repeatability, not that the tier was selected correctly.
        # -RequireTier is what pins the tier for a CI job.
        Record-Result -Phase 'P1' -Name "empty policy probe is repeatable -> tier=$($Script:ExpectedTier)" -Pass ($probeEmpty.tier -eq $Script:ExpectedTier) -Detail "tier=$($probeEmpty.tier); consistency check, not tier validation -- use -RequireTier for that"
        $expAugEmpty = Get-ExpectedDaclAug -HasDenied:$false
        Record-Result -Phase 'P1' -Name "empty policy probe -> needsDaclAugmentation=$expAugEmpty" -Pass ($probeEmpty.needsDaclAugmentation -eq $expAugEmpty) -Detail "needsDaclAugmentation=$($probeEmpty.needsDaclAugmentation)"
    }

    $cfgRw = New-Config -Name 'probe-rw' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw)
    $probeRw = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgRw -Phase 'P1' -Name 'probe-rw-config'
    if ($probeRw) {
        Record-Result -Phase 'P1' -Name "rw-paths probe -> tier=$($Script:ExpectedTier)" -Pass ($probeRw.tier -eq $Script:ExpectedTier) -Detail "tier=$($probeRw.tier)"
        $expAugRw = Get-ExpectedDaclAug -HasDenied:$false
        Record-Result -Phase 'P1' -Name "rw-paths probe -> needsDaclAugmentation=$expAugRw" -Pass ($probeRw.needsDaclAugmentation -eq $expAugRw) -Detail "needsDaclAugmentation=$($probeRw.needsDaclAugmentation)"
    }

    $cfgDenied = New-Config -Name 'probe-denied' -CommandLine 'cmd /c exit 0' -Denied @($denied)
    $probeDenied = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgDenied -Phase 'P1' -Name 'probe-denied-config'
    if ($probeDenied) {
        Record-Result -Phase 'P1' -Name "denied probe -> tier=$($Script:ExpectedTier)" -Pass ($probeDenied.tier -eq $Script:ExpectedTier) -Detail "tier=$($probeDenied.tier)"
        $expAugDenied = Get-ExpectedDaclAug -HasDenied:$true
        Record-Result -Phase 'P1' -Name "denied probe -> needsDaclAugmentation=$expAugDenied" -Pass ($probeDenied.needsDaclAugmentation -eq $expAugDenied) -Detail "needsDaclAugmentation=$($probeDenied.needsDaclAugmentation)"
    }

    $cfgRefuse = New-Config -Name 'probe-refuse' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw) -AllowDaclMutation $false
    $probeRefuse = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgRefuse -Phase 'P1' -Name 'probe-allow-dacl-false'
    if ($probeRefuse) {
        # Under Set-StrictMode -Version Latest, accessing an absent property
        # throws; check existence via PSObject.Properties instead of
        # `$null -eq $obj.foo`.
        $tierMissing = -not [bool]$probeRefuse.PSObject.Properties['tier']
        $errorStr    = if ($probeRefuse.PSObject.Properties['error']) { [string]$probeRefuse.error } else { '' }
        if (Get-ExpectedDaclAug -HasDenied:$false) {
            # The expected tier needs DACL augmentation for rw paths, so
            # allowDaclMutation=false trips DaclFallbackDisabled and the
            # detector returns an error (tier omitted).
            Record-Result -Phase 'P1' -Name 'allowDaclMutation=false + rw-paths probe -> error (DACL augmentation refused)' -Pass ($tierMissing -and ($errorStr -match 'DACL fallback')) -Detail "tierMissing=$tierMissing; error=$errorStr"
        } else {
            # BaseContainer host: rw paths need no DACL augmentation, so
            # allowDaclMutation=false is a no-op and the probe still resolves.
            $tierVal = if ($probeRefuse.PSObject.Properties['tier']) { [string]$probeRefuse.tier } else { '<missing>' }
            Record-Result -Phase 'P1' -Name 'allowDaclMutation=false + rw-paths probe -> still resolves (no DACL augmentation needed)' -Pass ((-not $tierMissing) -and ($tierVal -eq $Script:ExpectedTier)) -Detail "tier=$tierVal; error=$errorStr"
        }
    }
}

Invoke-WpcPhase -Key 'Probes' -Body { Phase-Probes }
Complete-WpcChild

