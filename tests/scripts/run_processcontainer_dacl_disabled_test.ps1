# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Behaviour when DACL augmentation is disabled.
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


# Phase 5 — allowDaclMutation=false rejection under forced T3
function Phase-DaclDisabled {
    Section 'Phase 5: debug build, allowDaclMutation=false (DACL-augmentation refusal)'
    Reset-StateFileBaseline

    # This phase exercises the DACL-augmentation refusal path, which only
    # engages when the host's expected tier augments DACLs for an rw policy
    # (i.e. appcontainer-dacl). On a BaseContainer host, rw paths use the
    # BaseContainer mechanism and need no DACL augmentation, so
    # allowDaclMutation=false is a no-op and there is nothing to refuse.
    if (-not (Get-ExpectedDaclAug -HasDenied:$false)) {
        Record-Result -Phase 'P5' -Name 'DACL-augmentation refusal' -Status 'skip' -Detail "rw policy needs no DACL augmentation on tier=$($Script:ExpectedTier)"
        return
    }

    $rw = Join-Path $ScratchRoot 'rw'
    $aclBefore = Get-Acl-Snapshot $rw

    $cfg = New-Config -Name 't3-refuse' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw) -AllowDaclMutation $false
    $log = Join-Path $ScratchRoot 'logs\t3-refuse.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log

    $aclAfter = Get-Acl-Snapshot $rw
    $stateAfter = @(Get-NewStateFiles)

    # A bare `exit != 0` is satisfied by a launch failure or a harness timeout,
    # which is the false-green pattern this suite exists to remove. This refusal
    # is raised during runner resolution, before any launch API, so wxc-exec
    # logs a ConfigRejected event with reason `runner_unavailable` and exits 1.
    # Test-WasRejected does not apply here: it deliberately treats
    # `runner_unavailable` as a non-rejection, because everywhere else it means
    # the host could not build a tier and the policy was never judged.
    $stderrOrLog = ($r.Stderr + "`n" + $logContent)
    $typedRefusal = [bool]($stderrOrLog -match '"reason"\s*:\s*"runner_unavailable"')
    $refused = (-not $r.TimedOut) -and ($r.ExitCode -eq 1) -and $typedRefusal
    Record-Result -Phase 'P5' -Name 'dispatch refused before launch (typed runner_unavailable, exit 1)' `
        -Pass $refused `
        -Detail "exit=$($r.ExitCode); timedOut=$($r.TimedOut); typedRefusal=$typedRefusal"
    Record-Result -Phase 'P5' -Name 'rw ACL untouched' -Pass ($aclBefore -eq $aclAfter)
    Record-Result -Phase 'P5' -Name 'no state file written' -Pass ($stateAfter.Count -eq 0)
    # Separates this refusal from any other runner_unavailable cause.
    Record-Result -Phase 'P5' -Name 'error message mentions DACL fallback' -Pass ([bool]($stderrOrLog -match '(?i)DACL fallback'))
}

Invoke-WpcPhase -Key 'DaclDisabled' -Body { Phase-DaclDisabled }
Complete-WpcChild

