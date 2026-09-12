# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_dacl_disabled_test.ps1
#
# Behaviour when DACL augmentation is disabled.
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_dacl_disabled_test.ps1 -RequireTier base-container
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
# Phase 5 — allowDaclMutation=false rejection under forced T3
# -----------------------------------------------------------------------
function Phase-DaclDisabled {
    Section 'Phase 5: debug build, allowDaclMutation=false (DACL-augmentation refusal)'
    Clear-StateFiles

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
    Assert-NoBfscfg -LogContent $logContent -Phase 'P5' -Name 't3-refuse'

    $aclAfter = Get-Acl-Snapshot $rw
    $stateAfter = @(Get-StateFiles)

    Record-Result -Phase 'P5' -Name 'dispatch refused (exit != 0)' -Pass ($r.ExitCode -ne 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P5' -Name 'rw ACL untouched' -Pass ($aclBefore -eq $aclAfter)
    Record-Result -Phase 'P5' -Name 'no state file written' -Pass ($stateAfter.Count -eq 0)
    $stderrOrLog = ($r.Stderr + "`n" + $logContent)
    Record-Result -Phase 'P5' -Name 'error message mentions DACL fallback' -Pass ([bool]($stderrOrLog -match '(?i)DACL fallback'))
}

Invoke-WpcPhase -Key 'DaclDisabled' -Body { Phase-DaclDisabled }
Complete-WpcChild

