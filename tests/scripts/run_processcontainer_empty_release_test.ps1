# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_empty_release_test.ps1
#
# Release-build run under an empty policy.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_empty_release_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = all passed, 1 = a failure or zero assertions, 78 = fatal.

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
    [string]$CapsJson,
    [string]$RequireTier,
    [string]$ExternalAnchorUrl,
    [string]$UnlistedDestinationUrl,
    [switch]$SkipNetwork,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts,
    [switch]$ReuseScratch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 2 — release-build empty-policy run (safe lane)
# -----------------------------------------------------------------------
function Phase-EmptyRelease {
    if ($SkipReleaseLane) {
        Section 'Phase 2: SKIPPED (--SkipReleaseLane)'
        # Record the skip rather than returning silently. An area that produces
        # no assertions at all is treated as a failure by both Complete-WpcChild
        # and the entry script, because "nothing ran" is normally a bug. A
        # deliberate skip has to say so to be distinguishable from one.
        Record-Result -Phase 'P2' -Name 'release lane' -Status 'skip' -Detail '-SkipReleaseLane was passed'
        return
    }
    Section 'Phase 2: release build, empty FS policy (safe lane)'

    # Use `echo` (a cmd builtin — no external EXE load, no LSA/RPC) and
    # assert the output round-trips back. Avoid `whoami`, `hostname`,
    # `set`, etc. which exercise capabilities the empty policy doesn't
    # grant — those would correctly fail under AppContainer and look
    # like a regression here.
    $cfg = New-Config -Name 'empty-release' -CommandLine 'cmd /c echo P2-empty-release-ok'
    $log = Join-Path $ScratchRoot 'logs\empty-release.log'
    $r = Invoke-Wxc -Wxc $WxcRelease -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log
    Assert-NoBfscfg -LogContent $logContent -Phase 'P2' -Name 'empty-release'

    Record-Result -Phase 'P2' -Name 'release exit=0' -Pass ($r.ExitCode -eq 0) -Detail "exit=$($r.ExitCode); stdout=$($r.Stdout.Trim())"
    Record-Result -Phase 'P2' -Name 'AppContainer ran the child (stdout round-trip)' -Pass ($r.Stdout -match 'P2-empty-release-ok')
    Record-Result -Phase 'P2' -Name "selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContent) -Detail "expected=$($Script:ExpectedTier)"
    Record-UiTelemetryResult -Phase 'P2' -Name 'UI restrictions applied telemetry' -LogContent $logContent -Check 'ui-restrictions'
}

Invoke-WpcPhase -Key 'EmptyRelease' -Body { Phase-EmptyRelease }
Complete-WpcChild

