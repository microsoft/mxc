# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_denied_release_test.ps1
#
# Release-build run with a denied path.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_denied_release_test.ps1 -RequireTier base-container
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
# Phase 3 — release-build deniedPaths-only (safe lane; deny routes via DACL)
# -----------------------------------------------------------------------
function Phase-DeniedRelease {
    if ($SkipReleaseLane) {
        Section 'Phase 3: SKIPPED (--SkipReleaseLane)'
        # See the note in run_processcontainer_empty_release_test.ps1: a
        # deliberate skip must be recorded, or it is indistinguishable from an
        # area that did nothing because of a bug.
        Record-Result -Phase 'P3' -Name 'release lane' -Status 'skip' -Detail '-SkipReleaseLane was passed'
        return
    }
    Section 'Phase 3: release build, deniedPaths only (safe lane)'
    Clear-StateFiles

    # deniedPaths is enforced on T3 (DENY ACEs) and on BaseContainer only once
    # the SANDBOX_CAP_DENY_PATHS bit lights up. Where unsupported, the runner
    # rejects deniedPaths at launch, so skip rather than assert a transient
    # limitation (the phase auto-enables when the capability appears).
    if (-not $Script:Caps.SupportsDeniedPaths) {
        Record-Result -Phase 'P3' -Name 'deniedPaths run' -Status 'skip' -Detail "deniedPaths not supported on tier=$($Script:ExpectedTier) (no SANDBOX_CAP_DENY_PATHS)"
        return
    }

    $denied = Join-Path $ScratchRoot 'denied'
    $aclBefore = Get-Acl-Snapshot $denied

    $cfg = New-Config -Name 'denied-release' -CommandLine 'cmd /c exit 0' -Denied @($denied)
    $log = Join-Path $ScratchRoot 'logs\denied-release.log'
    $r = Invoke-Wxc -Wxc $WxcRelease -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log
    # Deny ACEs route through DaclManager on either tier; only the
    # selected-tier label differs.
    Assert-NoBfscfg -LogContent $logContent -Phase 'P3' -Name 'denied-release'

    $aclAfter = Get-Acl-Snapshot $denied

    Record-Result -Phase 'P3' -Name 'release exit=0' -Pass ($r.ExitCode -eq 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P3' -Name "selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContent) -Detail "expected=$($Script:ExpectedTier)"
    Record-Result -Phase 'P3' -Name 'denied-path ACL restored after run' -Pass ($aclBefore -eq $aclAfter)
    Record-Result -Phase 'P3' -Name 'no orphan state files' -Pass (@(Get-StateFiles).Count -eq 0)
}

Invoke-WpcPhase -Key 'DeniedRelease' -Body { Phase-DeniedRelease }
Complete-WpcChild

