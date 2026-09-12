# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_denied_paths_test.ps1
#
# Denied-path enforcement on the natively selected tier.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_denied_paths_test.ps1 -RequireTier base-container
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
# Phase 4d — Tier 1 (BaseContainer) deny-ACE empirical test
#
# Asserts that the deny ACE the dispatcher applies on the T1 path actually
# denies the BaseContainer-spawned child. BaseContainer might not run under
# the AppContainer SID, in which case the ACE targets a principal the child
# is not, and the deny is a silent no-op.
#
# Skipped unless BaseContainer is usable, read from the selected tier rather
# than symbol presence: a present-but-disabled API still resolves to T3,
# where forcing T1 cannot exercise the deny.
# -----------------------------------------------------------------------
function Phase-T1DenyForced {
    Section 'Phase 4d: T1 deny-ACE empirical test (skipped if BC not usable)'
    Clear-StateFiles

    # Use the release-build probe to discover BC usability (same JSON
    # surface as Phase 1). T1 is usable only when the empty-policy probe
    # resolves to base-container.
    $probe = Invoke-Probe -Wxc $WxcRelease -Phase 'P4d' -Name 'bc-presence-probe'
    if (-not $probe) {
        Record-Result -Phase 'P4d' -Name 'probe succeeded' -Pass $false -Detail 'probe returned null; cannot proceed'
        return
    }
    if ($probe.tier -ne 'base-container') {
        Record-Result -Phase 'P4d' -Name 'BaseContainer usable (required for T1 deny test)' -Status 'skip' -Detail "BaseContainer not usable on this host (tier=$($probe.tier), apiPresent=$($probe.probes.baseContainerApiPresent))"
        return
    }
    # The deny test is only meaningful once BaseContainer can enforce
    # deniedPaths. Before SANDBOX_CAP_DENY_PATHS lights up the runner rejects
    # deniedPaths outright, which would otherwise make this phase "pass"
    # vacuously (the run aborts, so the child never echoes the secret). Skip
    # until the capability is present; it then asserts real deny enforcement.
    if (-not $Script:Caps.SupportsDeniedPaths) {
        Record-Result -Phase 'P4d' -Name 'BaseContainer deny-ACE enforcement' -Status 'skip' -Detail 'BaseContainer does not yet support deniedPaths (no SANDBOX_CAP_DENY_PATHS)'
        return
    }

    $denied = Join-Path $ScratchRoot 'deniedT1'
    New-Item -ItemType Directory -Force -Path $denied | Out-Null
    $marker = Join-Path $denied 'secret.txt'
    # Use a sentinel string the test can grep for. If the child ever
    # echoes it, the deny ACE failed silently.
    $sentinel = 'T1_DENY_SENTINEL_e54a23'
    Set-Content -LiteralPath $marker -Value $sentinel -Encoding utf8 -Force

    $aclBefore = Get-Acl-Snapshot $denied

    # The child invocation: try to read the marker. cmd.exe's `type`
    # writes "Access is denied." (or an OS-localized variant) to stderr
    # and exits with a non-zero code when the file can't be opened.
    $cmd = "cmd /c type `"$marker`""
    $cfg = New-Config -Name 't1-deny-forced' -CommandLine $cmd -Denied @($denied)
    $log = Join-Path $ScratchRoot 'logs\t1-deny-forced.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log

    $aclAfter = Get-Acl-Snapshot $denied
    $stateAfter = @(Get-StateFiles)

    Record-Result -Phase 'P4d' -Name 'selected isolation tier: base-container' -Pass ([bool]($logContent -match '(?im)selected isolation tier:.*?base-container')) -Detail "log saw tier=base-container"
    Record-Result -Phase 'P4d' -Name 'child did not echo denied-file contents (deny ACE worked)' -Pass (-not ($r.Stdout -match $sentinel)) -Detail "stdout-saw-sentinel=$([bool]($r.Stdout -match $sentinel))"
    Record-Result -Phase 'P4d' -Name 'child exited non-zero (access denied)' -Pass ($r.ExitCode -ne 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P4d' -Name 'denied ACL restored after run' -Pass ($aclBefore -eq $aclAfter)
    Record-Result -Phase 'P4d' -Name 'no orphan state files' -Pass ($stateAfter.Count -eq 0) -Detail "files=$($stateAfter.Count)"
}

Invoke-WpcPhase -Key 'T1DenyForced' -Body { Phase-T1DenyForced }
Complete-WpcChild

