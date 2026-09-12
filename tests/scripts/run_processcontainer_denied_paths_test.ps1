# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_denied_paths_test.ps1
#
# Denied-path enforcement on the natively selected tier.
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_denied_paths_test.ps1 -RequireTier base-container
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
# Phase 4d — Tier 1 (BaseContainer) deny-ACE empirical test
#
# Asserts that the deny ACE the dispatcher applies on the T1 path
# actually denies the BaseContainer-spawned child access to the path.
# This is the empirical answer to phase-4 review #4 ("BaseContainer
# might not run under the AppContainer SID, in which case the deny ACE
# targets a principal the child does not run as → silent no-op").
#
# Strategy:
#   1. Skip the phase entirely unless BaseContainer is *usable* on this
#      host (most current 25H2 hosts have either no API or a disabled
#      one, where Tier 1 is never selected). Usability is read from the
#      selected tier, not raw symbol presence: a present-but-disabled
#      API still resolves to T3, so forcing T1 there cannot exercise the
#      deny.
#   2. Create a marker file under a denied directory. Force T1. Have the
#      child try to `type` the marker. The child must exit non-zero AND
#      not echo the marker contents.
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

