# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Denied-path enforcement on the natively selected tier.
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
function Phase-T1DenyForced {
    Section 'Phase 4d: T1 deny-ACE empirical test (skipped if BC not usable)'
    Reset-StateFileBaseline

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
        # Enforcement cannot be tested, but the documented refusal can: the
        # PSEC path rejects deniedPaths outright rather than running unenforced
        # (base_container_runner.rs:2285).
        $rejDir = Join-Path $ScratchRoot 'deniedT1-unsupported'
        New-Item -ItemType Directory -Force -Path $rejDir | Out-Null
        $rejCfg = New-Config -Name 'denied-unsupported' `
            -CommandLine "$env:SystemRoot\System32\cmd.exe /c echo hi" `
            -ReadWrite @((Join-Path $ScratchRoot 'rw')) -Denied @($rejDir)
        $rejLog = Join-Path $ScratchRoot 'logs\denied-unsupported.log'
        $rej = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $rejCfg -LogPath $rejLog -TimeoutSec 30
        Record-Result -Phase 'P4d' -Name 'deniedPaths is refused, not silently unenforced, without SANDBOX_CAP_DENY_PATHS' `
            -Pass (Test-WasRejected $rej) `
            -Detail "exit=$($rej.ExitCode); stderr=$(Format-Snippet $rej.Stderr)"
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
    # Wrapped so the marker proves the workload actually started. Without it a
    # launch failure satisfies every assertion below: no sentinel, non-zero
    # exit, untouched ACLs, no state files.
    $cmd = New-ProbeCommand -Body "type `"$marker`""
    $cfg = New-Config -Name 't1-deny-forced' -CommandLine $cmd -Denied @($denied)
    $log = Join-Path $ScratchRoot 'logs\t1-deny-forced.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log
    $ran = Test-WorkloadRan $r

    $aclAfter = Get-Acl-Snapshot $denied
    $stateAfter = @(Get-NewStateFiles)

    Record-Result -Phase 'P4d' -Name 'selected isolation tier: base-container' -Pass ([bool]($logContent -match '(?im)selected isolation tier:.*?base-container')) -Detail "log saw tier=base-container"
    Record-Result -Phase 'P4d' -Name 'workload actually started' -Pass $ran -Detail "marker seen=$ran; the deny assertions below are only meaningful if it did"
    Record-Result -Phase 'P4d' -Name 'child did not echo denied-file contents (deny ACE worked)' -Pass ($ran -and -not ($r.Stdout -match $sentinel)) -Detail "ran=$ran; stdout-saw-sentinel=$([bool]($r.Stdout -match $sentinel))"
    Record-Result -Phase 'P4d' -Name 'child exited non-zero (access denied)' -Pass ($ran -and $r.ExitCode -ne 0) -Detail "ran=$ran; exit=$($r.ExitCode)"
    Record-Result -Phase 'P4d' -Name 'denied ACL restored after run' -Pass ($aclBefore -eq $aclAfter)
    Record-Result -Phase 'P4d' -Name 'no orphan state files' -Pass ($stateAfter.Count -eq 0) -Detail "files=$($stateAfter.Count)"
}

Invoke-WpcPhase -Key 'T1DenyForced' -Body { Phase-T1DenyForced }
Complete-WpcChild

