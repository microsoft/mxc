# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_crash_recovery_test.ps1
#
# DACL restore-state recovery after an abnormal exit.
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_crash_recovery_test.ps1 -RequireTier base-container
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
# Phase 6 — crash-recovery
# -----------------------------------------------------------------------
function Phase-CrashRecovery {
    Section 'Phase 6: debug build, taskkill mid-run (DACL state crash recovery)'
    Clear-StateFiles

    # Crash recovery is about reaping orphaned DACL-augmentation state, so it
    # only applies when an rw policy actually augments DACLs (appcontainer-dacl
    # tier). On a BaseContainer host no ACEs/state files are written for rw
    # paths, so there is nothing to orphan or reap.
    if (-not (Get-ExpectedDaclAug -HasDenied:$false)) {
        Record-Result -Phase 'P6' -Name 'DACL state crash recovery' -Status 'skip' -Detail "rw policy writes no DACL state on tier=$($Script:ExpectedTier)"
        return
    }

    $rw = Join-Path $ScratchRoot 'rw'
    $aclBefore = Get-Acl-Snapshot $rw

    # Need a long-sleeper that does NOT need raw sockets (AppContainer
    # blocks them, so `ping` exits in milliseconds with "Access denied").
    # PowerShell's Start-Sleep just calls WaitForSingleObject — no
    # privilege required.
    $cfg = New-Config -Name 't3-crash' -CommandLine 'powershell.exe -NoLogo -NoProfile -Command "Start-Sleep -Seconds 20"' -ReadWrite @($rw) -TimeoutMs 60000
    $log = Join-Path $ScratchRoot 'logs\t3-crash.log'

    # Natural detection lands at T3 for any policy with rw paths, so no
    # MXC_FORCE_TIER manipulation is needed (and it would be a no-op
    # against the production binary in any case).
    $proc = Start-Process -FilePath $WxcDebug `
        -ArgumentList @('--config', "`"$cfg`"", '--experimental', '--log-file', "`"$log`"") `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $ScratchRoot 'logs\t3-crash.stdout') `
                                      -RedirectStandardError  (Join-Path $ScratchRoot 'logs\t3-crash.stderr')

    # Wait until the dispatcher writes a state file (ACEs applied) or 10s.
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $sf = @(Get-StateFiles | Where-Object { $_.Name -match "pid-$($proc.Id)-" })
        if ($sf.Count -gt 0) { break }
        Start-Sleep -Milliseconds 200
    }
    $stateMid = @(Get-StateFiles | Where-Object { $_.Name -match "pid-$($proc.Id)-" })
    $aclMid = Get-Acl-Snapshot $rw

    Record-Result -Phase 'P6' -Name 'state file present mid-run' -Pass ($stateMid.Count -gt 0)
    Record-Result -Phase 'P6' -Name 'ACEs visible mid-run' -Pass ($aclBefore -ne $aclMid)

    # Kill — simulate hard crash.
    try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch {
        Write-Warning "Could not kill PID $($proc.Id): $_"
    }
    Wait-Process -Id $proc.Id -ErrorAction SilentlyContinue

    $aclAfterKill = Get-Acl-Snapshot $rw
    $stateAfterKill = @(Get-StateFiles | Where-Object { $_.Name -match "pid-$($proc.Id)-" })
    Record-Result -Phase 'P6' -Name 'state file orphaned after kill' -Pass ($stateAfterKill.Count -gt 0)
    Record-Result -Phase 'P6' -Name 'ACEs still on path after kill' -Pass ($aclAfterKill -ne $aclBefore)

    # Next wxc-exec invocation should reap the orphan via recover_orphaned_state.
    $recoveryStdout = & $WxcRelease --probe 2>&1
    Start-Sleep -Milliseconds 300
    $aclAfterRecovery = Get-Acl-Snapshot $rw
    $stateAfterRecovery = @(Get-StateFiles)

    Record-Result -Phase 'P6' -Name 'orphan reaped on next launch'   -Pass ($stateAfterRecovery.Count -eq 0) -Detail "remaining=$($stateAfterRecovery.Count)"
    Record-Result -Phase 'P6' -Name 'ACL restored after recovery'    -Pass ($aclBefore -eq $aclAfterRecovery)
    Record-Result -Phase 'P6' -Name 'startup log mentions DACL recovery' -Pass ([bool](($recoveryStdout -join "`n") -match 'DACL recovery'))
}

Invoke-WpcPhase -Key 'CrashRecovery' -Body { Phase-CrashRecovery }
Complete-WpcChild

