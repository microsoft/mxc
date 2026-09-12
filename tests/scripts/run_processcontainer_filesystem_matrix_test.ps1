# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_filesystem_matrix_test.ps1
#
# Read-write / read-only / denied / unlisted filesystem access matrix.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_filesystem_matrix_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = all passed, 1 = a failure or zero assertions, 78 = fatal.

[CmdletBinding()]
param(
    # -ContextJson carries the context the entry script already resolved.
    # Anything passed explicitly overrides it, so a standalone run works too.
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


# -----------------------------------------------------------------------
# Phase 4 — debug build, T3 forced, rw + ro + denied (the real test)
# -----------------------------------------------------------------------
function Phase-T3Forced {
    Section 'Phase 4: debug build, natural detection -> T3'
    Reset-StateFileBaseline

    $rw = Join-Path $ScratchRoot 'rw'
    $ro = Join-Path $ScratchRoot 'ro'
    $denied = Join-Path $ScratchRoot 'denied'

    $aclRwBefore     = Get-Acl-Snapshot $rw
    $aclRoBefore     = Get-Acl-Snapshot $ro
    $aclDeniedBefore = Get-Acl-Snapshot $denied

    $cmd = "cmd /c echo hello-from-t3 > `"$rw\probe.txt`" && type `"$rw\probe.txt`""
    # deniedPaths is only included where the tier can enforce it; on a
    # BaseContainer host without deny support the runner would reject the whole
    # request. rw/ro still exercise the grant path either way. Assign in two
    # steps: `if/else { @() }` as an expression collapses an empty array to
    # $null, which then trips New-Config's `.Count` under StrictMode.
    $deniedPolicy = @()
    if ($Script:Caps.SupportsDeniedPaths) { $deniedPolicy = @($denied) }
    $cfg = New-Config -Name 't3-forced' -CommandLine $cmd -ReadWrite @($rw) -ReadOnly @($ro) -Denied $deniedPolicy
    $log = Join-Path $ScratchRoot 'logs\t3-forced.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log

    $aclRwAfter     = Get-Acl-Snapshot $rw
    $aclRoAfter     = Get-Acl-Snapshot $ro
    $aclDeniedAfter = Get-Acl-Snapshot $denied
    $stateAfter     = @(Get-NewStateFiles)

    Record-Result -Phase 'P4' -Name 'child exit=0' -Pass ($r.ExitCode -eq 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P4' -Name "selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContent) -Detail "expected=$($Script:ExpectedTier)"
    Record-UiTelemetryResult -Phase 'P4' -Name 'UI restrictions applied telemetry' -LogContent $logContent -Check 'ui-restrictions'
    Record-UiTelemetryResult -Phase 'P4' -Name 'Win32k mitigation NOT applied (ui.disable=false)' -LogContent $logContent -Check 'win32k' -Expected $false -Detail 'this config has ui.disable=false'
    Record-Result -Phase 'P4' -Name 'rw ACL restored after run'     -Pass ($aclRwBefore -eq $aclRwAfter)
    Record-Result -Phase 'P4' -Name 'ro ACL restored after run'     -Pass ($aclRoBefore -eq $aclRoAfter)
    Record-Result -Phase 'P4' -Name 'denied ACL restored after run' -Pass ($aclDeniedBefore -eq $aclDeniedAfter)
    Record-Result -Phase 'P4' -Name 'no orphan state files'         -Pass ($stateAfter.Count -eq 0) -Detail "files=$($stateAfter.Count)"
    Record-Result -Phase 'P4' -Name 'child wrote and read inside rw path' -Pass ($r.Stdout -match 'hello-from-t3')

    # And again with ui.disable=true so we hit the Win32k MITIGATION_POLICY path.
    # cmd.exe will likely fail to initialize under Win32k disable (it loads
    # user32 indirectly), so we don't assert child exit=0 — only that the
    # mitigation telemetry was emitted (which happens before CreateProcessW).
    $cfg2 = New-Config -Name 't3-ui-disable' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw)
    $json = Get-Content -Raw $cfg2 | ConvertFrom-Json
    $json.ui.disable = $true
    ($json | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $cfg2 -Encoding utf8 -Force

    $log2 = Join-Path $ScratchRoot 'logs\t3-ui-disable.log'
    $r2 = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg2 -LogPath $log2
    $logContent2 = Read-Log $log2

    Record-UiTelemetryResult -Phase 'P4' -Name 'ui.disable=true emits Win32k mitigation applied' -LogContent $logContent2 -Check 'win32k' -Detail "child exit=$($r2.ExitCode) (expected to fail; cmd.exe needs Win32k)"
    Record-Result -Phase 'P4' -Name "ui.disable=true emits selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContent2) -Detail "expected=$($Script:ExpectedTier)"
    # Even though child crashed, ACEs must still be cleaned up.
    $aclRwAfterUi = Get-Acl-Snapshot $rw
    Record-Result -Phase 'P4' -Name 'ui.disable=true rw ACL still cleaned up' -Pass ($aclRwBefore -eq $aclRwAfterUi)
    Record-Result -Phase 'P4' -Name 'ui.disable=true no orphan state files' -Pass (@(Get-NewStateFiles).Count -eq 0)

    # ---------------------------------------------------------------------
    # Sandbox property test: ping requires raw ICMP sockets, which
    # AppContainer denies by default (no `internetClient` capability is
    # not the issue — even with it, raw sockets need elevated
    # privileges). The child should exit non-zero almost immediately.
    # If ping ever succeeds here we have a sandbox escape.
    # ---------------------------------------------------------------------
    $cfgPing = New-Config -Name 't3-ping-blocked' `
        -CommandLine (New-ProbeCommand -Body 'ping.exe -n 1 -w 1000 127.0.0.1') `
        -ReadWrite @($rw) -TimeoutMs 10000
    $logPing = Join-Path $ScratchRoot 'logs\t3-ping-blocked.log'

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $rPing = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgPing -LogPath $logPing -TimeoutSec 30
    $stopwatch.Stop()
    $logContentPing = Read-Log $logPing

    $combinedPing = "$($rPing.Stdout)`n$($rPing.Stderr)"
    $aclRwAfterPing = Get-Acl-Snapshot $rw
    # A launch failure would otherwise satisfy the exit code, the timing and
    # the error regex without ping.exe ever being invoked.
    $pingRan = Test-WorkloadRan $rPing

    Record-Result -Phase 'P4' -Name 'sandbox blocks ping: workload actually started' -Pass $pingRan -Detail "marker seen=$pingRan"
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping (child exit != 0)' -Pass ($pingRan -and $rPing.ExitCode -ne 0) -Detail "ran=$pingRan; exit=$($rPing.ExitCode)"
    # A successful ping takes ~1.5s; raw-socket creation failure exits in
    # milliseconds. 5s is a generous bound that still detects "ping ran".
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping (failed fast, < 5s)' -Pass ($pingRan -and $stopwatch.Elapsed.TotalSeconds -lt 5) -Detail ("ran=$pingRan; elapsed={0:N2}s" -f $stopwatch.Elapsed.TotalSeconds)
    # Best-effort: confirm the failure was access/socket related rather than
    # ENOENT. Localized messages vary, so this is informational.
    $accessSignal = $combinedPing -match '(?im)access\s*is\s*denied|access\s*denied|socket|10013|ICMP|general\s*failure|unable\s*to\s*contact'
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping (failure looks socket-related)' -Pass ([bool]$accessSignal) -Detail 'best-effort string match'
    Record-Result -Phase 'P4' -Name "sandbox blocks ping: selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContentPing) -Detail "expected=$($Script:ExpectedTier)"
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping: rw ACL still cleaned up' -Pass ($aclRwBefore -eq $aclRwAfterPing)
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping: no orphan state files' -Pass (@(Get-NewStateFiles).Count -eq 0)

    # ---------------------------------------------------------------------
    # Access matrix: the existing sub-tests verify ACL apply/restore and
    # that the rw grant *functionally* works (write+read inside rw). They
    # do NOT verify that:
    #   - ro is read-only (RO success on read, FAIL on write)
    #   - denied is actually denied (FAIL on both)
    #   - paths NOT in any policy are denied too (control row — proves
    #     the AppContainer is sandboxed at all, not just that explicit
    #     ACEs work)
    # We pre-stage a `readme.txt` in each path, run a child that
    # attempts read+write on each, and parse the resulting matrix.
    # ---------------------------------------------------------------------
    $control = Join-Path $ScratchRoot 'control'
    # Pre-stage host-created files for the negative-side rows. We deliberately
    # do NOT pre-create one in $rw — the rw row uses a child-created marker
    # so it tests the grant at face value rather than depending on Windows'
    # inheritance propagation to pre-existing children.
    'ro-content'      | Out-File -LiteralPath (Join-Path $ro      'readme.txt') -Encoding ascii -Force
    'denied-content'  | Out-File -LiteralPath (Join-Path $denied  'readme.txt') -Encoding ascii -Force
    'control-content' | Out-File -LiteralPath (Join-Path $control 'readme.txt') -Encoding ascii -Force

    $aclControlBefore = Get-Acl-Snapshot $control

    # No `>nul` redirects: AppContainer does not reliably grant access to the
    # NUL device, and every clause of an earlier matrix attempt using it
    # failed. Without them `type` dumps to stdout and errors go to stderr;
    # both are fine, since the parser only consumes ^(TAG)=(PASS|FAIL)$.
    function Probe-Read  { param($tag, $path, $name) "(type ""$path\$name"") && echo $tag=PASS || echo $tag=FAIL" }
    function Probe-Write { param($tag, $path, $name) "(echo data > ""$path\$name"") && echo $tag=PASS || echo $tag=FAIL" }
    $clauses = @(
        # RW: child writes a fresh marker, then reads it back. This tests
        # the grant directly without relying on inheritance propagation.
        Probe-Write 'RW_WRITE'       $rw      'rw_marker.tmp'
        Probe-Read  'RW_READ'        $rw      'rw_marker.tmp'
        # RO: child reads the host-pre-created readme (tests inheritance
        # propagation of the ALLOW ACE to existing children).
        Probe-Read  'RO_READ'        $ro      'readme.txt'
        Probe-Write 'RO_WRITE'       $ro      'rw_marker.tmp'
        # Control: a path in NO policy must fail both ways (proves the
        # AppContainer is sandboxed at all, not just that explicit ACEs work).
        Probe-Read  'CONTROL_READ'   $control 'readme.txt'
        Probe-Write 'CONTROL_WRITE'  $control 'control_attempt.tmp'
    )
    # Denied rows only when the tier can enforce deniedPaths (see capability).
    if ($Script:Caps.SupportsDeniedPaths) {
        $clauses += Probe-Read  'DENIED_READ'  $denied 'readme.txt'
        $clauses += Probe-Write 'DENIED_WRITE' $denied 'denied_attempt.tmp'
    }
    $matrixCmd = 'cmd /c ' + ($clauses -join ' & ')

    $matrixDenied = @()
    if ($Script:Caps.SupportsDeniedPaths) { $matrixDenied = @($denied) }
    $cfgMatrix = New-Config -Name 't3-access-matrix' -CommandLine $matrixCmd -ReadWrite @($rw) -ReadOnly @($ro) -Denied $matrixDenied
    $logMatrix = Join-Path $ScratchRoot 'logs\t3-access-matrix.log'
    $rMatrix = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgMatrix -LogPath $logMatrix
    $logContentMatrix = Read-Log $logMatrix

    # Parse the matrix from stdout into a hashtable.
    $matrix = @{}
    foreach ($line in ($rMatrix.Stdout -split "`r?`n")) {
        if ($line -match '^(?<k>RW_READ|RW_WRITE|RO_READ|RO_WRITE|DENIED_READ|DENIED_WRITE|CONTROL_READ|CONTROL_WRITE)=(?<v>PASS|FAIL)\s*$') {
            $matrix[$matches['k']] = $matches['v']
        }
    }
    # Surface the raw matrix for diagnostic value when something fails.
    $matrixSummary = ($matrix.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '

    function Assert-Matrix {
        param([string]$Key, [string]$Want, [string]$Reason)
        $got = if ($matrix.ContainsKey($Key)) { $matrix[$Key] } else { '<missing>' }
        $wantV = Format-Verdict $Want 'allowed' 'denied'
        $gotV  = Format-Verdict $got  'allowed' 'denied'
        $fullV = Format-VerdictSummary $matrixSummary 'allowed' 'denied'
        Record-Result -Phase 'P4' -Name "matrix $Key ($Reason)" -Pass ($got -eq $Want) -Detail "expected=$wantV; got=$gotV; full=$fullV"
    }

    Assert-Matrix 'RW_WRITE'       'PASS' 'rw grant must allow child to create files'
    Assert-Matrix 'RW_READ'        'PASS' 'rw grant must allow child to read its own file'
    Assert-Matrix 'RO_READ'        'PASS' 'ro grant must allow reads (tests ACE inheritance to existing children)'
    Assert-Matrix 'RO_WRITE'       'FAIL' 'ro grant must NOT allow writes'
    if ($Script:Caps.SupportsDeniedPaths) {
        Assert-Matrix 'DENIED_READ'    'FAIL' 'denied path must block reads'
        Assert-Matrix 'DENIED_WRITE'   'FAIL' 'denied path must block writes'
    } else {
        Record-Result -Phase 'P4' -Name 'matrix DENIED_READ/DENIED_WRITE' -Status 'skip' -Detail "deniedPaths not supported on tier=$($Script:ExpectedTier)"
    }
    Assert-Matrix 'CONTROL_READ'   'FAIL' 'control path (no policy) must be sandboxed'
    Assert-Matrix 'CONTROL_WRITE'  'FAIL' 'control path (no policy) must be sandboxed'

    # All four ACLs must round-trip clean even though RO_WRITE / DENIED_*
    # / CONTROL_* failures left no host-side residue (the failures are
    # AppContainer-side, not host-side).
    Record-Result -Phase 'P4' -Name 'matrix: rw ACL restored' -Pass ($aclRwBefore -eq (Get-Acl-Snapshot $rw))
    Record-Result -Phase 'P4' -Name 'matrix: ro ACL restored' -Pass ($aclRoBefore -eq (Get-Acl-Snapshot $ro))
    Record-Result -Phase 'P4' -Name 'matrix: denied ACL restored' -Pass ($aclDeniedBefore -eq (Get-Acl-Snapshot $denied))
    Record-Result -Phase 'P4' -Name 'matrix: control ACL untouched' -Pass ($aclControlBefore -eq (Get-Acl-Snapshot $control))
    Record-Result -Phase 'P4' -Name 'matrix: no orphan state files' -Pass (@(Get-NewStateFiles).Count -eq 0)
}

Invoke-WpcPhase -Key 'T3Forced' -Body { Phase-T3Forced }
Complete-WpcChild

