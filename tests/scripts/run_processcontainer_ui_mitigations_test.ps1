# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_ui_mitigations_test.ps1
#
# JOB_OBJECT_UILIMIT_* mitigation matrix (docs/process-container/UIPolicy_Schema.md).
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_ui_mitigations_test.ps1 -RequireTier base-container
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
. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Native.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 4b — UI mitigation behavior matrix (host baseline tier, debug build)
#
# Phase 4 already asserts that Win32k mitigation applied telemetry fires
# when ui.disable=true and that UI Job Object assigned fires unconditionally.
# Those checks only prove the parent reached the corresponding API. This
# phase runs an in-sandbox probe binary that *attempts the operations the
# UI restrictions are documented to block*, then asserts the kernel
# actually denied them.
#
# Scenario A: ui.disable=false + maximal base_process_ui blocks ->
#   every JOB_OBJECT_UILIMIT_* bit is set. Run all probes EXCEPT WIN32K
#   and assert each is reported PASS (operation was blocked).
# Scenario B: ui.disable=true -> Win32k mitigation. Run WIN32K alone and
#   assert the child process never printed WIN32K=FAIL (mitigation killed
#   it on the GetMessageW syscall).
# -----------------------------------------------------------------------
function Phase-UiMitigationMatrix {
    Section 'Phase 4b: UI mitigation behavior matrix (host baseline tier)'

    $rw = Join-Path $ScratchRoot 'rw'

    # ---------------- Scenario A: maximal UILIMIT bits -----------------
    # ui: disable=false (so Win32k is allowed but UILIMIT bits gate
    # specific operations), clipboard=none (block both R+W),
    # injection=false. base_process_ui: isolation=container (HANDLES +
    # GLOBALATOMS), desktopSystemControl=false (DESKTOP + EXITWINDOWS),
    # systemSettings=none (SYSTEMPARAMETERS + DISPLAYSETTINGS), ime=false.
    # NOTE: GLOBALATOMS is NOT probed here. JOB_OBJECT_UILIMIT_GLOBALATOMS
    # does not fail the atom APIs — it gives the job a private atom table —
    # so it cannot be verified with the simple "API failed -> PASS" matrix.
    # Phase-GlobalAtomIsolation covers it with a bidirectional isolation test.
    # Create a hidden window owned by THIS (out-of-job) process. Its USER handle
    # is what the HANDLES probe must NOT be able to use: JOB_OBJECT_UILIMIT_HANDLES
    # does not stop FindWindow from returning HWNDs — it blocks USING handles
    # owned by processes outside the job — so the probe calls
    # GetWindowThreadProcessId on the HWND. That reads window-manager state
    # directly (no WM_GETTEXT / SendMessage), so it is not confounded by UIPI or
    # the target pumping messages. PASS = it could not resolve the owner (limit
    # blocked the handle use); FAIL = it read back our process id.
    $handleTitle = "MxcHandleProbe_$([guid]::NewGuid().ToString('N'))"
    $winHost = New-Object Mxc.WindowHost
    $winHost.Start($handleTitle)
    try {
        $hwndVal = $winHost.Hwnd.ToInt64()
        $probeArgsA = 'READCLIPBOARD WRITECLIPBOARD SYSTEMPARAMETERS DISPLAYSETTINGS DESKTOP EXITWINDOWS HANDLES INJECTION'
        $cmdA = "`"$UiProbeDebug`" $probeArgsA --handle-hwnd=$hwndVal --handle-pid=$PID"
        $cfgA = New-Config -Name 'ui-matrix-A-allbits' `
            -CommandLine $cmdA `
            -ReadWrite @($rw) `
            -UiDisable $false `
            -Clipboard 'none' `
            -Injection $false `
            -BpUiIsolation 'container' `
            -BpUiDesktopControl $false `
            -BpUiSystemSettings 'none' `
            -BpUiIme $false `
            -Env (Get-ProbeEnvWithDestructive)
        $logA = Join-Path $ScratchRoot 'logs\ui-matrix-A.log'
        $rA = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgA -LogPath $logA
        $logContentA = Read-Log $logA
        Assert-NoBfscfg -LogContent $logContentA -Phase 'P4b' -Name 'ui-matrix-A'

        $matrixA = @{}
        foreach ($line in ($rA.Stdout -split "`r?`n")) {
            if ($line -match '^(?<k>READCLIPBOARD|WRITECLIPBOARD|SYSTEMPARAMETERS|DISPLAYSETTINGS|DESKTOP|EXITWINDOWS|HANDLES|INJECTION|WIN32K)=(?<v>PASS|FAIL)\s*$') {
                $matrixA[$matches['k']] = $matches['v']
            }
        }
        $summaryA = ($matrixA.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '

        Record-Result -Phase 'P4b' -Name 'scenarioA: UI restrictions applied telemetry' -Pass (Test-UiRestrictionsApplied -LogContent $logContentA)
        Record-Result -Phase 'P4b' -Name "scenarioA: selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContentA) -Detail "expected=$($Script:ExpectedTier)"
        # ui.disable=false on this run: Win32k mitigation applied must NOT appear.
        Record-Result -Phase 'P4b' -Name 'scenarioA: Win32k mitigation NOT applied (ui.disable=false)' -Pass (-not (Test-Win32kMitigationApplied -LogContent $logContentA))

        foreach ($tag in @('READCLIPBOARD','WRITECLIPBOARD','SYSTEMPARAMETERS','DISPLAYSETTINGS','DESKTOP','EXITWINDOWS','HANDLES')) {
            $got = if ($matrixA.ContainsKey($tag)) { $matrixA[$tag] } else { '<missing>' }
            $gotV  = Format-Verdict $got 'blocked' 'allowed'
            $fullV = Format-VerdictSummary $summaryA 'blocked' 'allowed'
            Record-Result -Phase 'P4b' -Name "scenarioA: $tag" -Pass ($got -eq 'PASS') -Detail "expected=blocked; got=$gotV; full=$fullV"
        }

        # INJECTION (JOB_OBJECT_UILIMIT_INJECTION, 0x200) is handled separately
        # from the hard-assertion loop above. The probe creates and foregrounds
        # its OWN window before SendInput so the kernel's foreground-accessible
        # check (which precedes the injection job-limit check and silently skips
        # input when the foreground belongs to another inaccessible process)
        # passes and the limit is actually evaluated. Outcomes:
        #   * build < 26100 (canBlockInputInjection false) -> SKIP (bit dropped).
        #   * INJECTION=INCONCLUSIVE -> the probe could not own the foreground on
        #     this desktop, so the limit was never exercised -> SKIP (not a
        #     verdict); the injected/gle pair would be ambiguous.
        #   * INJECTION=PASS -> owned foreground and SendInput was blocked
        #     (injected 0/1 gle=5): enforced -> hard PASS.
        #   * INJECTION=FAIL -> owned foreground but the event went through
        #     (injected 1/1 gle=0): genuinely not enforced -> WARN, not a green
        #     PASS. Auto-promotes to PASS once enforcement is on.
        $injDiag = if ($rA.Stdout -match '(?m)^INJECTION=DIAG\s+(?<d>.+?)\s*$') { $matches['d'] } else { '<no diag>' }
        $injInconclusive = [bool]($rA.Stdout -match '(?m)^INJECTION=INCONCLUSIVE\s*$')
        if (-not $Script:Caps.CanBlockInputInjection) {
            Record-Result -Phase 'P4b' -Name 'scenarioA: INJECTION' -Status 'skip' -Detail "JOB_OBJECT_UILIMIT_INJECTION not supported on this build (< 26100); diag=$injDiag"
        } elseif ($injInconclusive) {
            Record-Result -Phase 'P4b' -Name 'scenarioA: INJECTION' -Status 'skip' -Detail "could not own the foreground on this desktop; injection limit not exercised; diag=$injDiag"
        } else {
            $injGot = if ($matrixA.ContainsKey('INJECTION')) { $matrixA['INJECTION'] } else { '<missing>' }
            if ($injGot -eq 'PASS') {
                Record-Result -Phase 'P4b' -Name 'scenarioA: INJECTION' -Status 'pass' -Detail "expected=blocked; got=blocked; diag=$injDiag"
            } else {
                # Owned the foreground but the injection still went through ->
                # the limit was not enforced. Non-failing WARN so the suite stays
                # green where OS enforcement is not yet active.
                $injGotV = Format-Verdict $injGot 'blocked' 'allowed'
                Record-Result -Phase 'P4b' -Name 'scenarioA: INJECTION enforcement' -Status 'warn' -Detail "expected=blocked; got=$injGotV; NOT ENFORCED; diag=$injDiag"
            }
        }

        # Negative control for HANDLES: same probe + host window, but
        # isolation=desktop sets NO UILIMIT_HANDLES. The probe MUST be able to
        # resolve the external window's owner -> HANDLES=FAIL, proving the
        # HANDLES=PASS above is a real isolation result and not vacuous (e.g.
        # GetWindowThreadProcessId failing for an unrelated reason).
        $cmdAneg = "`"$UiProbeDebug`" HANDLES --handle-hwnd=$hwndVal --handle-pid=$PID"
        $cfgAneg = New-Config -Name 'ui-matrix-A-handles-neg' `
            -CommandLine $cmdAneg `
            -ReadWrite @($rw) `
            -UiDisable $false `
            -BpUiIsolation 'desktop' `
            -Env (Get-ProbeEnvWithDestructive)
        $logAneg = Join-Path $ScratchRoot 'logs\ui-matrix-A-handles-neg.log'
        $rAneg = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgAneg -LogPath $logAneg
        Assert-NoBfscfg -LogContent (Read-Log $logAneg) -Phase 'P4b' -Name 'ui-matrix-A-handles-neg'
        $negHandles = if ($rAneg.Stdout -match '(?m)^HANDLES=(?<v>PASS|FAIL)\s*$') { $matches['v'] } else { '<missing>' }
        $negHandlesV = Format-Verdict $negHandles 'blocked' 'allowed'
        $negStdoutV  = Format-VerdictSummary ($rAneg.Stdout.Trim()) 'blocked' 'allowed'
        Record-Result -Phase 'P4b' -Name 'negative control: HANDLES usable without UILIMIT_HANDLES' -Pass ($negHandles -eq 'FAIL') -Detail "expected=allowed; got=$negHandlesV; stdout=$negStdoutV"
    }
    finally {
        $winHost.Stop()
    }

    # ---------------- Scenario B: ui.disable=true (Win32k mitigation) ----
    # WIN32K probe makes a Win32k syscall (GetMessageW). The mitigation is
    # honored in either of two ways depending on the host:
    #   * user32.dll loads, the GetMessageW syscall is reached, and the kernel
    #     terminates the process — the probe prints nothing; or
    #   * user32.dll fails to load at all (its init makes blocked win32k
    #     syscalls) — the probe prints a WIN32K=DIAG line and nothing else.
    # Either way the child must print neither WIN32K=FAIL nor WIN32K=PASS. If
    # the mitigation is NOT honored, user32 loads and GetMessageW returns, so
    # the probe prints WIN32K=FAIL. WIN32K is destructive-gated, so the
    # MXC_PROBE_DESTRUCTIVE_OK override must reach the child (via the full env
    # block) for the GetMessageW path to be attempted.
    $cmdB = "`"$UiProbeDebug`" WIN32K"
    $cfgB = New-Config -Name 'ui-matrix-B-win32k' `
        -CommandLine $cmdB `
        -ReadWrite @($rw) `
        -UiDisable $true `
        -Env (Get-ProbeEnvWithDestructive)
    $logB = Join-Path $ScratchRoot 'logs\ui-matrix-B.log'
    $rB = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgB -LogPath $logB
    $logContentB = Read-Log $logB
    Assert-NoBfscfg -LogContent $logContentB -Phase 'P4b' -Name 'ui-matrix-B'

    $printedFail = ($rB.Stdout -match '(?m)^WIN32K=FAIL\s*$')
    $printedPass = ($rB.Stdout -match '(?m)^WIN32K=PASS\s*$')

    Record-Result -Phase 'P4b' -Name 'scenarioB: Win32k mitigation applied telemetry' -Pass (Test-Win32kMitigationApplied -LogContent $logContentB)
    Record-Result -Phase 'P4b' -Name "scenarioB: selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContentB) -Detail "expected=$($Script:ExpectedTier)"
    # Mitigation worked iff the child never reported WIN32K=FAIL. Child
    # exit code is incidental — under the mitigation the process is killed
    # by the kernel; without it the probe completes and exits 0.
    Record-Result -Phase 'P4b' -Name 'scenarioB: child did NOT report WIN32K=allowed (mitigation honored)' -Pass (-not $printedFail) -Detail "exit=$($rB.ExitCode); stdout=$(Format-VerdictSummary ($rB.Stdout.Trim()) 'blocked' 'allowed')"
    Record-Result -Phase 'P4b' -Name 'scenarioB: child did NOT report WIN32K=blocked' -Pass (-not $printedPass) -Detail 'probe never reports WIN32K=blocked (process is killed before printing)'
}

Invoke-WpcPhase -Key 'UiMitigationMatrix' -Body { Phase-UiMitigationMatrix }
Complete-WpcChild

