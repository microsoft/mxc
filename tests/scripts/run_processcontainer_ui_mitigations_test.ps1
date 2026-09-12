# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_ui_mitigations_test.ps1
#
# JOB_OBJECT_UILIMIT_* mitigation matrix (docs/process-container/UIPolicy_Schema.md).
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_ui_mitigations_test.ps1 -RequireTier base-container
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
. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Native.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 4b — UI mitigation behavior matrix (host baseline tier, debug build)
#
# Phase 4 asserts only that the parent reached the corresponding API. This
# phase runs an in-sandbox probe that attempts the operations the UI
# restrictions are documented to block, then asserts the kernel denied them.
#
# Scenario A: ui.disable=false + maximal base_process_ui blocks -> every
#   JOB_OBJECT_UILIMIT_* bit set. Every probe except WIN32K must report PASS.
# Scenario B: ui.disable=true -> Win32k mitigation. WIN32K alone; the child
#   must never print WIN32K=FAIL.
# -----------------------------------------------------------------------
function Phase-UiMitigationMatrix {
    Section 'Phase 4b: UI mitigation behavior matrix (host baseline tier)'

    $rw = Join-Path $ScratchRoot 'rw'

    # ---------------- Scenario A: maximal UILIMIT bits -----------------
    # GLOBALATOMS is not probed here: the limit gives the job a private atom
    # table rather than failing the atom APIs, so it cannot be verified with
    # the "API failed -> PASS" matrix. Phase-GlobalAtomIsolation covers it.
    #
    # Create a hidden window owned by THIS out-of-job process. HANDLES does not
    # stop FindWindow from returning HWNDs — it blocks USING handles owned by
    # processes outside the job — so the probe calls GetWindowThreadProcessId,
    # which reads window-manager state directly and is not confounded by UIPI.
    # PASS = could not resolve the owner; FAIL = read back our process id.
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

        $matrixA = @{}
        foreach ($line in ($rA.Stdout -split "`r?`n")) {
            if ($line -match '^(?<k>READCLIPBOARD|WRITECLIPBOARD|SYSTEMPARAMETERS|DISPLAYSETTINGS|DESKTOP|EXITWINDOWS|HANDLES|INJECTION|WIN32K)=(?<v>PASS|FAIL)\s*$') {
                $matrixA[$matches['k']] = $matches['v']
            }
        }
        $summaryA = ($matrixA.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '

        Record-UiTelemetryResult -Phase 'P4b' -Name 'scenarioA: UI restrictions applied telemetry' -LogContent $logContentA -Check 'ui-restrictions'
        Record-Result -Phase 'P4b' -Name "scenarioA: selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContentA) -Detail "expected=$($Script:ExpectedTier)"
        # ui.disable=false on this run: Win32k mitigation applied must NOT appear.
        Record-UiTelemetryResult -Phase 'P4b' -Name 'scenarioA: Win32k mitigation NOT applied (ui.disable=false)' -LogContent $logContentA -Check 'win32k' -Expected $false

        foreach ($tag in @('READCLIPBOARD','WRITECLIPBOARD','SYSTEMPARAMETERS','DISPLAYSETTINGS','DESKTOP','EXITWINDOWS','HANDLES')) {
            $got = if ($matrixA.ContainsKey($tag)) { $matrixA[$tag] } else { '<missing>' }
            $gotV  = Format-Verdict $got 'blocked' 'allowed'
            $fullV = Format-VerdictSummary $summaryA 'blocked' 'allowed'
            Record-Result -Phase 'P4b' -Name "scenarioA: $tag" -Pass ($got -eq 'PASS') -Detail "expected=blocked; got=$gotV; full=$fullV"
        }

        # INJECTION is handled outside the hard-assertion loop. The probe
        # foregrounds its own window first so the kernel's foreground check
        # (which precedes the injection limit) passes and the limit is really
        # evaluated. SKIP on build < 26100 (bit dropped) or on INCONCLUSIVE
        # (never owned the foreground); PASS when SendInput was blocked; WARN
        # rather than green when it went through, auto-promoting once enforced.
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
    $cmdB = New-ProbeCommand -Body "`"$UiProbeDebug`" WIN32K"
    $cfgB = New-Config -Name 'ui-matrix-B-win32k' `
        -CommandLine $cmdB `
        -ReadWrite @($rw) `
        -UiDisable $true `
        -Env (Get-ProbeEnvWithDestructive)
    $logB = Join-Path $ScratchRoot 'logs\ui-matrix-B.log'
    $rB = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgB -LogPath $logB
    $logContentB = Read-Log $logB

    $printedFail = ($rB.Stdout -match '(?m)^WIN32K=FAIL\s*$')
    $printedPass = ($rB.Stdout -match '(?m)^WIN32K=PASS\s*$')
    # Both assertions below are satisfied by empty stdout, so a launch failure
    # would be indistinguishable from the kernel killing the child. The marker
    # is printed before the probe is reached and makes the difference visible.
    $ranB = Test-WorkloadRan $rB

    Record-UiTelemetryResult -Phase 'P4b' -Name 'scenarioB: Win32k mitigation applied telemetry' -LogContent $logContentB -Check 'win32k'
    Record-Result -Phase 'P4b' -Name "scenarioB: selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContentB) -Detail "expected=$($Script:ExpectedTier)"
    Record-Result -Phase 'P4b' -Name 'scenarioB: workload actually started' -Pass $ranB -Detail "marker seen=$ranB; without it, silence is not evidence of the mitigation"
    Record-Result -Phase 'P4b' -Name 'scenarioB: child did NOT report WIN32K=allowed (mitigation honored)' -Pass ($ranB -and -not $printedFail) -Detail "ran=$ranB; exit=$($rB.ExitCode); stdout=$(Format-VerdictSummary ($rB.Stdout.Trim()) 'blocked' 'allowed')"
    Record-Result -Phase 'P4b' -Name 'scenarioB: child did NOT report WIN32K=blocked' -Pass ($ranB -and -not $printedPass) -Detail 'probe never reports WIN32K=blocked (process is killed before printing)'
}

Invoke-WpcPhase -Key 'UiMitigationMatrix' -Body { Phase-UiMitigationMatrix }
Complete-WpcChild

