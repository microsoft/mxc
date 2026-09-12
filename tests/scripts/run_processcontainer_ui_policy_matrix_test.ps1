# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_ui_policy_matrix_test.ps1
#
# Full UI policy resolution matrix.
#
# Phase 4b proves the MAXIMAL lockdown works: every knob at its most
# restrictive setting blocks every probe. That is one point in the space.
# This area walks the rest of it -- every documented value of every UI knob,
# including the values that are supposed to ALLOW an operation.
#
# The expectations come from `resolve_ui_restrictions`
# (src/core/wxc_common/src/ui_policy.rs), whose mapping is "the named thing is
# the thing you keep": clipboard=read allows reading and blocks writing;
# systemSettings=display allows display changes and blocks parameter changes.
# Each policy value maps onto a probe tag that is expected to come back
# blocked or allowed, so an inverted or dropped mapping fails here.
#
# Allow-direction coverage matters more than it looks. A restriction flag
# wired to the wrong bit, or set unconditionally regardless of policy, still
# passes every blocked-direction assertion in Phase 4b. Only an allow case
# catches it.
#
# SAFETY: EXITWINDOWS is never probed in a case where it is expected to be
# allowed. The probe calls ExitWindowsEx(EWX_LOGOFF|EWX_FORCEIFHUNG); when the
# UI limit is absent that is a real logoff of the operator's session, not a
# refused call. Those cases record an explicit skip rather than silently
# dropping the tag, so the gap stays visible in the results.
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_ui_policy_matrix_test.ps1 -RequireTier base-container
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
    # the child scripts do not each re-run --probe. Absent (a standalone run)
    # means probe the host here.
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


# Run one UI-policy case and assert each expected tag verdict.
#
# $Case.Expect maps a probe tag to 'blocked' or 'allowed'. Only the tags named
# there are handed to the probe, so a case never runs an operation it has no
# expectation for -- which is what keeps EXITWINDOWS out of the allow cases.
# $HwndVal/$HostPid are the external window used by the HANDLES probe; they are
# harmless for cases that do not ask for HANDLES.
function Invoke-UiPolicyCase {
    param(
        [Parameter(Mandatory)][hashtable]$Case,
        [Parameter(Mandatory)][string]$Phase,
        [long]$HwndVal = 0,
        [int]$HostPid = 0
    )

    $tags = @($Case.Expect.Keys | Sort-Object)
    $probeArgs = $tags -join ' '
    $cmd = "`"$UiProbeDebug`" $probeArgs"
    if ($tags -contains 'HANDLES') {
        $cmd += " --handle-hwnd=$HwndVal --handle-pid=$HostPid"
    }

    $cfgArgs = @{
        Name        = "ui-policy-$($Case.Name)"
        CommandLine = $cmd
        ReadWrite   = @((Join-Path $ScratchRoot 'rw'))
        Env         = (Get-ProbeEnvWithDestructive)
    }
    foreach ($k in 'UiDisable', 'Clipboard', 'Injection', 'BpUiIsolation',
                   'BpUiDesktopControl', 'BpUiSystemSettings', 'BpUiIme') {
        if ($Case.ContainsKey($k)) { $cfgArgs[$k] = $Case[$k] }
    }

    $cfg = New-Config @cfgArgs
    $log = Join-Path $ScratchRoot "logs\ui-policy-$($Case.Name).log"
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log
    Assert-NoBfscfg -LogContent (Read-Log $log) -Phase $Phase -Name "ui-policy-$($Case.Name)"

    $matrix = @{}
    foreach ($line in ($r.Stdout -split "`r?`n")) {
        if ($line -match '^(?<k>[A-Z][A-Z0-9_]*)=(?<v>PASS|FAIL|INCONCLUSIVE)\s*$') {
            $matrix[$matches['k']] = $matches['v']
        }
    }
    $summary = ($matrix.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
    $summaryV = Format-VerdictSummary $summary 'blocked' 'allowed'

    foreach ($tag in $tags) {
        $want = $Case.Expect[$tag]
        $got  = if ($matrix.ContainsKey($tag)) { $matrix[$tag] } else { '<missing>' }
        $gotV = Format-Verdict $got 'blocked' 'allowed'
        $name = "$($Case.Label) -> $tag=$want"

        # INJECTION is the one tag whose verdict is not a clean two-state.
        # Mirror Phase 4b: unsupported build or a lost foreground race is a
        # skip, and a genuine non-enforcement is a warn rather than a red fail,
        # so the suite stays green where the OS does not enforce the bit yet.
        if ($tag -eq 'INJECTION') {
            $diag = if ($r.Stdout -match '(?m)^INJECTION=DIAG\s+(?<d>.+?)\s*$') { $matches['d'] } else { '<no diag>' }
            if (-not $Script:Caps.CanBlockInputInjection) {
                Record-Result -Phase $Phase -Name $name -Status 'skip' -Detail "JOB_OBJECT_UILIMIT_INJECTION not supported on this build (< 26100); diag=$diag"
                continue
            }
            if ($got -eq 'INCONCLUSIVE') {
                Record-Result -Phase $Phase -Name $name -Status 'skip' -Detail "could not own the foreground; injection limit not exercised; diag=$diag"
                continue
            }
            if ($want -eq 'blocked' -and $got -ne 'PASS') {
                Record-Result -Phase $Phase -Name $name -Status 'warn' -Detail "expected=blocked; got=$gotV; NOT ENFORCED; diag=$diag"
                continue
            }
        }

        $expectToken = if ($want -eq 'blocked') { 'PASS' } else { 'FAIL' }
        Record-Result -Phase $Phase -Name $name -Pass ($got -eq $expectToken) `
            -Detail "expected=$want; got=$gotV; full=$summaryV"
    }
}


# -----------------------------------------------------------------------
# Phase 4e -- UI policy resolution matrix
#
# One case per documented value of each knob. Cases assert only the tags the
# knob actually governs, so a failure names the exact mapping that broke.
# -----------------------------------------------------------------------
function Phase-UiPolicyMatrix {
    Section 'Phase 4e: UI policy resolution matrix (every documented value)'

    # The HANDLES probe needs a USER handle owned by a process OUTSIDE the
    # job. Created once and shared by every case; harmless for the rest.
    $handleTitle = "MxcUiPolicyProbe_$([guid]::NewGuid().ToString('N'))"
    $winHost = New-Object Mxc.WindowHost
    $winHost.Start($handleTitle)
    try {
        $hwndVal = $winHost.Hwnd.ToInt64()

        # --- ui.clipboard: 4 documented values ---------------------------
        # "the named thing is the thing you keep": read => reading survives.
        $cases = @(
            @{ Name = 'clip-all';   Label = 'ui.clipboard=all';   Clipboard = 'all'
               Expect = @{ READCLIPBOARD = 'allowed'; WRITECLIPBOARD = 'allowed' } }
            @{ Name = 'clip-read';  Label = 'ui.clipboard=read';  Clipboard = 'read'
               Expect = @{ READCLIPBOARD = 'allowed'; WRITECLIPBOARD = 'blocked' } }
            @{ Name = 'clip-write'; Label = 'ui.clipboard=write'; Clipboard = 'write'
               Expect = @{ READCLIPBOARD = 'blocked'; WRITECLIPBOARD = 'allowed' } }
            @{ Name = 'clip-none';  Label = 'ui.clipboard=none';  Clipboard = 'none'
               Expect = @{ READCLIPBOARD = 'blocked'; WRITECLIPBOARD = 'blocked' } }

            # --- ui.injection: both values -------------------------------
            @{ Name = 'inject-on';  Label = 'ui.injection=true';  Injection = $true
               Expect = @{ INJECTION = 'allowed' } }
            @{ Name = 'inject-off'; Label = 'ui.injection=false'; Injection = $false
               Expect = @{ INJECTION = 'blocked' } }

            # --- processContainer.ui.isolation: 4 documented values -------
            # Only `handles` and `container` set UILIMIT_HANDLES. `atoms`
            # governs the global atom namespace, which this probe cannot see
            # (Phase 4c covers it bidirectionally), so under `atoms` the
            # HANDLES probe must still succeed. That asymmetry is the whole
            # point of these four cases: it separates the two flags.
            @{ Name = 'iso-desktop';   Label = 'pcUi.isolation=desktop';   BpUiIsolation = 'desktop'
               Expect = @{ HANDLES = 'allowed' } }
            @{ Name = 'iso-handles';   Label = 'pcUi.isolation=handles';   BpUiIsolation = 'handles'
               Expect = @{ HANDLES = 'blocked' } }
            @{ Name = 'iso-atoms';     Label = 'pcUi.isolation=atoms';     BpUiIsolation = 'atoms'
               Expect = @{ HANDLES = 'allowed' } }
            @{ Name = 'iso-container'; Label = 'pcUi.isolation=container'; BpUiIsolation = 'container'
               Expect = @{ HANDLES = 'blocked' } }
            # isolation is a free-form string in the wire model, so an
            # unrecognized value is reachable and is documented to fall back
            # to full isolation rather than to no isolation.
            @{ Name = 'iso-bogus';     Label = 'pcUi.isolation=<unrecognized> defaults to full isolation'
               BpUiIsolation = 'not-a-real-isolation-level'
               Expect = @{ HANDLES = 'blocked' } }

            # --- processContainer.ui.systemSettings: 4 documented values --
            @{ Name = 'sys-all';   Label = 'pcUi.systemSettings=all';   BpUiSystemSettings = 'all'
               Expect = @{ SYSTEMPARAMETERS = 'allowed'; DISPLAYSETTINGS = 'allowed' } }
            @{ Name = 'sys-param'; Label = 'pcUi.systemSettings=parameters'; BpUiSystemSettings = 'parameters'
               Expect = @{ SYSTEMPARAMETERS = 'allowed'; DISPLAYSETTINGS = 'blocked' } }
            @{ Name = 'sys-disp';  Label = 'pcUi.systemSettings=display'; BpUiSystemSettings = 'display'
               Expect = @{ SYSTEMPARAMETERS = 'blocked'; DISPLAYSETTINGS = 'allowed' } }
            @{ Name = 'sys-none';  Label = 'pcUi.systemSettings=none';  BpUiSystemSettings = 'none'
               Expect = @{ SYSTEMPARAMETERS = 'blocked'; DISPLAYSETTINGS = 'blocked' } }
            @{ Name = 'sys-bogus'; Label = 'pcUi.systemSettings=<unrecognized> defaults to block all'
               BpUiSystemSettings = 'not-a-real-settings-level'
               Expect = @{ SYSTEMPARAMETERS = 'blocked'; DISPLAYSETTINGS = 'blocked' } }

            # --- processContainer.ui.desktopSystemControl -----------------
            # true unblocks BOTH desktop switching and logoff. Only DESKTOP is
            # probed: CreateDesktopW is reversible, ExitWindowsEx is not.
            @{ Name = 'deskctl-on';  Label = 'pcUi.desktopSystemControl=true'; BpUiDesktopControl = $true
               Expect = @{ DESKTOP = 'allowed' } }
            @{ Name = 'deskctl-off'; Label = 'pcUi.desktopSystemControl=false'; BpUiDesktopControl = $false
               Expect = @{ DESKTOP = 'blocked'; EXITWINDOWS = 'blocked' } }
        )

        foreach ($case in $cases) {
            Invoke-UiPolicyCase -Case $case -Phase 'P4e' -HwndVal $hwndVal -HostPid $PID
        }

        # The allowed half of desktopSystemControl=true that cannot be probed.
        # Recorded rather than omitted so the matrix does not read as complete.
        Record-Result -Phase 'P4e' -Name 'pcUi.desktopSystemControl=true -> EXITWINDOWS=allowed' -Status 'skip' `
            -Detail 'not probeable: an unblocked ExitWindowsEx(EWX_LOGOFF) really logs the session off'

        # ime has no probe tag, so the documented "evaluated independently of
        # ui.disable" behavior has no behavioral assertion available.
        Record-Result -Phase 'P4e' -Name 'pcUi.ime=false -> input-method changes blocked' -Status 'skip' `
            -Detail 'wxc-ui-probe has no IME tag; no behavioral assertion available for block_input_method_changes'
    }
    finally {
        $winHost.Stop()
    }
}


# -----------------------------------------------------------------------
# Phase 4f -- ui.disable=true overrides every individual allow
#
# Documented: when ui.disable is true, every restriction flag is set
# regardless of the other knobs. So a config that asks for maximal permission
# on every other knob must still come back fully blocked. This is the one
# case where a permissive knob is expected NOT to take effect, which makes it
# the natural place for an override regression to hide.
#
# WIN32K is not probed here: ui.disable=true also engages the Win32k
# mitigation, which terminates the process at the first Win32k syscall, and
# every tag below is a Win32k call. See Phase 4b scenario B, which asserts the
# mitigation itself. On a host where the mitigation is active the child dies
# before printing, and the tags come back <missing> -> these assertions fail
# rather than silently passing, which is the honest outcome for a probe that
# could not run.
# -----------------------------------------------------------------------
function Phase-UiDisableOverrides {
    Section 'Phase 4f: ui.disable=true overrides permissive knobs'

    $case = @{
        Name               = 'disable-overrides'
        Label              = 'ui.disable=true + every knob permissive'
        UiDisable          = $true
        Clipboard          = 'all'
        Injection          = $true
        BpUiIsolation      = 'desktop'
        BpUiDesktopControl = $true
        BpUiSystemSettings = 'all'
        Expect             = @{
            READCLIPBOARD    = 'blocked'
            WRITECLIPBOARD   = 'blocked'
            SYSTEMPARAMETERS = 'blocked'
            DISPLAYSETTINGS  = 'blocked'
            DESKTOP          = 'blocked'
        }
    }

    $winHost = New-Object Mxc.WindowHost
    $winHost.Start("MxcUiDisableProbe_$([guid]::NewGuid().ToString('N'))")
    try {
        Invoke-UiPolicyCase -Case $case -Phase 'P4f' -HwndVal $winHost.Hwnd.ToInt64() -HostPid $PID
    }
    finally {
        $winHost.Stop()
    }
}


Invoke-WpcPhase -Key 'UiPolicyMatrix'    -Body { Phase-UiPolicyMatrix }
Invoke-WpcPhase -Key 'UiDisableOverride' -Body { Phase-UiDisableOverrides }
Complete-WpcChild
