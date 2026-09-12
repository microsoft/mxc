# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Full UI policy resolution matrix.
#
# Phase 4b proves maximal lockdown — one point in the space. This area walks
# the rest: every documented value of every UI knob, including the values that
# are supposed to ALLOW an operation.
#
# Expectations come from `resolve_ui_restrictions`
# (src/core/wxc_common/src/ui_policy.rs), whose rule is "the named thing is
# the thing you keep": clipboard=read allows reading and blocks writing.
#
# Allow-direction coverage matters: a flag wired to the wrong bit, or set
# unconditionally, still passes every blocked-direction assertion in 4b.
#
# SAFETY: EXITWINDOWS is never probed where it is expected to be allowed —
# that would be a real logoff of the operator's session. Those cases record an
# explicit skip so the gap stays visible.
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
. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Native.ps1')

Initialize-WpcContext @PSBoundParameters


# Assert the documented floor: with every UI knob permissive, a contained
# process gets every UI capability.
#
# UIPolicy_Schema.md:95 maps clipboard="all" to no UILIMIT flags and "Allowed"
# for both directions; os-version-support.md:185 marks clipboard, systemSettings
# and desktopSystemControl supported on every build. No doc says containment
# removes them. So anything still denied here is a real defect, not a quirk of
# the test host, and it is reported as one -- it also explains at a glance why
# the individual allow cases below went red.
function Measure-UiReachable {
    $tags = @('READCLIPBOARD', 'WRITECLIPBOARD', 'SYSTEMPARAMETERS', 'DISPLAYSETTINGS', 'DESKTOP')
    $cfg = New-Config -Name 'ui-policy-baseline' -CommandLine "`"$UiProbeDebug`" $($tags -join ' ')" `
        -ReadWrite @((Join-Path $ScratchRoot 'rw')) -Env (Get-ProbeEnvWithDestructive) `
        -UiDisable $false -Clipboard 'all' -BpUiSystemSettings 'all' -BpUiDesktopControl $true `
        -BpUiIsolation 'desktop'
    $log = Join-Path $ScratchRoot 'logs\ui-policy-baseline.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log

    $verdicts = @([regex]::Matches($r.Stdout, '(?m)^[A-Z][A-Z0-9_]*=(?:PASS|FAIL|INCONCLUSIVE)\s*$'))
    if ($r.ExitCode -ne 0 -or $verdicts.Count -eq 0) {
        Record-Result -Phase 'P4e' -Name 'baseline: a fully permissive UI policy grants every UI capability' -Pass $false `
            -Detail "the baseline case did not run (exit=$($r.ExitCode); verdicts=$($verdicts.Count))"
        return
    }

    # FAIL from the probe means the operation succeeded, i.e. the capability is
    # granted -- which is what a permissive policy must produce.
    $denied = @($tags | Where-Object { $r.Stdout -notmatch "(?m)^$_=FAIL\s*$" })

    $shown = if ($denied.Count) { $denied -join ', ' } else { '<none>' }
    Record-Result -Phase 'P4e' -Name 'baseline: a fully permissive UI policy grants every UI capability' `
        -Pass ($denied.Count -eq 0) `
        -Detail "still denied: $shown (UIPolicy_Schema.md:95 and os-version-support.md:185 document these as allowed)"
}


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

        if ($got -eq 'INCONCLUSIVE') {
            $diag = if ($r.Stdout -match "(?m)^$tag=DIAG\s+(?<d>.+?)\s*$") { $matches['d'] } else { '<no diag>' }
            # ui.disable=true engages the Win32k mitigation, which stops user32
            # from loading. Losing the GUI subsystem outright is strictly
            # stronger than the individual limit, so it satisfies "blocked".
            if ($Case.ContainsKey('GuiGoneIsBlocked') -and $want -eq 'blocked' -and $diag -match 'user32') {
                Record-Result -Phase $Phase -Name $name -Pass $true `
                    -Detail "expected=blocked; GUI subsystem unavailable (Win32k mitigation); diag=$diag"
                continue
            }
            # Nothing documents the probe being unable to run here, so this is a
            # finding rather than a skip.
            Record-Result -Phase $Phase -Name $name -Pass $false `
                -Detail "expected=$want; the probe could not exercise $tag and no policy here explains that; diag=$diag"
            continue
        }

        # A contained process still gets the documented capability when the knob
        # is permissive (UIPolicy_Schema.md:95, os-version-support.md:185).
        # Measure-UiReachable reports the contradiction once; the per-knob cases
        # below stay red so a real regression is never hidden behind a skip.

        $expectToken = if ($want -eq 'blocked') { 'PASS' } else { 'FAIL' }
        Record-Result -Phase $Phase -Name $name -Pass ($got -eq $expectToken) `
            -Detail "expected=$want; got=$gotV; full=$summaryV"
    }
}


# Phase 4e -- UI policy resolution matrix
#
# One case per documented value of each knob. Cases assert only the tags the
# knob actually governs, so a failure names the exact mapping that broke.
function Phase-UiPolicyMatrix {
    Section 'Phase 4e: UI policy resolution matrix (every documented value)'

    Measure-UiReachable

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

        # isolation is a closed enum on the wire, so an unrecognized value is
        # refused at deserialize; the resolver's fallback arm is unreachable
        # from JSON. systemSettings is a free string and does reach it.
        $cfg = New-Config -Name 'ui-policy-iso-bogus' -CommandLine "`"$UiProbeDebug`" HANDLES" `
            -ReadWrite @((Join-Path $ScratchRoot 'rw')) -BpUiIsolation 'not-a-real-isolation-level'
        $log = Join-Path $ScratchRoot 'logs\ui-policy-iso-bogus.log'
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log
        Record-Result -Phase 'P4e' -Name 'pcUi.isolation=<unrecognized> is rejected (closed enum)' `
            -Pass (Test-WasRejected -Run $r -Log (Read-Log $log)) `
            -Detail "exit=$($r.ExitCode)"

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


# Phase 4f -- ui.disable=true overrides every individual allow
#
# Documented: ui.disable=true sets every restriction flag regardless of the
# other knobs, so maximal permission everywhere must still come back fully
# blocked. The one case where a permissive knob is expected NOT to take
# effect, and so the natural place for an override regression to hide.
#
# WIN32K is not probed: ui.disable also engages the Win32k mitigation, which
# kills the process at the first Win32k syscall — and every tag here is one.
# Phase 4b scenario B asserts the mitigation itself.
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
        GuiGoneIsBlocked   = $true
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
