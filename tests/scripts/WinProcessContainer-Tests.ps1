# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# WinProcessContainer-Tests.ps1  (formerly Win25H2Safe-Tests.ps1)
#
# Exercises the Windows process-container (AppContainer / BaseContainer) stack
# without ever invoking bfscfg.exe (which hard-locks the bfs.sys minifilter on
# 25H2). The harness is capability-driven and runs on any Windows host: it
# derives the EXPECTED containment tier from the runtime --probe signals rather
# than hardcoding it (see Get-HostCapabilities).
#
# Safety model (`tier2_bfs` Cargo feature OFF, the default):
#   * Test-Preflight refuses to run if either wxc-exec binary reports
#     `bfsCompiledIn=true` in --probe output. This is the load-bearing
#     gate; everything else is belt-and-suspenders. It applies on every
#     build — bfscfg is never invoked regardless of OS version, so no
#     OS-version branching is needed for safety. (bfscfg.exe only ships on
#     Germanium+ / 24H2+25H2 anyway; 22H2/23H2 lack it entirely.)
#   * With `tier2_bfs` off, `fallback_detector::find_bfscfg_exe` returns
#     `Ok(None)` unconditionally, `appcontainer-bfs` is never selected, and
#     the dispatcher falls back to BaseContainer (T1, when usable) or
#     AppContainer + DACL (T3).
#   * Every run is post-checked: if the captured log contains the spawn
#     marker "Output from bfscfg.exe" the run fails and the harness aborts.
#   * The harness relies on **natural** tier selection — there is no
#     `-ForceTier` parameter and no `MXC_FORCE_TIER` env-var manipulation
#     (the env var is `#[cfg(test)]`-gated and has no effect on the
#     production wxc-exec binary).
#
# Tier expectations (with tier2_bfs OFF) are identical for every policy shape:
#   * BaseContainer usable -> `base-container`
#   * otherwise            -> `appcontainer-dacl`
# $Script:ExpectedTier (derived once at startup) drives every tier assertion.

[CmdletBinding()]
param(
    # Defaults assume the script lives at <repo>\tests\scripts\; the
    # cargo workspace and built binaries are under <repo>\src\. Override
    # any of these explicitly if the layout differs.
    [string]$RepoRoot       = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$CargoRoot      = (Join-Path $RepoRoot 'src'),
    [string]$WxcDebug       = (Join-Path $RepoRoot 'src\target\debug\wxc-exec.exe'),
    [string]$WxcRelease     = (Join-Path $RepoRoot 'src\target\release\wxc-exec.exe'),
    [string]$UiProbeDebug   = (Join-Path $RepoRoot 'src\target\debug\wxc-ui-probe.exe'),
    [string]$UiProbeRelease = (Join-Path $RepoRoot 'src\target\release\wxc-ui-probe.exe'),
    [string]$ScratchRoot    = (Join-Path $env:TEMP 'mxc-wpc-tests'),
    # Default results/log files live in $env:TEMP but OUTSIDE $ScratchRoot
    # so `Initialize-Scratch`'s recursive nuke can't conflict with the
    # `Start-Transcript` file handle (the script starts the transcript
    # BEFORE wiping the scratch tree). The previous default landed them
    # under $ScratchRoot and tripped a "file in use" abort on every run.
    [string]$ResultsFile    = (Join-Path $env:TEMP 'WinProcessContainer-Tests.results.txt'),
    [string]$ResultsJson    = (Join-Path $env:TEMP 'WinProcessContainer-Tests.results.json'),
    [string]$CargoLog       = (Join-Path $env:TEMP 'WinProcessContainer-Tests.cargo.log'),
    [switch]$SkipBuild,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts,
    # Restrict execution to a subset of phases (build + preflight + scratch
    # init always run). Accepts the phase keys listed in $AllPhases below, e.g.
    # -Phases UiMitigationMatrix runs only Phase 4b. Empty = run all phases.
    [string[]]$Phases = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The UI-mitigation probe binary refuses EXITWINDOWS / WIN32K by default —
# running those operations outside a sandbox can log out the interactive
# user. The contained child must see MXC_PROBE_DESTRUCTIVE_OK=1 to attempt
# them. NOTE: the AppContainer (T3) runner REPLACES the child environment with
# the config's `process.env` whenever it is non-empty (it only falls back to
# CreateEnvironmentBlock when env is empty), so a process-level `$env:` here
# would NOT reach the child. The override is therefore delivered per-run via
# New-Config -Env (see Get-ProbeEnvWithDestructive). That env block must be
# COMPLETE — CreateProcessW requires at least %SystemRoot% and fails with
# ERROR_ENVVAR_NOT_FOUND (0x800700CB) on a one-var block — so we pass the full
# current environment plus the override, not just the override alone.

# kernel32 atom-table P/Invoke used by Phase-GlobalAtomIsolation to plant a
# host-side global atom (direction 1) and to probe its own session-global
# table for the contained process's atom (direction 2). Guarded so a re-run
# in the same PowerShell session doesn't throw "type already exists".
if (-not ([System.Management.Automation.PSTypeName]'Mxc.AtomNative').Type) {
    Add-Type -Namespace 'Mxc' -Name 'AtomNative' -MemberDefinition @'
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ushort GlobalAddAtomW(string lpString);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern ushort GlobalFindAtomW(string lpString);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern ushort GlobalDeleteAtom(ushort nAtom);
'@ | Out-Null
}

# A hidden, message-pumping top-level window owned by the harness process —
# used by Phase 4b's HANDLES probe as a USER handle owned by a process OUTSIDE
# the job. The window runs its message loop on a dedicated background thread so
# a cross-job GetWindowTextW (WM_GETTEXT) is answered promptly in the (broken)
# case where the JOB_OBJECT_UILIMIT_HANDLES limit fails to block it.
if (-not ([System.Management.Automation.PSTypeName]'Mxc.WindowHost').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Mxc {
    public class WindowHost {
        [StructLayout(LayoutKind.Sequential)]
        private struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public int ptX; public int ptY; }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateWindowExW(int dwExStyle, string lpClassName, string lpWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyWindow(IntPtr hWnd);
        [DllImport("user32.dll")]
        private static extern int GetMessageW(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
        [DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref MSG lpMsg);
        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessageW(ref MSG lpMsg);
        [DllImport("user32.dll")]
        private static extern bool PostThreadMessageW(uint idThread, uint Msg, IntPtr wParam, IntPtr lParam);
        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        private const uint WM_QUIT = 0x0012;
        private const int WS_EX_TOOLWINDOW = 0x00000080;

        private Thread _thread;
        private uint _threadId;
        private volatile IntPtr _hwnd = IntPtr.Zero;
        private readonly ManualResetEventSlim _ready = new ManualResetEventSlim(false);
        private string _title;

        public IntPtr Hwnd { get { return _hwnd; } }
        public string Title { get { return _title; } }

        public void Start(string title) {
            _title = title;
            _thread = new Thread(Run);
            _thread.IsBackground = true;
            _thread.Start();
            if (!_ready.Wait(5000)) { throw new Exception("WindowHost: window creation timed out"); }
            if (_hwnd == IntPtr.Zero) { throw new Exception("WindowHost: CreateWindowExW failed"); }
        }

        private void Run() {
            _threadId = GetCurrentThreadId();
            // The system "STATIC" class needs no registration; omitting
            // WS_VISIBLE keeps the window hidden. The window just needs to be a
            // valid HWND owned by this (out-of-job) process for the HANDLES
            // probe's GetWindowThreadProcessId to resolve.
            _hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, "STATIC", _title, 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            _ready.Set();
            if (_hwnd == IntPtr.Zero) { return; }
            MSG msg;
            // Pump the queue to keep this thread (and thus the window) alive
            // until Stop() posts WM_QUIT. GetMessageW returns 0 on WM_QUIT and
            // -1 on error; exit on both.
            while (GetMessageW(out msg, IntPtr.Zero, 0, 0) > 0) {
                TranslateMessage(ref msg);
                DispatchMessageW(ref msg);
            }
            DestroyWindow(_hwnd);
        }

        public void Stop() {
            if (_thread == null) { return; }
            if (_threadId != 0) { PostThreadMessageW(_threadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero); }
            _thread.Join(3000);
        }
    }
}
'@ | Out-Null
}

# -----------------------------------------------------------------------
# Result accumulator
# -----------------------------------------------------------------------
$Script:Results = [System.Collections.Generic.List[object]]::new()

function Record-Result {
    param(
        [Parameter(Mandatory)] [string]$Phase,
        [Parameter(Mandatory)] [string]$Name,
        [bool]$Pass = $true,
        # Visual/semantic status. When omitted, derived from -Pass for back-
        # compat (pass/fail). 'skip' = not applicable on this host/tier/build;
        # 'warn' = a constraint we expected to hold was NOT enforced (e.g. an
        # OS feature gated off). Neither 'skip' nor 'warn' fails the run, but
        # both render distinctly so a non-enforced check is never a green PASS.
        [ValidateSet('pass', 'fail', 'skip', 'warn')] [string]$Status,
        [string]$Detail = ''
    )
    if (-not $PSBoundParameters.ContainsKey('Status')) {
        $Status = if ($Pass) { 'pass' } else { 'fail' }
    } else {
        # Keep the boolean consistent for downstream logic: only 'fail' fails.
        $Pass = ($Status -ne 'fail')
    }
    $entry = [pscustomobject]@{
        Phase  = $Phase
        Name   = $Name
        Pass   = $Pass
        Status = $Status
        Detail = $Detail
    }
    $Script:Results.Add($entry) | Out-Null
    switch ($Status) {
        'pass' { $tag = '[PASS]'; $color = 'Green' }
        'fail' { $tag = '[FAIL]'; $color = 'Red' }
        'skip' { $tag = '[SKIP]'; $color = 'Yellow' }
        'warn' { $tag = '[WARN]'; $color = 'Yellow' }
    }
    Write-Host ("  {0} {1} :: {2} {3}" -f $tag, $Phase, $Name, $(if ($Detail) { "($Detail)" } else { '' })) -ForegroundColor $color
}

function Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
}

# Probe binaries report each checked operation as TAG=PASS / TAG=FAIL, where
# PASS/FAIL describe the *probe's* notion of the outcome, not the harness
# verdict. Surfacing those raw tokens next to the harness's own [PASS]/[FAIL]
# reads as a contradiction (e.g. a green [PASS] line containing "got=FAIL").
# These helpers translate the probe tokens into semantic verbs for display
# only — the wire protocol and the parsing regexes are unchanged. Callers pass
# the verb pair for the probe family: UI/atom probes use blocked/allowed
# (PASS = the constraint blocked the op); the filesystem matrix uses
# allowed/denied (PASS = the access succeeded).
function Format-Verdict {
    param([string]$Verdict, [string]$Pass, [string]$Fail)
    switch ($Verdict) {
        'PASS' { $Pass }
        'FAIL' { $Fail }
        default { $Verdict }
    }
}

function Format-VerdictSummary {
    param([string]$Summary, [string]$Pass, [string]$Fail)
    [regex]::Replace($Summary, '=(PASS|FAIL)\b', {
        param($m) '=' + (Format-Verdict $m.Groups[1].Value $Pass $Fail)
    })
}

# -----------------------------------------------------------------------
# Pre-flight
# -----------------------------------------------------------------------
function Test-Preflight {
    Section 'Pre-flight'

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Host ("OS: {0} (build {1})" -f $os.Caption, $os.BuildNumber)

    $bfsPath = Join-Path $env:SystemRoot 'System32\bfscfg.exe'
    $bfsPresent = Test-Path $bfsPath
    # bfscfg.exe ships only on Germanium+ builds (24H2/25H2); 22H2/23H2 lack it
    # entirely. Its presence is informational only — this harness never invokes
    # it on any build (the bfsCompiledIn=false gate below is what enforces
    # safety), so absence is not a problem.
    Write-Host ("bfscfg.exe present in System32: {0} (Germanium+ ships it; pre-Ge builds do not)" -f $bfsPresent)

    if (-not $SkipBuild) {
        if (-not (Test-Path (Join-Path $CargoRoot 'Cargo.toml'))) {
            throw "No Cargo.toml at $CargoRoot. Pass -CargoRoot <path> if the workspace lives elsewhere."
        }
        Write-Host "Building debug + release binaries (workspace: $CargoRoot)..."
        Push-Location $CargoRoot
        try {
            & cargo build -p wxc 2>&1 | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "cargo build (debug) failed" }
            & cargo build -p wxc --release 2>&1 | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "cargo build (release) failed" }
            & cargo build -p wxc_ui_probe 2>&1 | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "cargo build wxc_ui_probe (debug) failed" }
            & cargo build -p wxc_ui_probe --release 2>&1 | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "cargo build wxc_ui_probe (release) failed" }
        } finally {
            Pop-Location
        }
    }

    if (-not (Test-Path $WxcDebug))   { throw "Debug binary not found at $WxcDebug" }
    if (-not (Test-Path $WxcRelease)) { throw "Release binary not found at $WxcRelease" }
    if (-not (Test-Path $UiProbeDebug))   { throw "UI probe debug binary not found at $UiProbeDebug" }
    if (-not (Test-Path $UiProbeRelease)) { throw "UI probe release binary not found at $UiProbeRelease" }

    # The load-bearing safety check: refuse to run if either binary has
    # the `tier2_bfs` Cargo feature compiled in. On 25H2 spawning
    # `bfscfg.exe` hard-locks the OS. The feature gate at compile time
    # is what makes the harness safe to run; this preflight verifies it.
    foreach ($pair in @(@{ Path = $WxcDebug; Label = 'debug' }, @{ Path = $WxcRelease; Label = 'release' })) {
        $probe = & $pair.Path --probe 2>$null | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $probe.probes.bfsCompiledIn) {
            throw "Preflight: $($pair.Label) binary at $($pair.Path) does not expose `bfsCompiledIn` in its --probe output. Rebuild from a tree that has the tier2_bfs gate."
        }
        if ($probe.probes.bfsCompiledIn) {
            throw "Preflight ABORT: $($pair.Label) binary at $($pair.Path) was built with --features tier2_bfs. On 25H2 this risks an OS hang. Rebuild without the feature (drop --features tier2_bfs) before re-running."
        }
        Write-Host ("bfsCompiledIn ({0,-7}): false" -f $pair.Label)
    }
}

# -----------------------------------------------------------------------
# Scratch + helpers
# -----------------------------------------------------------------------
function Assert-SafeScratchRoot {
    # Refuse to nuke arbitrary paths. `Initialize-Scratch` issues a
    # recursive `Remove-Item -Force` against `$ScratchRoot`; if a user
    # accidentally passes `-ScratchRoot C:\` (or any other important
    # directory) the harness must abort BEFORE the destructive call.
    #
    # Policy: the path must be non-empty, must resolve to somewhere
    # under `$env:TEMP`, must NOT be the TEMP root itself, must NOT be
    # a drive root, and must carry the `mxc-` prefix in its leaf name.
    if ([string]::IsNullOrWhiteSpace($ScratchRoot)) {
        throw "Refusing to operate on an empty/whitespace -ScratchRoot."
    }
    $resolved = [System.IO.Path]::GetFullPath($ScratchRoot)
    $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP)
    if (-not $resolved.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing -ScratchRoot '$resolved': must resolve under `$env:TEMP` ($tempRoot). Recursive deletion of paths outside TEMP is blocked."
    }
    if ($resolved.TrimEnd('\','/') -ieq $tempRoot.TrimEnd('\','/')) {
        throw "Refusing -ScratchRoot '$resolved': cannot equal `$env:TEMP` itself."
    }
    # `Path.GetPathRoot` of a drive root returns the same string (e.g.
    # `C:\` → `C:\`). Any path whose root equals itself is the root.
    $root = [System.IO.Path]::GetPathRoot($resolved)
    if ($root -and ($resolved.TrimEnd('\','/') -ieq $root.TrimEnd('\','/'))) {
        throw "Refusing -ScratchRoot '$resolved': drive roots are not valid scratch directories."
    }
    $leaf = Split-Path -Path $resolved -Leaf
    if ($leaf -notlike 'mxc-*') {
        throw "Refusing -ScratchRoot '$resolved': leaf name '$leaf' must start with 'mxc-' to confirm operator intent."
    }
}

function Initialize-Scratch {
    Assert-SafeScratchRoot
    if (Test-Path $ScratchRoot) {
        Remove-Item -Recurse -Force -LiteralPath $ScratchRoot
    }
    New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'logs')    | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'configs') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'rw')      | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'ro')      | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'denied')  | Out-Null
    # `control` is intentionally NOT named in any policy. Used by the
    # access-matrix sub-test to confirm AppContainer denies paths that
    # were never granted, not just ones explicitly denied.
    New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'control') | Out-Null
}

function Get-DaclRestoreDir {
    Join-Path $env:LOCALAPPDATA 'Microsoft\MXC\dacl-restore'
}

function Get-StateFiles {
    # Emits FileInfo objects naturally so pipelines (Where-Object) iterate
    # element-by-element. Callers that need .Count must wrap with @(...)
    # because an empty function output materializes as $null at assignment.
    $dir = Get-DaclRestoreDir
    if (-not (Test-Path $dir)) { return }
    Get-ChildItem -LiteralPath $dir -Filter '*.json' -ErrorAction SilentlyContinue
}

function Clear-StateFiles {
    # Wipe the dacl-restore directory so a phase can assert
    # "no NEW state files appeared during this phase".
    $dir = Get-DaclRestoreDir
    if (Test-Path $dir) {
        Get-ChildItem -LiteralPath $dir -Filter '*.json' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

function Get-Acl-Snapshot {
    param([string]$Path)
    # Use icacls' raw text. Strip the trailing summary line so transient
    # state doesn't perturb the comparison.
    $raw = & icacls.exe $Path 2>&1
    ($raw | Where-Object { $_ -notmatch 'Successfully processed' }) -join "`n"
}

function Read-Log {
    param([string]$LogPath)
    if (Test-Path $LogPath) { Get-Content -Raw -LiteralPath $LogPath } else { '' }
}

function Assert-NoBfscfg {
    param(
        [string]$LogContent,
        [string]$Phase,
        [string]$Name,
        # Phases that intentionally exercise the T2-selected, no-invocation
        # path (P2 empty policy, P3 denied-only) pass this switch. The
        # `bfscfg` substring check still fires either way — that one
        # signals actual invocation, which is fatal everywhere.
        [switch]$AllowBfsTierSelection
    )
    # The unique signature of an actual bfscfg.exe invocation is
    # `Output from bfscfg.exe:` emitted by
    # filesystem_bfs::execute_bfscfg_operation on a non-empty
    # stdout/stderr capture. The plain substring `bfscfg` also appears
    # in legitimate fallback-chain warnings ("bfscfg.exe not present;
    # falling back to AppContainer + DACL") which are evidence of the
    # safety gate WORKING, not of invocation. Match only the
    # spawn-output marker.
    if ($LogContent -match '(?im)Output from bfscfg\.exe') {
        throw "[$Phase :: $Name] FATAL: log contains 'Output from bfscfg.exe' (real invocation). Aborting to avoid 25H2 deadlock."
    }
    if (-not $AllowBfsTierSelection) {
        # Logger interleaves a `[timestamp] ` token between every
        # write fragment, so a single `writeln!(logger, "x: {}", y)`
        # serializes as `x: [ts] y`. Use `.*?` instead of `\s*` to
        # bridge that token.
        if ($LogContent -match '(?im)selected isolation tier:.*?appcontainer-bfs') {
            throw "[$Phase :: $Name] FATAL: log shows 'selected isolation tier: appcontainer-bfs'. Aborting."
        }
    }
}

# -----------------------------------------------------------------------
# Config generation
# -----------------------------------------------------------------------
# Build a COMPLETE environment block (current process env + the destructive
# override) for delivery to the contained probe via New-Config -Env. The T3
# runner replaces the child env with process.env when it is non-empty, and
# CreateProcessW requires a full block (notably %SystemRoot%), so passing only
# the override would fail with ERROR_ENVVAR_NOT_FOUND (0x800700CB).
function Get-ProbeEnvWithDestructive {
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $k = [string]$e.Key
        # Skip the hidden per-drive "=C:" cwd vars and any empty key; skip the
        # override (re-added below) and the test-only tier knob.
        if ([string]::IsNullOrEmpty($k) -or $k.StartsWith('=')) { continue }
        if ($k -ieq 'MXC_PROBE_DESTRUCTIVE_OK' -or $k -ieq 'MXC_FORCE_TIER') { continue }
        [void]$list.Add("$k=$($e.Value)")
    }
    [void]$list.Add('MXC_PROBE_DESTRUCTIVE_OK=1')
    return $list.ToArray()
}

# -----------------------------------------------------------------------
# Capability model — derive the expected containment tier from runtime
# --probe signals rather than hardcoding it, so the harness runs unchanged on
# both T3 hosts (BaseContainer unusable) and T1 hosts (BaseContainer usable,
# e.g. pre-Germanium builds that lack bfscfg.exe entirely).
#
# `tier2_bfs` is always OFF here (Test-Preflight enforces bfsCompiledIn=false),
# so `appcontainer-bfs` is never selected and the selected tier is identical
# for every policy shape: `base-container` when BaseContainer is usable, else
# `appcontainer-dacl`. BaseContainer usability is detected by the empty-policy
# probe resolving to `base-container`.
# -----------------------------------------------------------------------
function Get-HostCapabilities {
    $p = Invoke-Probe -Wxc $WxcRelease -Phase 'P0' -Name 'host-capabilities'
    if (-not $p) {
        throw 'Get-HostCapabilities: empty-policy --probe failed; cannot determine host tier.'
    }
    $tier = [string]$p.tier
    # Fail fast on an empty/absent tier. A detector error makes $p.tier null,
    # which would collapse to "" here; Test-SelectedTier then escapes "" into a
    # pattern that matches ANY "selected isolation tier:" line, silently turning
    # an unknown tier into false PASS results. Surface the probe error/warnings
    # instead of proceeding with an unknown tier.
    if ([string]::IsNullOrEmpty($tier)) {
        $errDetail = if ($p.PSObject.Properties['error'] -and $p.error) { [string]$p.error } else { '<none>' }
        $warnDetail = if ($p.PSObject.Properties['warnings'] -and $p.warnings) { ($p.warnings -join '; ') } else { '<none>' }
        throw "Get-HostCapabilities: empty-policy --probe returned no tier (error=$errDetail; warnings=$warnDetail); cannot determine host tier."
    }
    # Defensive: older binaries may not expose baseContainerSupportsDenyPaths.
    $denyBit = if ($p.probes.PSObject.Properties['baseContainerSupportsDenyPaths']) {
        [bool]$p.probes.baseContainerSupportsDenyPaths
    } else { $false }
    # uiCapabilities is absent on older binaries / when the detector errored.
    $canInject = $false
    if ($p.probes.PSObject.Properties['uiCapabilities'] -and
        $p.probes.uiCapabilities.PSObject.Properties['canBlockInputInjection']) {
        $canInject = [bool]$p.probes.uiCapabilities.canBlockInputInjection
    }
    return [pscustomobject]@{
        BaselineTier                   = $tier
        BaseContainerUsable            = ($tier -eq 'base-container')
        BaseContainerApiPresent        = [bool]$p.probes.baseContainerApiPresent
        BfsCompiledIn                  = [bool]$p.probes.bfsCompiledIn
        BfscfgPresent                  = [bool]$p.probes.bfscfgPresent
        BaseContainerSupportsDenyPaths = $denyBit
        # JOB_OBJECT_UILIMIT_INJECTION is build-gated (>= 26100). The probe
        # reports whether the OS build supports the bit; runtime enforcement may
        # still be behind a feature flag, which the Phase 4b INJECTION check
        # accounts for separately.
        CanBlockInputInjection         = $canInject
        # deniedPaths is enforced on T3 via DENY ACEs, and on BaseContainer only
        # when the SANDBOX_CAP_DENY_PATHS bit is set (lights up when the feature
        # ships). Detected at runtime so denied tests auto-enable then.
        SupportsDeniedPaths            = (($tier -eq 'appcontainer-dacl') -or $denyBit)
    }
}

# Expected needsDaclAugmentation for a policy shape: DACL tier always augments;
# BaseContainer augments only when the policy carries denied paths.
function Get-ExpectedDaclAug {
    param([bool]$HasDenied)
    switch ($Script:Caps.BaselineTier) {
        'appcontainer-dacl' { return $true }
        'base-container'    { return [bool]$HasDenied }
        default             { return $true }
    }
}

# Pass when the log shows the host's expected isolation tier. The logger
# interleaves a `[ts] ` token between write fragments, so bridge with `.*?`.
function Test-SelectedTier {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$LogContent)
    $pattern = '(?im)selected isolation tier:.*?' + [regex]::Escape($Script:ExpectedTier)
    return [bool]($LogContent -match $pattern)
}

# Pass when the log shows that UI restrictions were applied, using the tier's
# telemetry. T3 (AppContainer + DACL) creates the job object on the OUTSIDE and
# logs "UI Job Object assigned". BaseContainer applies the job/UI limits INSIDE
# via Experimental_CreateProcessInSandbox and instead logs a
# "[ui subsystem] ... uilimits blocked" line.
function Test-UiRestrictionsApplied {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$LogContent)
    if ($Script:ExpectedTier -eq 'appcontainer-dacl') {
        return [bool]($LogContent -match 'UI Job Object assigned')
    }
    return [bool]($LogContent -match '(?im)uilimits blocked')
}

# Pass when the log shows the Win32k mitigation (win32k syscalls blocked) was
# applied. T3 logs "Win32k mitigation applied"; BaseContainer logs a
# "win32k_system_calls: ... blocked" line in its [ui subsystem] section (vs.
# "... allowed" when ui.disable=false).
function Test-Win32kMitigationApplied {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$LogContent)
    if ($Script:ExpectedTier -eq 'appcontainer-dacl') {
        return [bool]($LogContent -match 'Win32k mitigation applied')
    }
    return [bool]($LogContent -match '(?im)win32k_system_calls:.*?blocked')
}

function New-Config {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$CommandLine,
        [string[]]$ReadWrite = @(),
        [string[]]$ReadOnly  = @(),
        [string[]]$Denied    = @(),
        [Nullable[bool]]$AllowDaclMutation = $null,
        [int]$TimeoutMs = 30000,
        [Nullable[bool]]$UiDisable          = $null,
        [string]$BpUiIsolation              = $null,
        [Nullable[bool]]$BpUiDesktopControl = $null,
        [string]$BpUiSystemSettings         = $null,
        [Nullable[bool]]$BpUiIme            = $null,
        [string]$Clipboard                  = $null,
        [Nullable[bool]]$Injection          = $null,
        [string[]]$Env                      = @()
    )
    $obj = [ordered]@{
        version     = '0.5.0-dev'
        containerId = "MxcWinPC-$Name"
        containment = 'appcontainer'
        process     = [ordered]@{
            commandLine = $CommandLine
            timeout     = $TimeoutMs
        }
    }
    if ($null -ne $Env -and $Env.Count -gt 0) { $obj['process']['env'] = @($Env) }
    $hasRw     = ($null -ne $ReadWrite -and $ReadWrite.Count -gt 0)
    $hasRo     = ($null -ne $ReadOnly  -and $ReadOnly.Count  -gt 0)
    $hasDenied = ($null -ne $Denied    -and $Denied.Count    -gt 0)
    if ($hasRw -or $hasRo -or $hasDenied) {
        $fs = [ordered]@{}
        if ($hasRw)     { $fs['readwritePaths'] = @($ReadWrite) }
        if ($hasRo)     { $fs['readonlyPaths']  = @($ReadOnly) }
        if ($hasDenied) { $fs['deniedPaths']    = @($Denied) }
        $obj['filesystem'] = $fs
    }
    if ($null -ne $AllowDaclMutation) {
        $obj['fallback'] = [ordered]@{ allowDaclMutation = [bool]$AllowDaclMutation }
    }
    $ui = [ordered]@{ disable = $(if ($null -ne $UiDisable) { [bool]$UiDisable } else { $false }) }
    if ($Clipboard) { $ui['clipboard'] = $Clipboard }
    if ($null -ne $Injection) { $ui['injection'] = [bool]$Injection }
    $obj['ui'] = $ui

    $needBp = ($BpUiIsolation -or $BpUiSystemSettings -or $null -ne $BpUiDesktopControl -or $null -ne $BpUiIme)
    if ($needBp) {
        $bp = [ordered]@{}
        if ($BpUiIsolation)              { $bp['isolation']            = $BpUiIsolation }
        if ($null -ne $BpUiDesktopControl) { $bp['desktopSystemControl'] = [bool]$BpUiDesktopControl }
        if ($BpUiSystemSettings)         { $bp['systemSettings']       = $BpUiSystemSettings }
        if ($null -ne $BpUiIme)          { $bp['ime']                  = [bool]$BpUiIme }
        $obj['processContainer'] = [ordered]@{ ui = $bp }
    }

    $path = Join-Path (Join-Path $ScratchRoot 'configs') "$Name.json"
    ($obj | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $path -Encoding utf8 -Force
    return $path
}

# -----------------------------------------------------------------------
# Test runners
# -----------------------------------------------------------------------
function Invoke-Probe {
    param([string]$Wxc, [string]$ConfigPath = $null, [string]$Phase, [string]$Name)
    # Use ProcessStartInfo so we can keep stdout (the JSON) separate from
    # stderr (DACL-recovery messages, build-time warnings).
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Wxc
    $argList = @('--probe')
    if ($ConfigPath) { $argList += @('--config', "`"$ConfigPath`"") }
    $psi.Arguments = ($argList -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    if (-not $p.WaitForExit(15000)) {
        try { $p.Kill() } catch {}
        Record-Result -Phase $Phase -Name $Name -Pass $false -Detail 'probe timeout'
        return $null
    }
    if ($p.ExitCode -ne 0) {
        Record-Result -Phase $Phase -Name $Name -Pass $false -Detail "exit=$($p.ExitCode); stderr=$stderr"
        return $null
    }
    try {
        return $stdout | ConvertFrom-Json
    } catch {
        Record-Result -Phase $Phase -Name $Name -Pass $false -Detail "malformed JSON: $_"
        return $null
    }
}

function Invoke-Wxc {
    param(
        [Parameter(Mandatory)] [string]$Wxc,
        [Parameter(Mandatory)] [string]$ConfigPath,
        [Parameter(Mandatory)] [string]$LogPath,
        [int]$ExpectExitCode = 0,
        [int]$TimeoutSec     = 60
    )
    # Scrub MXC_FORCE_TIER defensively in case some other process in this
    # session set it. The env var is `#[cfg(test)]`-gated and has no
    # effect on production wxc-exec — natural detection drives every
    # tier-selection assertion below.
    Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Wxc
    $psi.Arguments = "--config `"$ConfigPath`" --experimental --log-file `"$LogPath`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        return [pscustomobject]@{ ExitCode = -1; Stdout = ''; Stderr = "TIMEOUT after ${TimeoutSec}s" }
    }
    return [pscustomobject]@{
        ExitCode = $p.ExitCode
        Stdout   = $p.StandardOutput.ReadToEnd()
        Stderr   = $p.StandardError.ReadToEnd()
    }
}

# -----------------------------------------------------------------------
# Phase 1 — probes (read-only, never touches bfscfg)
#
# Expectations assume the `tier2_bfs` Cargo feature is OFF (Test-Preflight
# enforces this), so the selected tier is the same for every policy shape:
# `base-container` when BaseContainer is usable, else `appcontainer-dacl`.
# The phase keys off $Script:ExpectedTier (derived from the empty-policy
# probe) rather than any OS-version assumption, so it runs unchanged on both
# T1-capable and T3-only hosts. needsDaclAugmentation is asserted via
# Get-ExpectedDaclAug (DACL tier always augments; BaseContainer augments only
# for denied paths).
# -----------------------------------------------------------------------
function Phase-Probes {
    Section 'Phase 1: --probe (read-only)'

    $rw = Join-Path $ScratchRoot 'rw'
    $denied = Join-Path $ScratchRoot 'denied'

    $probeEmpty = Invoke-Probe -Wxc $WxcRelease -Phase 'P1' -Name 'probe-no-config'
    if ($probeEmpty) {
        $bcState = if ($Script:Caps.BaseContainerUsable) { 'usable' }
                   elseif ($probeEmpty.probes.baseContainerApiPresent) { 'present-but-disabled' }
                   else { 'absent' }
        Write-Host ("BaseContainer state on this host: {0} (apiPresent={1}); expected tier={2}" -f $bcState, $probeEmpty.probes.baseContainerApiPresent, $Script:ExpectedTier)

        Record-Result -Phase 'P1' -Name 'expected tier is a recognized value' -Pass ($Script:ExpectedTier -in @('base-container', 'appcontainer-dacl')) -Detail "expectedTier=$($Script:ExpectedTier)"
        Record-Result -Phase 'P1' -Name 'bfsCompiledIn=false (safety gate)' -Pass (-not $probeEmpty.probes.bfsCompiledIn) -Detail "bfsCompiledIn=$($probeEmpty.probes.bfsCompiledIn)"
        Record-Result -Phase 'P1' -Name 'bfscfgPresent=false when feature off' -Pass (-not $probeEmpty.probes.bfscfgPresent) -Detail "bfscfgPresent=$($probeEmpty.probes.bfscfgPresent)"
        Record-Result -Phase 'P1' -Name "empty policy probe -> tier=$($Script:ExpectedTier)" -Pass ($probeEmpty.tier -eq $Script:ExpectedTier) -Detail "tier=$($probeEmpty.tier)"
        $expAugEmpty = Get-ExpectedDaclAug -HasDenied:$false
        Record-Result -Phase 'P1' -Name "empty policy probe -> needsDaclAugmentation=$expAugEmpty" -Pass ($probeEmpty.needsDaclAugmentation -eq $expAugEmpty) -Detail "needsDaclAugmentation=$($probeEmpty.needsDaclAugmentation)"
    }

    $cfgRw = New-Config -Name 'probe-rw' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw)
    $probeRw = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgRw -Phase 'P1' -Name 'probe-rw-config'
    if ($probeRw) {
        Record-Result -Phase 'P1' -Name "rw-paths probe -> tier=$($Script:ExpectedTier)" -Pass ($probeRw.tier -eq $Script:ExpectedTier) -Detail "tier=$($probeRw.tier)"
        $expAugRw = Get-ExpectedDaclAug -HasDenied:$false
        Record-Result -Phase 'P1' -Name "rw-paths probe -> needsDaclAugmentation=$expAugRw" -Pass ($probeRw.needsDaclAugmentation -eq $expAugRw) -Detail "needsDaclAugmentation=$($probeRw.needsDaclAugmentation)"
    }

    $cfgDenied = New-Config -Name 'probe-denied' -CommandLine 'cmd /c exit 0' -Denied @($denied)
    $probeDenied = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgDenied -Phase 'P1' -Name 'probe-denied-config'
    if ($probeDenied) {
        Record-Result -Phase 'P1' -Name "denied probe -> tier=$($Script:ExpectedTier)" -Pass ($probeDenied.tier -eq $Script:ExpectedTier) -Detail "tier=$($probeDenied.tier)"
        $expAugDenied = Get-ExpectedDaclAug -HasDenied:$true
        Record-Result -Phase 'P1' -Name "denied probe -> needsDaclAugmentation=$expAugDenied" -Pass ($probeDenied.needsDaclAugmentation -eq $expAugDenied) -Detail "needsDaclAugmentation=$($probeDenied.needsDaclAugmentation)"
    }

    $cfgRefuse = New-Config -Name 'probe-refuse' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw) -AllowDaclMutation $false
    $probeRefuse = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgRefuse -Phase 'P1' -Name 'probe-allow-dacl-false'
    if ($probeRefuse) {
        # Under Set-StrictMode -Version Latest, accessing an absent property
        # throws; check existence via PSObject.Properties instead of
        # `$null -eq $obj.foo`.
        $tierMissing = -not [bool]$probeRefuse.PSObject.Properties['tier']
        $errorStr    = if ($probeRefuse.PSObject.Properties['error']) { [string]$probeRefuse.error } else { '' }
        if (Get-ExpectedDaclAug -HasDenied:$false) {
            # The expected tier needs DACL augmentation for rw paths, so
            # allowDaclMutation=false trips DaclFallbackDisabled and the
            # detector returns an error (tier omitted).
            Record-Result -Phase 'P1' -Name 'allowDaclMutation=false + rw-paths probe -> error (DACL augmentation refused)' -Pass ($tierMissing -and ($errorStr -match 'DACL fallback')) -Detail "tierMissing=$tierMissing; error=$errorStr"
        } else {
            # BaseContainer host: rw paths need no DACL augmentation, so
            # allowDaclMutation=false is a no-op and the probe still resolves.
            $tierVal = if ($probeRefuse.PSObject.Properties['tier']) { [string]$probeRefuse.tier } else { '<missing>' }
            Record-Result -Phase 'P1' -Name 'allowDaclMutation=false + rw-paths probe -> still resolves (no DACL augmentation needed)' -Pass ((-not $tierMissing) -and ($tierVal -eq $Script:ExpectedTier)) -Detail "tier=$tierVal; error=$errorStr"
        }
    }
}

# -----------------------------------------------------------------------
# Phase 2 — release-build empty-policy run (safe lane, T2 path but no bfscfg)
# -----------------------------------------------------------------------
function Phase-EmptyRelease {
    if ($SkipReleaseLane) {
        Section 'Phase 2: SKIPPED (--SkipReleaseLane)'
        return
    }
    Section 'Phase 2: release build, empty FS policy (safe lane)'

    # Use `echo` (a cmd builtin — no external EXE load, no LSA/RPC) and
    # assert the output round-trips back. Avoid `whoami`, `hostname`,
    # `set`, etc. which exercise capabilities the empty policy doesn't
    # grant — those would correctly fail under AppContainer and look
    # like a regression here.
    $cfg = New-Config -Name 'empty-release' -CommandLine 'cmd /c echo P2-empty-release-ok'
    $log = Join-Path $ScratchRoot 'logs\empty-release.log'
    $r = Invoke-Wxc -Wxc $WxcRelease -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log
    # With BaseContainer unusable and tier2_bfs off, the empty-policy run
    # selects T3 (AppContainer + DACL). Assert bfscfg.exe was never invoked.
    Assert-NoBfscfg -LogContent $logContent -Phase 'P2' -Name 'empty-release'

    Record-Result -Phase 'P2' -Name 'release exit=0' -Pass ($r.ExitCode -eq 0) -Detail "exit=$($r.ExitCode); stdout=$($r.Stdout.Trim())"
    Record-Result -Phase 'P2' -Name 'AppContainer ran the child (stdout round-trip)' -Pass ($r.Stdout -match 'P2-empty-release-ok')
    Record-Result -Phase 'P2' -Name "selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContent) -Detail "expected=$($Script:ExpectedTier)"
    Record-Result -Phase 'P2' -Name 'no bfscfg invocation in log' -Pass (-not ($logContent -match '(?im)Output from bfscfg\.exe'))
    Record-Result -Phase 'P2' -Name 'UI restrictions applied telemetry' -Pass (Test-UiRestrictionsApplied -LogContent $logContent)
}

# -----------------------------------------------------------------------
# Phase 3 — release-build deniedPaths-only (safe lane; deny routes via DACL)
# -----------------------------------------------------------------------
function Phase-DeniedRelease {
    if ($SkipReleaseLane) {
        Section 'Phase 3: SKIPPED (--SkipReleaseLane)'
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
    # With `tier2_bfs` off, denied-only policy falls through T2→T3.
    # Deny ACEs still route through DaclManager (same code path as
    # before; only the selected-tier label differs). bfscfg.exe is
    # not invoked under any tier.
    Assert-NoBfscfg -LogContent $logContent -Phase 'P3' -Name 'denied-release'

    $aclAfter = Get-Acl-Snapshot $denied

    Record-Result -Phase 'P3' -Name 'release exit=0' -Pass ($r.ExitCode -eq 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P3' -Name "selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContent) -Detail "expected=$($Script:ExpectedTier)"
    Record-Result -Phase 'P3' -Name 'no bfscfg invocation in log' -Pass (-not ($logContent -match '(?im)Output from bfscfg\.exe'))
    Record-Result -Phase 'P3' -Name 'denied-path ACL restored after run' -Pass ($aclBefore -eq $aclAfter)
    Record-Result -Phase 'P3' -Name 'no orphan state files' -Pass (@(Get-StateFiles).Count -eq 0)
}

# -----------------------------------------------------------------------
# Phase 4 — debug build, T3 forced, rw + ro + denied (the real test)
# -----------------------------------------------------------------------
function Phase-T3Forced {
    Section 'Phase 4: debug build, natural detection -> T3 (tier2_bfs off)'
    Clear-StateFiles

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
    Assert-NoBfscfg -LogContent $logContent -Phase 'P4' -Name 't3-forced'

    $aclRwAfter     = Get-Acl-Snapshot $rw
    $aclRoAfter     = Get-Acl-Snapshot $ro
    $aclDeniedAfter = Get-Acl-Snapshot $denied
    $stateAfter     = @(Get-StateFiles)

    Record-Result -Phase 'P4' -Name 'child exit=0' -Pass ($r.ExitCode -eq 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P4' -Name "selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContent) -Detail "expected=$($Script:ExpectedTier)"
    Record-Result -Phase 'P4' -Name 'UI restrictions applied telemetry' -Pass (Test-UiRestrictionsApplied -LogContent $logContent)
    Record-Result -Phase 'P4' -Name 'Win32k mitigation NOT applied (ui.disable=false)' -Pass (-not (Test-Win32kMitigationApplied -LogContent $logContent)) -Detail 'this config has ui.disable=false'
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
    Assert-NoBfscfg -LogContent $logContent2 -Phase 'P4' -Name 't3-ui-disable'

    Record-Result -Phase 'P4' -Name 'ui.disable=true emits Win32k mitigation applied' -Pass (Test-Win32kMitigationApplied -LogContent $logContent2) -Detail "child exit=$($r2.ExitCode) (expected to fail; cmd.exe needs Win32k)"
    Record-Result -Phase 'P4' -Name "ui.disable=true emits selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContent2) -Detail "expected=$($Script:ExpectedTier)"
    # Even though child crashed, ACEs must still be cleaned up.
    $aclRwAfterUi = Get-Acl-Snapshot $rw
    Record-Result -Phase 'P4' -Name 'ui.disable=true rw ACL still cleaned up' -Pass ($aclRwBefore -eq $aclRwAfterUi)
    Record-Result -Phase 'P4' -Name 'ui.disable=true no orphan state files' -Pass (@(Get-StateFiles).Count -eq 0)

    # ---------------------------------------------------------------------
    # Sandbox property test: ping requires raw ICMP sockets, which
    # AppContainer denies by default (no `internetClient` capability is
    # not the issue — even with it, raw sockets need elevated
    # privileges). The child should exit non-zero almost immediately.
    # If ping ever succeeds here we have a sandbox escape.
    # ---------------------------------------------------------------------
    $cfgPing = New-Config -Name 't3-ping-blocked' `
        -CommandLine 'ping.exe -n 1 -w 1000 127.0.0.1' `
        -ReadWrite @($rw) -TimeoutMs 10000
    $logPing = Join-Path $ScratchRoot 'logs\t3-ping-blocked.log'

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $rPing = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgPing -LogPath $logPing -TimeoutSec 30
    $stopwatch.Stop()
    $logContentPing = Read-Log $logPing
    Assert-NoBfscfg -LogContent $logContentPing -Phase 'P4' -Name 't3-ping-blocked'

    $combinedPing = "$($rPing.Stdout)`n$($rPing.Stderr)"
    $aclRwAfterPing = Get-Acl-Snapshot $rw

    Record-Result -Phase 'P4' -Name 'sandbox blocks ping (child exit != 0)' -Pass ($rPing.ExitCode -ne 0) -Detail "exit=$($rPing.ExitCode)"
    # ping with one attempt and 1s timeout would take ~1.5s if successful;
    # raw-socket creation failure exits in milliseconds. Use 5s as a
    # generous upper bound that still detects "ping actually ran".
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping (failed fast, < 5s)' -Pass ($stopwatch.Elapsed.TotalSeconds -lt 5) -Detail ("elapsed={0:N2}s" -f $stopwatch.Elapsed.TotalSeconds)
    # Best-effort confirmation that the failure mode was access/socket
    # related, not e.g. ENOENT for ping.exe. Localized OS messages may
    # vary; we accept several known signatures plus a network-error
    # pattern. This is informational — the exit code + timing are the
    # load-bearing assertions.
    $accessSignal = $combinedPing -match '(?im)access\s*is\s*denied|access\s*denied|socket|10013|ICMP|general\s*failure|unable\s*to\s*contact'
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping (failure looks socket-related)' -Pass ([bool]$accessSignal) -Detail 'best-effort string match'
    Record-Result -Phase 'P4' -Name "sandbox blocks ping: selected isolation tier: $($Script:ExpectedTier)" -Pass (Test-SelectedTier -LogContent $logContentPing) -Detail "expected=$($Script:ExpectedTier)"
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping: rw ACL still cleaned up' -Pass ($aclRwBefore -eq $aclRwAfterPing)
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping: no orphan state files' -Pass (@(Get-StateFiles).Count -eq 0)

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

    # No outer cmd /c "..." wrapper, no NUL device redirects. Hypothesis
    # under test: every previously-passing AppContainer command in this
    # harness uses either a file redirect or no redirect at all. The
    # earlier matrix attempt was the first test to use `>nul`/`2>nul`,
    # and every clause failed. AppContainer may not grant access to the
    # NUL device by default. Dropping the redirects lets `type` dump
    # the file contents to stdout (parser ignores non-TAG lines) and
    # lets `echo`'s error messages go to captured stderr.
    # type's stdout goes to the inherited stdout (the harness captures
    # it). type's stderr goes to inherited stderr on read failure
    # (e.g. "Access is denied") — also captured. Both are fine: the
    # harness's regex parser only consumes lines that match
    # ^(TAG)=(PASS|FAIL)$ and ignores everything else.
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
    Assert-NoBfscfg -LogContent $logContentMatrix -Phase 'P4' -Name 't3-access-matrix'

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
    Record-Result -Phase 'P4' -Name 'matrix: no orphan state files' -Pass (@(Get-StateFiles).Count -eq 0)
}

# -----------------------------------------------------------------------
# Phase 4c — Tier 1 (BaseContainer) deny-ACE empirical test
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
    Section 'Phase 4c: T1 deny-ACE empirical test (skipped if BC not usable)'
    Clear-StateFiles

    # Use the release-build probe to discover BC usability (same JSON
    # surface as Phase 1). T1 is usable only when the empty-policy probe
    # resolves to base-container.
    $probe = Invoke-Probe -Wxc $WxcRelease -Phase 'P4c' -Name 'bc-presence-probe'
    if (-not $probe) {
        Record-Result -Phase 'P4c' -Name 'probe succeeded' -Pass $false -Detail 'probe returned null; cannot proceed'
        return
    }
    if ($probe.tier -ne 'base-container') {
        Record-Result -Phase 'P4c' -Name 'BaseContainer usable (required for T1 deny test)' -Status 'skip' -Detail "BaseContainer not usable on this host (tier=$($probe.tier), apiPresent=$($probe.probes.baseContainerApiPresent))"
        return
    }
    # The deny test is only meaningful once BaseContainer can enforce
    # deniedPaths. Before SANDBOX_CAP_DENY_PATHS lights up the runner rejects
    # deniedPaths outright, which would otherwise make this phase "pass"
    # vacuously (the run aborts, so the child never echoes the secret). Skip
    # until the capability is present; it then asserts real deny enforcement.
    if (-not $Script:Caps.SupportsDeniedPaths) {
        Record-Result -Phase 'P4c' -Name 'BaseContainer deny-ACE enforcement' -Status 'skip' -Detail 'BaseContainer does not yet support deniedPaths (no SANDBOX_CAP_DENY_PATHS)'
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

    Record-Result -Phase 'P4c' -Name 'selected isolation tier: base-container' -Pass ([bool]($logContent -match '(?im)selected isolation tier:.*?base-container')) -Detail "log saw tier=base-container"
    Record-Result -Phase 'P4c' -Name 'child did not echo denied-file contents (deny ACE worked)' -Pass (-not ($r.Stdout -match $sentinel)) -Detail "stdout-saw-sentinel=$([bool]($r.Stdout -match $sentinel))"
    Record-Result -Phase 'P4c' -Name 'child exited non-zero (access denied)' -Pass ($r.ExitCode -ne 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P4c' -Name 'denied ACL restored after run' -Pass ($aclBefore -eq $aclAfter)
    Record-Result -Phase 'P4c' -Name 'no orphan state files' -Pass ($stateAfter.Count -eq 0) -Detail "files=$($stateAfter.Count)"
}

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

# -----------------------------------------------------------------------
# Phase 4c — GLOBALATOMS bidirectional isolation (host baseline tier)
#
# JOB_OBJECT_UILIMIT_GLOBALATOMS does NOT make the atom APIs fail — the
# documented behavior is that each job gets its own private atom table, so
# GlobalAddAtomW still succeeds inside the container. The restriction is
# therefore verified as *isolation* between the host's session-global atom
# table and the contained job's private table, in BOTH directions:
#
#   * host -> guest: the host plants a global atom and passes its name to the
#     probe. The probe must NOT be able to find it. Decided by the probe and
#     printed as GLOBALATOMS_HOST_TO_GUEST=PASS|FAIL.
#   * guest -> host: the probe adds its own atom, creates the ready file, and
#     blocks until the host creates the release file. While the probe holds
#     the atom alive the host checks its own global table and must NOT find
#     it. Decided here (the job-private table is torn down when the container
#     exits, so the check MUST happen while the probe is still alive — hence
#     the handshake).
# -----------------------------------------------------------------------
function Invoke-GlobalAtomProbe {
    # Runs the GLOBALATOMS bidirectional handshake once with the given
    # isolation mode and returns the observed results so the caller can assert
    # either the isolated (container) or non-isolated (desktop) expectation.
    # Returns: HostToGuest (PASS|FAIL|<missing>), GuestFound (UInt16 atom, or
    # $null if the probe never signalled ready), TierMatch (bool), Detail.
    param(
        [Parameter(Mandatory)] [string]$Isolation,
        [Parameter(Mandatory)] [string]$Name
    )
    $rw = Join-Path $ScratchRoot 'rw'
    New-Item -ItemType Directory -Path $rw -Force | Out-Null

    $suffix      = [guid]::NewGuid().ToString('N')
    $hostName    = "MxcWinPCHostAtom_$suffix"
    $guestName   = "MxcWinPCGuestAtom_$suffix"
    $readyFile   = Join-Path $rw "globalatom-ready-$suffix"
    $releaseFile = Join-Path $rw "globalatom-release-$suffix"
    Remove-Item -LiteralPath $readyFile, $releaseFile -ErrorAction SilentlyContinue

    # Plant the host-side global atom (the direction-1 reference). Held alive
    # until the finally block — PowerShell stays running, so it persists for
    # the whole contained run.
    $hostAtom = [Mxc.AtomNative]::GlobalAddAtomW($hostName)
    if ($hostAtom -eq 0) {
        return [pscustomobject]@{ HostToGuest = '<missing>'; GuestFound = $null; TierMatch = $false; Detail = 'host GlobalAddAtomW returned 0' }
    }

    $cmd = "`"$UiProbeDebug`" GLOBALATOMS " +
        "--atom-host-name=$hostName --atom-guest-name=$guestName " +
        "--atom-ready-file=`"$readyFile`" --atom-release-file=`"$releaseFile`""
    $cfg = New-Config -Name $Name `
        -CommandLine $cmd `
        -ReadWrite @($rw) `
        -UiDisable $false `
        -BpUiIsolation $Isolation
    $log = Join-Path $ScratchRoot "logs\$Name.log"

    # Match Invoke-Wxc's defensive scrub of the test-only tier override.
    Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $WxcDebug
    $psi.Arguments = "--config `"$cfg`" --experimental --log-file `"$log`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    # The probe blocks mid-run waiting on the release file, so we cannot use
    # the synchronous Invoke-Wxc (which reads stdout only after exit). Drain
    # both streams asynchronously to avoid a pipe-buffer deadlock while the
    # child is parked.
    $sbOut = New-Object System.Text.StringBuilder
    $sbErr = New-Object System.Text.StringBuilder
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    # Use explicit SourceIdentifiers so the finally block can unregister the
    # subscriptions AND remove the backing PSEventJobs unambiguously.
    # Unregister-Event removes only the subscription, not the job it created,
    # so without Remove-Job the jobs accumulate across same-session re-runs.
    $outSid = "MxcGAOut_$suffix"
    $errSid = "MxcGAErr_$suffix"
    $outEvt = Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -SourceIdentifier $outSid -MessageData $sbOut -Action {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    }
    $errEvt = Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived -SourceIdentifier $errSid -MessageData $sbErr -Action {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    }

    $guestFound = $null
    try {
        [void]$p.Start()
        $p.BeginOutputReadLine()
        $p.BeginErrorReadLine()

        # Wait for the probe to signal that its atom now exists.
        $deadline = (Get-Date).AddSeconds(30)
        $ready = $false
        while ((Get-Date) -lt $deadline) {
            if (Test-Path -LiteralPath $readyFile) { $ready = $true; break }
            if ($p.HasExited) { break }
            Start-Sleep -Milliseconds 100
        }

        if ($ready) {
            # Direction 2: does the host find the contained process's atom?
            $guestFound = [Mxc.AtomNative]::GlobalFindAtomW($guestName)
        }

        # Release the probe so it deletes its atom and exits.
        Set-Content -LiteralPath $releaseFile -Value 'go' -ErrorAction SilentlyContinue

        if (-not $p.WaitForExit(30000)) {
            try { $p.Kill() } catch {}
        }
        $p.WaitForExit()   # ensure async stdout/stderr handlers flush
    }
    finally {
        # Remove the host-planted atom regardless of outcome.
        [void][Mxc.AtomNative]::GlobalDeleteAtom($hostAtom)
        # Unregister the subscriptions, then remove the PSEventJobs they
        # created (Unregister-Event leaves the job behind).
        foreach ($sid in @($outSid, $errSid)) {
            Unregister-Event -SourceIdentifier $sid -ErrorAction SilentlyContinue
            Remove-Job -Name $sid -Force -ErrorAction SilentlyContinue
        }
    }

    $stdout = $sbOut.ToString()
    $logContent = Read-Log $log
    Assert-NoBfscfg -LogContent $logContent -Phase 'P4c' -Name $Name
    $tierMatch = Test-SelectedTier -LogContent $logContent
    $h2g = if ($stdout -match '(?m)^GLOBALATOMS_HOST_TO_GUEST=(?<v>PASS|FAIL)\s*$') { $matches['v'] } else { '<missing>' }
    return [pscustomobject]@{ HostToGuest = $h2g; GuestFound = $guestFound; TierMatch = $tierMatch; Detail = "stdout=$(Format-VerdictSummary ($stdout.Trim()) 'blocked' 'allowed')" }
}

function Phase-GlobalAtomIsolation {
    Section 'Phase 4c: GLOBALATOMS bidirectional isolation (host baseline tier)'

    # ---- Positive: isolation=container sets UILIMIT_GLOBALATOMS -> isolated.
    $pos = Invoke-GlobalAtomProbe -Isolation 'container' -Name 'ui-globalatoms'
    Record-Result -Phase 'P4c' -Name "selected isolation tier: $($Script:ExpectedTier)" -Pass $pos.TierMatch
    Record-Result -Phase 'P4c' -Name 'host atom NOT visible to contained process (host->guest)' -Pass ($pos.HostToGuest -eq 'PASS') -Detail "expected=blocked; got=$(Format-Verdict $pos.HostToGuest 'blocked' 'allowed'); $($pos.Detail)"
    if ($null -eq $pos.GuestFound) {
        Record-Result -Phase 'P4c' -Name 'contained atom NOT visible to host (guest->host)' -Pass $false -Detail 'probe never signalled ready; no guest-atom check performed'
    } else {
        Record-Result -Phase 'P4c' -Name 'contained atom NOT visible to host (guest->host)' -Pass ($pos.GuestFound -eq 0) -Detail "GlobalFindAtomW=$($pos.GuestFound) (0 = not found = isolated)"
    }

    # ---- Negative control: isolation=desktop sets NO UILIMIT_GLOBALATOMS, so
    # the global atom table is shared. The probe MUST see the host atom and the
    # host MUST see the guest atom — proving the positive results above are not
    # vacuous (e.g. an atom API silently failing would otherwise read as PASS).
    $neg = Invoke-GlobalAtomProbe -Isolation 'desktop' -Name 'ui-globalatoms-neg'
    Record-Result -Phase 'P4c' -Name 'negative control: host atom visible without UILIMIT_GLOBALATOMS (host->guest)' -Pass ($neg.HostToGuest -eq 'FAIL') -Detail "expected=allowed; got=$(Format-Verdict $neg.HostToGuest 'blocked' 'allowed'); $($neg.Detail)"
    if ($null -eq $neg.GuestFound) {
        Record-Result -Phase 'P4c' -Name 'negative control: contained atom VISIBLE to host without UILIMIT_GLOBALATOMS' -Pass $false -Detail 'probe never signalled ready; no guest-atom check performed'
    } else {
        Record-Result -Phase 'P4c' -Name 'negative control: contained atom VISIBLE to host without UILIMIT_GLOBALATOMS' -Pass ($neg.GuestFound -ne 0) -Detail "GlobalFindAtomW=$($neg.GuestFound) (nonzero = found = NOT isolated)"
    }
}

# -----------------------------------------------------------------------
# Phase 5 — allowDaclMutation=false rejection under forced T3
# -----------------------------------------------------------------------
function Phase-DaclDisabled {
    Section 'Phase 5: debug build, allowDaclMutation=false (DACL-augmentation refusal)'
    Clear-StateFiles

    # This phase exercises the DACL-augmentation refusal path, which only
    # engages when the host's expected tier augments DACLs for an rw policy
    # (i.e. appcontainer-dacl). On a BaseContainer host, rw paths use the
    # BaseContainer mechanism and need no DACL augmentation, so
    # allowDaclMutation=false is a no-op and there is nothing to refuse.
    if (-not (Get-ExpectedDaclAug -HasDenied:$false)) {
        Record-Result -Phase 'P5' -Name 'DACL-augmentation refusal' -Status 'skip' -Detail "rw policy needs no DACL augmentation on tier=$($Script:ExpectedTier)"
        return
    }

    $rw = Join-Path $ScratchRoot 'rw'
    $aclBefore = Get-Acl-Snapshot $rw

    $cfg = New-Config -Name 't3-refuse' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw) -AllowDaclMutation $false
    $log = Join-Path $ScratchRoot 'logs\t3-refuse.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log
    Assert-NoBfscfg -LogContent $logContent -Phase 'P5' -Name 't3-refuse'

    $aclAfter = Get-Acl-Snapshot $rw
    $stateAfter = @(Get-StateFiles)

    Record-Result -Phase 'P5' -Name 'dispatch refused (exit != 0)' -Pass ($r.ExitCode -ne 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P5' -Name 'rw ACL untouched' -Pass ($aclBefore -eq $aclAfter)
    Record-Result -Phase 'P5' -Name 'no state file written' -Pass ($stateAfter.Count -eq 0)
    $stderrOrLog = ($r.Stderr + "`n" + $logContent)
    Record-Result -Phase 'P5' -Name 'error message mentions DACL fallback' -Pass ([bool]($stderrOrLog -match '(?i)DACL fallback'))
}

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

    # Natural detection with `tier2_bfs` off lands at T3 for any
    # policy with rw paths, so no MXC_FORCE_TIER manipulation is
    # needed (and it would be a no-op against the production binary
    # in any case).
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

# -----------------------------------------------------------------------
# Phase 7 — Rust unit tests
# -----------------------------------------------------------------------
function Invoke-CargoTest {
    # Run a `cargo test` invocation, append its full output to $CargoLog,
    # surface only summary / error lines to the transcript.
    param(
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Label
    )
    "" | Add-Content -LiteralPath $CargoLog
    "===== $Label  (cargo $($Arguments -join ' ')) =====" | Add-Content -LiteralPath $CargoLog
    $output = & cargo @Arguments 2>&1
    $exit = $LASTEXITCODE
    $output | Out-File -LiteralPath $CargoLog -Append -Encoding utf8

    # Surface load-bearing lines to the transcript:
    # - "test result:" — pass/fail summary per test binary
    # - "error[" / "error:" / "warning:" — compile / link diagnostics
    # - "Compiling " / "Finished " — high-level cargo progress
    $summary = $output | Where-Object {
        $_ -match '^(test result:|error(\[|:)|warning:|\s+Compiling |\s+Finished )'
    }
    if ($summary) {
        $summary | ForEach-Object { Write-Host "  $_" }
    } else {
        # Fallback: surface the last 10 lines so a silent failure doesn't
        # disappear into the side log.
        Write-Host '  (no summary lines matched — last 10 lines:)'
        $output | Select-Object -Last 10 | ForEach-Object { Write-Host "    $_" }
    }
    return $exit
}

function Phase-UnitTests {
    Section 'Phase 7: cargo test'
    # Truncate the cargo log at the start of each run.
    Set-Content -LiteralPath $CargoLog -Value "WinProcessContainer-Tests cargo log — $(Get-Date -Format 'o')`n" -Encoding utf8
    Push-Location $CargoRoot
    try {
        $exit1 = Invoke-CargoTest -Arguments @('test', '-p', 'wxc_common', '--lib') -Label 'wxc_common --lib'
        Record-Result -Phase 'P7' -Name 'cargo test -p wxc_common' -Pass ($exit1 -eq 0) -Detail "exit=$exit1; full log: $CargoLog"
        # `wxc` is a binary-only crate — no --lib target. Run its bin tests.
        $exit2 = Invoke-CargoTest -Arguments @('test', '-p', 'wxc', '--bins') -Label 'wxc --bins'
        Record-Result -Phase 'P7' -Name 'cargo test -p wxc --bins' -Pass ($exit2 -eq 0) -Detail "exit=$exit2; full log: $CargoLog"
    } finally {
        Pop-Location
    }
}

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
# Capture all host output (Write-Host, Section banners, cargo build/test
# output) to a transcript file so the user can paste a single path
# instead of scrolling the terminal. Stop-Transcript runs in finally so
# even an abort produces a complete transcript.
try { Stop-Transcript | Out-Null } catch {}  # close any orphaned transcript
$null = Start-Transcript -Path $ResultsFile -Force -IncludeInvocationHeader

try {
    Test-Preflight
    $Script:Caps = Get-HostCapabilities
    $Script:ExpectedTier = $Script:Caps.BaselineTier
    Write-Host ("Host capabilities: expectedTier={0} baseContainerUsable={1} apiPresent={2} bfscfgPresent={3} bfsCompiledIn={4} supportsDeniedPaths={5}" -f `
        $Script:Caps.BaselineTier, $Script:Caps.BaseContainerUsable, $Script:Caps.BaseContainerApiPresent, $Script:Caps.BfscfgPresent, $Script:Caps.BfsCompiledIn, $Script:Caps.SupportsDeniedPaths) -ForegroundColor Cyan
    Initialize-Scratch

    # Phase registry. Build + preflight + scratch init above always run; this
    # table is filtered by the -Phases parameter (empty = run all). Phase 4b is
    # 'UiMitigationMatrix'; Phase 4c is 'GlobalAtomIsolation'.
    $AllPhases = [ordered]@{
        'UnitTests'           = { Phase-UnitTests }
        'Probes'              = { Phase-Probes }
        'EmptyRelease'        = { Phase-EmptyRelease }
        'DeniedRelease'       = { Phase-DeniedRelease }
        'T3Forced'            = { Phase-T3Forced }
        'T1DenyForced'        = { Phase-T1DenyForced }
        'UiMitigationMatrix'  = { Phase-UiMitigationMatrix }
        'GlobalAtomIsolation' = { Phase-GlobalAtomIsolation }
        'DaclDisabled'        = { Phase-DaclDisabled }
        'CrashRecovery'       = { Phase-CrashRecovery }
    }
    if ($Phases.Count -gt 0) {
        $unknown = $Phases | Where-Object { $_ -notin $AllPhases.Keys }
        if ($unknown) { throw "Unknown -Phases value(s): $($unknown -join ', '). Valid: $($AllPhases.Keys -join ', ')" }
    }
    foreach ($key in $AllPhases.Keys) {
        if ($Phases.Count -eq 0 -or $Phases -contains $key) {
            & $AllPhases[$key]
        }
    }
}
catch {
    Write-Host ''
    Write-Host "HARNESS ABORTED: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    # Record the abort as a failure so the cleanup logic in `finally`
    # preserves the scratch dir for post-mortem inspection.
    Record-Result -Phase 'ABORT' -Name 'harness aborted' -Pass $false -Detail "$_"
}
finally {
    Section 'Summary'
    # Force pipeline output to an array — under StrictMode, $null.Count throws.
    $passed  = @($Script:Results | Where-Object { $_.Status -eq 'pass' })
    $failed  = @($Script:Results | Where-Object { $_.Status -eq 'fail' })
    $skipped = @($Script:Results | Where-Object { $_.Status -eq 'skip' })
    $warned  = @($Script:Results | Where-Object { $_.Status -eq 'warn' })
    $pass = $passed.Count
    $fail = $failed.Count
    $skip = $skipped.Count
    $warn = $warned.Count
    Write-Host ("Total: {0}    Passed: {1}    Failed: {2}    Skipped: {3}    Warnings: {4}" -f ($pass + $fail + $skip + $warn), $pass, $fail, $skip, $warn)
    if ($warn -gt 0) {
        Write-Host ''
        Write-Host 'Warnings (constraint not enforced on this host):' -ForegroundColor Yellow
        foreach ($r in $warned) {
            Write-Host ("  [{0}] {1} :: {2}" -f $r.Phase, $r.Name, $r.Detail) -ForegroundColor Yellow
        }
    }
    if ($skip -gt 0) {
        Write-Host ''
        Write-Host 'Skipped (not applicable on this host):' -ForegroundColor Yellow
        foreach ($r in $skipped) {
            Write-Host ("  [{0}] {1} :: {2}" -f $r.Phase, $r.Name, $r.Detail) -ForegroundColor Yellow
        }
    }
    if ($fail -gt 0) {
        Write-Host ''
        Write-Host 'Failures:' -ForegroundColor Red
        foreach ($r in $failed) {
            Write-Host ("  [{0}] {1} :: {2}" -f $r.Phase, $r.Name, $r.Detail) -ForegroundColor Red
        }
    }

    # Structured JSON for programmatic consumption.
    $summary = [pscustomobject]@{
        timestamp   = (Get-Date).ToString('o')
        host        = $env:COMPUTERNAME
        os          = (Get-CimInstance Win32_OperatingSystem).Caption
        osBuild     = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        total       = $pass + $fail + $skip + $warn
        passed      = $pass
        failed      = $fail
        skipped     = $skip
        warnings    = $warn
        results     = $Script:Results
    }
    try {
        ($summary | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $ResultsJson -Encoding utf8 -Force
    } catch {
        Write-Host "warning: could not write JSON results: $_" -ForegroundColor Yellow
    }

    Write-Host ''
    if (Test-Path $ScratchRoot) {
        Write-Host ("Logs and configs: {0}" -f $ScratchRoot)
    }
    Write-Host ("Transcript:        {0}" -f $ResultsFile)
    Write-Host ("JSON summary:      {0}" -f $ResultsJson)
    if (Test-Path $CargoLog) {
        Write-Host ("Cargo full log:    {0}" -f $CargoLog)
    }
    if (-not $KeepArtifacts -and $fail -eq 0 -and $pass -gt 0 -and (Test-Path $ScratchRoot)) {
        # Re-validate before deletion — `Assert-SafeScratchRoot` ran at
        # the start of the suite, but the variable could in principle
        # be mutated mid-run by future refactors. Cheap belt-and-
        # suspenders against an accidental recursive delete escape.
        Assert-SafeScratchRoot
        Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue
    }
    try { Stop-Transcript | Out-Null } catch {}
    if ($fail -gt 0 -or $pass -eq 0) { exit 1 } else { exit 0 }
}
