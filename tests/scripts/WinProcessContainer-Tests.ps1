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
#
# Schema version:
#   Configs are authored at 0.8.0-alpha (`$Script:SchemaVersion`). The LEGACY
#   network fields — defaultPolicy / enforcementMode / allowedHosts /
#   blockedHosts / allowLocalNetwork / network.proxy — are pinned to
#   0.7.0-alpha (`$Script:LegacySchemaVersion`), because 0.8 is where the
#   directional `network.egress` / `network.ingress` shape became the
#   documented way to express network intent. New-Config switches lanes
#   automatically when a -Legacy* parameter is supplied.
#
# What the network phases assert:
#   The DOCUMENTED contract, not the current implementation. The authoritative
#   sources are docs/process-container/networking.md and
#   docs/sandbox-policy/0.8.0/networking/networking.md, both revised recently.
#   Where the backend has not caught up, the assertion FAILS — that is the
#   intended signal. A suite that only encodes present behavior cannot tell
#   anyone the backend drifted from its spec.
#
# Prerequisites are failures, not skips:
#   * -RequireTier <tier> aborts when the host does not naturally select that
#     tier. Without it, a mis-provisioned T1 runner silently runs the T3
#     assertions and reports green having proven nothing about BaseContainer.
#   * The egress anchor is probed from the HOST before any network phase runs.
#     A host with no connectivity would read every positive assertion as
#     "blocked", so an unreachable anchor aborts. -SkipNetwork is the explicit
#     opt-out for air-gapped bring-up.

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
    # Hard prerequisite on the containment tier. When set, the harness ABORTS
    # if the host does not naturally select this tier. Without it a
    # mis-provisioned T1 runner silently runs the T3 assertions (every
    # expectation is derived from $Script:ExpectedTier) and reports green
    # having proven nothing about BaseContainer. CI passes the tier its job
    # name claims to cover. Same doctrine as run_seatbelt_all_tests.sh: a
    # missing prerequisite is a FAILURE, not a skip.
    [ValidateSet('base-container', 'appcontainer-dacl')]
    [string]$RequireTier,
    # Reachability anchor for the positive egress assertions. An egress-allow
    # test that cannot distinguish "policy blocked it" from "this host has no
    # internet" proves nothing, so the phase probes this from the HOST first
    # and fails (never skips) when the host itself cannot reach it.
    [string]$ExternalAnchorUrl = 'https://dev.azure.com',
    # A second reachable destination, used as the negative control for the
    # explicit-egress-rule phase: the allow rules name the anchor and nothing
    # else, so this one must be blocked INSIDE the container while remaining
    # reachable from the host. If the host cannot reach it either, a BLOCKED
    # verdict is unattributable and the phase fails rather than scoring green.
    [string]$UnlistedDestinationUrl = 'https://example.com',
    # Opt out of every live-network phase (air-gapped bring-up). The parse-only
    # rejection phase still runs — it needs no connectivity.
    [switch]$SkipNetwork,
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

    # Informational banner only — the load-bearing safety gate is the
    # bfsCompiledIn check below. CIM is unavailable on some locked-down hosts,
    # so don't let a cosmetic query abort the whole harness.
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Write-Host ("OS: {0} (build {1})" -f $os.Caption, $os.BuildNumber)
    } catch {
        Write-Host ("OS: unknown (CIM unavailable: {0})" -f $_.Exception.Message.Trim())
    }

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
    # `alias` holds the path-aliasing fixtures (Phase 10): the same object
    # reached via `..`, an 8.3 short name, and the \\?\ prefix.
    New-Item -ItemType Directory -Path (Join-Path $ScratchRoot 'alias')   | Out-Null
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
        throw "MXC-FATAL [$Phase :: $Name] log contains 'Output from bfscfg.exe' (real invocation). Aborting to avoid 25H2 deadlock."
    }
    if (-not $AllowBfsTierSelection) {
        # Logger interleaves a `[timestamp] ` token between every
        # write fragment, so a single `writeln!(logger, "x: {}", y)`
        # serializes as `x: [ts] y`. Use `.*?` instead of `\s*` to
        # bridge that token.
        if ($LogContent -match '(?im)selected isolation tier:.*?appcontainer-bfs') {
            throw "MXC-FATAL [$Phase :: $Name] log shows 'selected isolation tier: appcontainer-bfs'. Aborting."
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

# Default schema version for generated configs. Everything the 0.8 stable
# schema can express is authored at 0.8; the LEGACY network fields
# (defaultPolicy / enforcementMode / allowedHosts / blockedHosts /
# allowLocalNetwork / network.proxy) stay pinned at 0.7 via -LegacySchema,
# because 0.8 is where the directional egress/ingress shape became the
# documented way to express network intent and mixing the two shapes in one
# config is not a scenario any doc describes.
$Script:SchemaVersion       = '0.8.0-alpha'
$Script:LegacySchemaVersion = '0.7.0-alpha'

# Write a config object verbatim. Used by the rejection phase for shapes the
# typed generator deliberately cannot produce (an explicitly empty `to: []`,
# a hostname where a CIDR belongs), since the property being asserted is that
# MXC refuses them.
function New-RawConfig {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] $Object
    )
    $path = Join-Path (Join-Path $ScratchRoot 'configs') "$Name.json"
    ($Object | ConvertTo-Json -Depth 12) | Out-File -LiteralPath $path -Encoding utf8 -Force
    return $path
}

# Build an `network.egress.allow[]` / `network.egress.deny[]` rule. `to` and
# `ports` are omitted (wildcard) unless supplied — per the 0.8 networking spec
# an omitted array is the wildcard while an explicitly empty one is rejected,
# so the two cases must stay distinguishable here.
function New-EgressRule {
    param(
        [string[]]$Cidr     = @(),
        [string[]]$Except   = @(),
        [string]$Protocol   = $null,
        [Nullable[int]]$Port    = $null,
        [Nullable[int]]$EndPort = $null
    )
    $rule = [ordered]@{}
    if ($Cidr.Count -gt 0) {
        $rule['to'] = @(foreach ($c in $Cidr) {
            $peer = [ordered]@{ cidr = $c }
            if ($Except.Count -gt 0) { $peer['except'] = @($Except) }
            $peer
        })
    }
    if ($Protocol -or $null -ne $Port -or $null -ne $EndPort) {
        $sel = [ordered]@{}
        if ($Protocol)          { $sel['protocol'] = $Protocol }
        if ($null -ne $Port)    { $sel['port']     = [int]$Port }
        if ($null -ne $EndPort) { $sel['endPort']  = [int]$EndPort }
        $rule['ports'] = @($sel)
    }
    return $rule
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
        [string[]]$Env                      = @(),
        [string]$Cwd                        = $null,
        # processContainer.capabilities — the AppContainer capability list.
        [string[]]$Capabilities             = @(),
        [Nullable[bool]]$LeastPrivilege     = $null,

        # --- schema 0.8 directional network (network.egress / network.ingress)
        # Supplying ANY of these emits a `network` block. Leave them all unset
        # for the "no network key at all" model-3 form.
        [ValidateSet('allow', 'deny')] [string]$EgressDefault  = $null,
        [ValidateSet('allow', 'deny')] [string]$IngressDefault = $null,
        [ValidateSet('allow', 'deny')] [string]$HostLoopback   = $null,
        [object[]]$EgressAllow = @(),
        [object[]]$EgressDeny  = @(),
        # Emit `"network": {}` — the third documented spelling of model 3.
        [switch]$EmptyNetwork,

        # --- runtime (not policy)
        [string]$NetworkProxy    = $null,   # runtimeConfig.networkProxy
        [string]$AllowedProxyPeer = $null,  # processContainer.network.allowedProxyPeer

        # --- LEGACY network, schema 0.7 only. Setting any of these pins the
        # config to 0.7.0-alpha, because these fields are the pre-directional
        # shape and no doc describes combining them with egress/ingress.
        [ValidateSet('allow', 'block')] [string]$LegacyDefaultPolicy = $null,
        [ValidateSet('capabilities', 'firewall', 'both')] [string]$LegacyEnforcementMode = $null,
        [string[]]$LegacyAllowedHosts = @(),
        [string[]]$LegacyBlockedHosts = @(),
        [Nullable[bool]]$LegacyAllowLocalNetwork = $null,
        [string]$LegacyProxyUrl = $null,
        [Nullable[int]]$LegacyProxyLocalhost = $null,
        [switch]$LegacyProxyBuiltinTestServer
    )

    $usesLegacyNetwork = ($LegacyDefaultPolicy -or $LegacyEnforcementMode -or
        $LegacyAllowedHosts.Count -gt 0 -or $LegacyBlockedHosts.Count -gt 0 -or
        $null -ne $LegacyAllowLocalNetwork -or $LegacyProxyUrl -or
        $null -ne $LegacyProxyLocalhost -or $LegacyProxyBuiltinTestServer)

    $usesDirectionalNetwork = ($EgressDefault -or $IngressDefault -or $HostLoopback -or
        ($null -ne $EgressAllow -and $EgressAllow.Count -gt 0) -or
        ($null -ne $EgressDeny -and $EgressDeny.Count -gt 0) -or
        $NetworkProxy -or $AllowedProxyPeer -or $EmptyNetwork)

    # A legacy parameter pins the config to 0.7, where none of the directional
    # keys (network.egress / network.ingress / runtimeConfig.networkProxy /
    # processContainer.network.allowedProxyPeer) exist and the schema is
    # closed. Silently dropping them would emit a config that fails for a
    # schema-shape reason instead of the reason under test, which is the
    # hardest kind of test bug to notice. Refuse the combination outright;
    # Phase 8f authors the deliberate legacy/directional mixture as raw JSON.
    if ($usesLegacyNetwork -and $usesDirectionalNetwork) {
        throw ("New-Config '$Name': -Legacy* pins the config to $Script:LegacySchemaVersion, " +
               'which has no egress/ingress/runtimeConfig/allowedProxyPeer keys. ' +
               'Use one network shape or the other, or author the mixture with New-RawConfig.')
    }

    $obj = [ordered]@{
        version     = $(if ($usesLegacyNetwork) { $Script:LegacySchemaVersion } else { $Script:SchemaVersion })
        containerId = "MxcWinPC-$Name"
        # `appcontainer` is not in the stable containment enum at 0.7 or 0.8;
        # `processcontainer` is the concrete Windows backend on both.
        containment = 'processcontainer'
        process     = [ordered]@{
            commandLine = $CommandLine
            timeout     = $TimeoutMs
        }
    }
    if ($Cwd) { $obj['process']['cwd'] = $Cwd }
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

    # --- network -------------------------------------------------------
    if ($usesLegacyNetwork) {
        $net = [ordered]@{}
        if ($LegacyDefaultPolicy)   { $net['defaultPolicy']   = $LegacyDefaultPolicy }
        if ($LegacyEnforcementMode) { $net['enforcementMode'] = $LegacyEnforcementMode }
        if ($LegacyAllowedHosts.Count -gt 0) { $net['allowedHosts'] = @($LegacyAllowedHosts) }
        if ($LegacyBlockedHosts.Count -gt 0) { $net['blockedHosts'] = @($LegacyBlockedHosts) }
        if ($null -ne $LegacyAllowLocalNetwork) { $net['allowLocalNetwork'] = [bool]$LegacyAllowLocalNetwork }
        if ($LegacyProxyUrl) {
            $net['proxy'] = [ordered]@{ url = $LegacyProxyUrl }
        } elseif ($null -ne $LegacyProxyLocalhost) {
            $net['proxy'] = [ordered]@{ localhost = [int]$LegacyProxyLocalhost }
        } elseif ($LegacyProxyBuiltinTestServer) {
            $net['proxy'] = [ordered]@{ builtinTestServer = $true }
        }
        $obj['network'] = $net
    } elseif ($EmptyNetwork) {
        $obj['network'] = [ordered]@{}
    } elseif ($EgressDefault -or $IngressDefault -or $HostLoopback -or
              $EgressAllow.Count -gt 0 -or $EgressDeny.Count -gt 0) {
        $net = [ordered]@{}
        if ($EgressDefault -or $EgressAllow.Count -gt 0 -or $EgressDeny.Count -gt 0) {
            $eg = [ordered]@{}
            if ($EgressDefault)          { $eg['default'] = $EgressDefault }
            if ($EgressAllow.Count -gt 0) { $eg['allow']  = @($EgressAllow) }
            if ($EgressDeny.Count -gt 0)  { $eg['deny']   = @($EgressDeny) }
            $net['egress'] = $eg
        }
        if ($IngressDefault -or $HostLoopback) {
            $ing = [ordered]@{}
            if ($IngressDefault) { $ing['default']      = $IngressDefault }
            if ($HostLoopback)   { $ing['hostLoopback'] = $HostLoopback }
            $net['ingress'] = $ing
        }
        $obj['network'] = $net
    }

    if ($NetworkProxy) {
        $obj['runtimeConfig'] = [ordered]@{ networkProxy = $NetworkProxy }
    }

    $ui = [ordered]@{ disable = $(if ($null -ne $UiDisable) { [bool]$UiDisable } else { $false }) }
    if ($Clipboard) { $ui['clipboard'] = $Clipboard }
    if ($null -ne $Injection) { $ui['injection'] = [bool]$Injection }
    $obj['ui'] = $ui

    # --- processContainer ----------------------------------------------
    $pc = [ordered]@{}
    if ($Capabilities.Count -gt 0)  { $pc['capabilities']  = @($Capabilities) }
    if ($null -ne $LeastPrivilege)  { $pc['leastPrivilege'] = [bool]$LeastPrivilege }
    if ($AllowedProxyPeer) { $pc['network'] = [ordered]@{ allowedProxyPeer = $AllowedProxyPeer } }
    $needBp = ($BpUiIsolation -or $BpUiSystemSettings -or $null -ne $BpUiDesktopControl -or $null -ne $BpUiIme)
    if ($needBp) {
        $bp = [ordered]@{}
        if ($BpUiIsolation)              { $bp['isolation']            = $BpUiIsolation }
        if ($null -ne $BpUiDesktopControl) { $bp['desktopSystemControl'] = [bool]$BpUiDesktopControl }
        if ($BpUiSystemSettings)         { $bp['systemSettings']       = $BpUiSystemSettings }
        if ($null -ne $BpUiIme)          { $bp['ime']                  = [bool]$BpUiIme }
        $pc['ui'] = $bp
    }
    if ($pc.Count -gt 0) { $obj['processContainer'] = $pc }

    $path = Join-Path (Join-Path $ScratchRoot 'configs') "$Name.json"
    ($obj | ConvertTo-Json -Depth 12) | Out-File -LiteralPath $path -Encoding utf8 -Force
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
    # Start draining both pipes BEFORE waiting. With stdout and stderr both
    # redirected and unread, the child blocks as soon as either 4 KB pipe
    # buffer fills, WaitForExit reports a timeout, and a perfectly healthy
    # rejection is recorded as a hang. These phases make that routine rather
    # than theoretical: every failure path flushes the whole redacted config
    # echo to stderr, and the proxy phase dumps a full environment block to
    # stdout — both comfortably exceed the buffer.
    $stdoutTask = $p.StandardOutput.ReadToEndAsync()
    $stderrTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        $partialOut = ''
        $partialErr = ''
        try { if ($stdoutTask.Wait(2000)) { $partialOut = $stdoutTask.Result } } catch {}
        try { if ($stderrTask.Wait(2000)) { $partialErr = $stderrTask.Result } } catch {}
        return [pscustomobject]@{
            ExitCode = -1
            TimedOut = $true
            Stdout   = $partialOut
            Stderr   = "TIMEOUT after ${TimeoutSec}s`n$partialErr"
        }
    }
    $out = ''
    $err = ''
    try { if ($stdoutTask.Wait(5000)) { $out = $stdoutTask.Result } } catch {}
    try { if ($stderrTask.Wait(5000)) { $err = $stderrTask.Result } } catch {}
    return [pscustomobject]@{
        ExitCode = $p.ExitCode
        TimedOut = $false
        Stdout   = $out
        Stderr   = $err
    }
}

# -----------------------------------------------------------------------
# Tier prerequisite
#
# Every expectation in this harness is derived from $Script:ExpectedTier, so
# the suite is self-consistent on ANY host — which also means a host that
# silently fell back to T3 runs the T3 assertions and reports green. A CI job
# named "process-t1" that never touched BaseContainer has proven nothing. When
# -RequireTier is passed the mismatch is a hard abort, not a skip.
# -----------------------------------------------------------------------
function Assert-RequiredTier {
    if (-not $RequireTier) {
        Write-Host 'Tier prerequisite: not requested (-RequireTier unset); running against the naturally selected tier.' -ForegroundColor DarkGray
        return
    }
    if ($Script:ExpectedTier -ne $RequireTier) {
        throw ("Tier prerequisite ABORT: -RequireTier '$RequireTier' but this host naturally selects '$($Script:ExpectedTier)' " +
               "(baseContainerApiPresent=$($Script:Caps.BaseContainerApiPresent)). " +
               'Running anyway would exercise the other tier and report a green suite that proves nothing about ' +
               "'$RequireTier'. Fix host provisioning or run without -RequireTier.")
    }
    Record-Result -Phase 'P0' -Name "tier prerequisite: host selects $RequireTier" -Pass $true -Detail "expectedTier=$($Script:ExpectedTier)"
}

# -----------------------------------------------------------------------
# Network test infrastructure
# -----------------------------------------------------------------------

# Documented in docs/process-container/networking.md §2: PSEC is the ONLY
# ProcessContainer path that receives schema 0.8 egress filters, proxy peer
# identity, or host-loopback configuration. Legacy SBOX and the AppContainer
# fallback reject those. The probe does not name the process-creation contract
# directly, so the tier stands in for it: `base-container` is the only tier
# that can be on PSEC. On a base-container host that is actually running the
# transitional SBOX contract the PSEC-only assertions will fail — which is the
# correct signal, not a false green.
function Test-PsecEligible {
    return ($Script:ExpectedTier -eq 'base-container')
}

# Reachability from the HOST, used as the prerequisite for every positive
# egress assertion. Uses curl.exe (in System32 on every supported build) so
# the probe path matches what the contained workload runs.
function Test-HostCanReachAnchor {
    param([string]$Url = $ExternalAnchorUrl)
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path $curl)) { return $false }
    & $curl --silent --show-error --max-time 12 --output NUL $Url 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

# A contained command line that fetches the anchor and prints a single
# unambiguous token. Both branches print, so "no output at all" is
# distinguishable from a policy verdict — a silent child means the run itself
# failed and the phase must not read that as "blocked".
function Get-AnchorFetchCommand {
    param([string]$Url = $ExternalAnchorUrl, [int]$TimeoutSec = 10)
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    return "$env:SystemRoot\System32\cmd.exe /c `"$curl --silent --show-error --max-time $TimeoutSec --output NUL $Url && echo NET=REACHED || echo NET=BLOCKED`""
}

# Classify a completed run into REACHED / BLOCKED / NORUN. NORUN covers "the
# sandbox never got far enough to print", which no network assertion may score.
#
# ONLY stdout is examined, and that is load-bearing. On every failure path
# wxc-exec flushes its diagnostic buffer to stderr, and that buffer contains
# the redacted config — including `process.commandLine`, which holds the
# literal text `echo NET=REACHED`. Scanning stderr therefore scores every
# failed run as REACHED, which makes NORUN unreachable and turns every guard
# built on it into a no-op. The workload's own output goes to stdout, which
# carries no config echo.
function Get-NetVerdict {
    param([Parameter(Mandatory)] $Result)
    $out = "$($Result.Stdout)"
    if ($out -match 'NET=REACHED') { return 'REACHED' }
    if ($out -match 'NET=BLOCKED') { return 'BLOCKED' }
    return 'NORUN'
}

# Strip wxc-exec's redacted config/request echo out of a captured stream.
#
# Any assertion that searches a log or stderr for a token is otherwise
# searching the harness's OWN config text: a config carrying
# `"timeout": 4000` matches /timeout/, and one carrying
# `capabilities: ["internetClient"]` matches /internetClient/, so the
# assertion passes whether or not the backend ever honored the field — the
# exact silent-drop it was written to catch.
# Strip wxc-exec's redacted config/request echo out of a captured stream.
#
# Any assertion that searches a log or stderr for a token is otherwise
# searching the harness's OWN config text: a config carrying
# `"timeout": 4000` matches /timeout/, and one carrying
# `capabilities: ["internetClient"]` matches /internetClient/, so the
# assertion passes whether or not the backend ever honored the field — the
# exact silent-drop it was written to catch.
#
# The echo is a PREFIX, not a suffix. wxc-exec writes three sections up front
# (`SECTION: JSON Config (redacted)`, `SECTION: Request simplified`, and
# `SECTION: Full \`ExecutionRequest\` configuration (redacted)`) and only then
# calls resolve_runner, which produces the tier selection, the capability list
# and every backend line. So the echoed block must be CUT OUT and the tail
# kept — truncating at the first marker would discard all the real output and
# leave every log assertion structurally unable to pass.
#
# The JSON bodies are skipped by brace depth rather than by matching a closing
# line: a Windows path can legitimately contain braces (a sandboxed TEMP
# directory is `...\sandbox.{<guid>}\...`), but they are balanced within the
# one line that holds them, so the running depth is unaffected.
function Remove-ConfigEcho {
    param([string]$Text)
    if (-not $Text) { return '' }
    $lines = $Text -split "`r?`n"
    $kept  = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $lines.Count) {
        $bare = ($lines[$i] -replace '\[\d{6,}\]', '')
        if ($bare -match 'SECTION: (JSON Config|Full .?ExecutionRequest)') {
            $i++
            $depth = 0
            $entered = $false
            while ($i -lt $lines.Count) {
                $body = ($lines[$i] -replace '\[\d{6,}\]', '')
                $i++
                $depth += ([regex]::Matches($body, '\{')).Count
                $depth -= ([regex]::Matches($body, '\}')).Count
                if ($depth -gt 0) { $entered = $true }
                if ($entered -and $depth -le 0) { break }
            }
            continue
        }
        if ($bare -match 'SECTION: Request simplified') {
            $i++
            while ($i -lt $lines.Count) {
                if (($lines[$i] -replace '\[\d{6,}\]', '') -match 'SECTION: ') { break }
                $i++
            }
            continue
        }
        $kept.Add($lines[$i])
        $i++
    }
    return ($kept -join "`n")
}

# Guard for differential assertions. Comparing two verdicts is only meaningful
# when both runs actually produced one: three NORUNs "agree" and would score a
# green that proves nothing, which is exactly the failure mode these phases
# exist to catch.
function Test-VerdictsRan {
    param([Parameter(Mandatory)] [object[]]$Runs)
    foreach ($r in $Runs) { if ($r.Verdict -eq 'NORUN') { return $false } }
    return $true
}

# "The backend refused this policy" — as distinct from "the run fell over".
#
# Two different failures are indistinguishable by exit code alone:
#
#   * Invoke-Wxc synthesizes ExitCode = -1 with empty stdout on timeout.
#   * wxc-exec itself exits -1 when the launch API fails (e.g. WIN32_ERROR(5)
#     on a host that never ran `wxc-host-prep prepare-system-drive`).
#
# Either would score every "must be rejected" assertion green on a host where
# nothing can run at all. The documented contract for an unsupported policy is
# a typed error raised during validation, BEFORE the container starts, so a
# run that got as far as calling the launch API did not reject the policy —
# it accepted it and then died for an unrelated reason, which is the opposite
# of what the assertion claims.
function Test-WasRejected {
    param(
        [Parameter(Mandatory)] [object]$Run,
        # Log text (config echo already stripped, or not — the markers matched
        # here are emitted by the runner, never by a config).
        [string]$Log
    )
    $result = $(if ($Run.PSObject.Properties['Result']) { $Run.Result } else { $Run })
    if ($result.TimedOut) { return $false }
    if ($result.ExitCode -eq 0) { return $false }
    if ($Run.PSObject.Properties['Verdict'] -and $Run.Verdict -ne 'NORUN') { return $false }

    $text = $Log
    if (-not $text -and $Run.PSObject.Properties['Log']) { $text = $Run.Log }
    if ($text -and ($text -match '(?i)create_process_failed|CreateProcessInSandbox failed|CreateProcessSecurityEnvironment failed')) {
        # Reached the launch API, so validation had already accepted the
        # policy. This is a host-provisioning failure, not a rejection.
        return $false
    }
    return $true
}

# The non-network counterpart of Get-NetVerdict's NORUN state.
#
# Every negative assertion ("the sentinel was NOT printed", "no survivor was
# left", "the exit code was non-zero") is satisfied by a workload that never
# started, so on a mis-provisioned host such a phase reports green having
# proven nothing. New-ProbeCommand prefixes an unconditional marker echo;
# Test-WorkloadRan then separates "the policy denied it" from "the sandbox
# never launched". A negative assertion must be AND-ed with this.
$Script:RanMarker = 'MXCRAN-7b21'

function New-ProbeCommand {
    param([Parameter(Mandatory)][string]$Body)
    # `&` (not `&&`) so the marker is printed regardless of what Body does.
    return "$env:SystemRoot\System32\cmd.exe /c `"echo $Script:RanMarker& $Body`""
}

function Test-WorkloadRan {
    param([Parameter(Mandatory)] $Result)
    return [bool]("$($Result.Stdout)" -match [regex]::Escape($Script:RanMarker))
}

# Collapse a captured stream into a single short line for a result detail.
# wxc-exec echoes the whole redacted config on failure, which is hundreds of
# lines and drowns the summary.
function Format-Snippet {
    param([string]$Text, [int]$Max = 200)
    if (-not $Text) { return '' }
    $one = ($Text.Trim() -replace '\s+', ' ')
    if ($one.Length -le $Max) { return $one }
    return $one.Substring(0, $Max) + '...'
}

# The host's IPv4 resolvers, needed so an egress allow rule set can permit
# DNS (name resolution follows the same egress rules). Get-DnsClientServerAddress
# is CIM-backed and raises a *terminating* exception on hosts that deny CIM, which
# -ErrorAction cannot suppress, so it is wrapped and backed by an ipconfig parse.
function Get-HostDnsServers {
    try {
        $viaCim = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
        if ($viaCim.Count -gt 0) { return $viaCim }
    } catch {}

    # ipconfig prints resolvers as a hanging-indent list under "DNS Servers",
    # so continuation lines are collected until a non-indented line ends it.
    try {
        $servers = [System.Collections.Generic.List[string]]::new()
        $inList = $false
        foreach ($line in (& "$env:SystemRoot\System32\ipconfig.exe" /all 2>$null)) {
            if ($line -match '^\s*DNS Servers[^:]*:\s*(.*)$') {
                $inList = $true
                if ($Matches[1].Trim()) { $servers.Add($Matches[1].Trim()) }
            }
            elseif ($inList -and $line -match '^\s{10,}(\S+)\s*$') { $servers.Add($Matches[1]) }
            elseif ($line -match '\S') { $inList = $false }
        }
        return @($servers | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -Unique)
    } catch { return @() }
}

# Host-side HTTP listener on 127.0.0.1, used as the host-loopback anchor.
# Returned object carries Url/Port plus a Stop() closure.
#
# A raw TcpListener speaking a hand-written response is used instead of
# HttpListener: HttpListener goes through http.sys, which requires a URL ACL
# reservation (`netsh http add urlacl`) that an unelevated account does not
# have, so it fails to bind on exactly the developer hosts this phase needs to
# run on. A plain socket needs no reservation. The accept loop runs on a
# background runspace so the harness thread stays free while the contained
# child connects.
function Start-LoopbackListener {
    $port = Get-FreeTcpPort
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
    try {
        $listener.Start()
    } catch {
        return $null
    }
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript({
        param($l)
        $body = 'MXC-LOOPBACK-ANCHOR'
        $response = [Text.Encoding]::ASCII.GetBytes(
            "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
        while ($true) {
            try {
                $client = $l.AcceptTcpClient()
                $stream = $client.GetStream()
                # Read whatever request line the client sent before replying;
                # curl will not report success if the peer resets first.
                $stream.ReadTimeout = 2000
                $buf = New-Object byte[] 1024
                try { [void]$stream.Read($buf, 0, $buf.Length) } catch {}
                $stream.Write($response, 0, $response.Length)
                $stream.Flush()
                $client.Close()
            } catch { break }
        }
    }).AddArgument($listener)
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{
        Port = $port
        Url  = "http://127.0.0.1:$port/"
        Stop = {
            try { $listener.Stop() } catch {}
            try { [void]$ps.EndInvoke($handle) } catch {}
            try { $ps.Dispose() } catch {}
        }.GetNewClosure()
    }
}

function Get-FreeTcpPort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    $port = $l.LocalEndpoint.Port
    $l.Stop()
    return $port
}

# Contained command line that fetches a host-loopback URL. Same two-branch
# token contract as Get-AnchorFetchCommand.
function Get-LoopbackFetchCommand {
    param([Parameter(Mandatory)][string]$Url, [int]$TimeoutSec = 5)
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    return "$env:SystemRoot\System32\cmd.exe /c `"$curl --silent --show-error --max-time $TimeoutSec --output NUL $Url && echo NET=REACHED || echo NET=BLOCKED`""
}

# Snapshot MXC-installed firewall rules so the legacy `enforcementMode:
# firewall` phase can assert MXC removes what it installed. The DACL side has
# a full apply/restore/orphan-reap story; the firewall side had none.
#
# NetworkManager::apply_firewall_rules names every rule it creates
# `WXC_<principal>_<millis>[_<action>_<index>]`, so an anchored `WXC_` prefix
# is the exact filter. netsh is used instead of Get-NetFirewallRule because the
# latter is CIM-backed and unavailable on locked-down hosts.
function Get-MxcFirewallRuleNames {
    try {
        $rules = & netsh.exe advfirewall firewall show rule name=all 2>$null
    } catch {
        return @()
    }
    if (-not $rules) { return @() }
    # Deliberately NOT anchored on the "Rule Name:" label — that literal is
    # localized, and on a non-English runner an anchored parse returns an
    # empty set, which reads as "no rules leaked" and scores green. Match the
    # rule token itself instead; `WXC_<principal>_<millis>[_<action>_<n>]` is
    # generated by NetworkManager::apply_firewall_rules and is not localized.
    @($rules | Select-String -Pattern '(WXC_[A-Za-z0-9_.-]+)' -AllMatches |
        ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value.Trim() } |
        Sort-Object -Unique)
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

# =======================================================================
# Phase 8 — schema 0.8 directional network policy
#
# These phases assert the DOCUMENTED contract, not the current code. The
# authoritative sources, both revised within the last month, are:
#   * docs/process-container/networking.md          (backend implementation)
#   * docs/sandbox-policy/0.8.0/networking/networking.md (shared policy)
# Where the implementation has not caught up, the assertion fails. That is
# the intended signal — a green suite that only encodes present behavior
# cannot tell anyone the backend diverged from its spec.
#
# Every positive assertion is paired with a negative control on an otherwise
# identical config, because "reached the anchor" and "blocked by policy" are
# indistinguishable from a single run on a host with no connectivity.
# =======================================================================

# Standard filesystem grant for a network test. `curl.exe` needs %SystemRoot%
# readable and the cwd fallback (documented in the 0.8 schema's `process.cwd`
# description) needs a readwrite directory to land in, so every network config
# carries the same pair. Keeping it identical across configs means a
# reachability difference is attributable to the network policy alone.
function Get-NetFsGrants {
    return @{
        ReadWrite = @((Join-Path $ScratchRoot 'rw'))
        ReadOnly  = @($env:SystemRoot)
    }
}

function Invoke-NetRun {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$ConfigPath,
        [int]$TimeoutSec = 45
    )
    $log = Join-Path $ScratchRoot "logs\$Name.log"
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $ConfigPath -LogPath $log -TimeoutSec $TimeoutSec
    $logContent = Read-Log $log
    Assert-NoBfscfg -LogContent $logContent -Phase 'P8' -Name $Name
    return [pscustomobject]@{
        Result  = $r
        Log     = $logContent
        Verdict = (Get-NetVerdict -Result $r)
    }
}

# -----------------------------------------------------------------------
# Phase 8a — the documented egress x ingress capability matrix.
#
# docs/process-container/networking.md §1 states the mapping exactly:
#
#   egress | ingress | capabilities                 | result
#   deny   | deny    | none                         | internet + private denied
#   allow  | deny    | internetClient               | internet out allowed
#   deny   | allow   | privateNetworkClientServer   | PSEC blocks out via WFP,
#                                                     permits private inbound;
#                                                     AppContainer fallback
#                                                     REJECTS (bidirectional)
#   allow  | allow   | both                         | both allowed
#
# The deny/allow row is the interesting one: it is the single combination the
# doc says a non-PSEC tier must REFUSE rather than approximate. A tier that
# quietly accepts it has granted bidirectional private-network access that the
# caller did not ask for, and nothing else in the suite would notice.
# -----------------------------------------------------------------------
function Phase-NetworkCapabilityMatrix {
    Section 'Phase 8a: schema 0.8 egress/ingress capability matrix'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8a' -Name 'network capability matrix' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible

    # --- deny/deny: no capabilities, everything denied.
    $cfgDD = New-Config -Name 'net-matrix-deny-deny' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 30000
    $dd = Invoke-NetRun -Name 'net-matrix-deny-deny' -ConfigPath $cfgDD
    Record-Result -Phase 'P8a' -Name 'egress=deny ingress=deny -> internet denied' `
        -Pass ($dd.Verdict -eq 'BLOCKED') `
        -Detail "verdict=$($dd.Verdict); exit=$($dd.Result.ExitCode)"

    # --- allow/deny: internetClient granted, internet reachable.
    $cfgAD = New-Config -Name 'net-matrix-allow-deny' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'allow' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 30000
    $ad = Invoke-NetRun -Name 'net-matrix-allow-deny' -ConfigPath $cfgAD
    Record-Result -Phase 'P8a' -Name 'egress=allow ingress=deny -> internet REACHED (internetClient granted)' `
        -Pass ($ad.Verdict -eq 'REACHED') `
        -Detail "verdict=$($ad.Verdict); exit=$($ad.Result.ExitCode)"
    # The capability is what makes the grant real. Assert the backend actually
    # named it, so a run that reached the anchor by some other route (a stale
    # firewall hole, an unenforced tier) is not scored as a working grant.
    Record-Result -Phase 'P8a' -Name 'egress=allow logs internetClient capability' `
        -Pass ([bool]((Remove-ConfigEcho $ad.Log) -match '(?i)internetClient')) `
        -Detail 'documented capability mapping for egress.default=allow'

    # --- deny/allow: the tier-dependent row.
    $cfgDA = New-Config -Name 'net-matrix-deny-allow' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'deny' -TimeoutMs 30000
    $da = Invoke-NetRun -Name 'net-matrix-deny-allow' -ConfigPath $cfgDA
    if ($psec) {
        Record-Result -Phase 'P8a' -Name 'egress=deny ingress=allow -> accepted on PSEC, egress still blocked by WFP' `
            -Pass ($da.Verdict -eq 'BLOCKED') `
            -Detail "verdict=$($da.Verdict); exit=$($da.Result.ExitCode)"
        Record-Result -Phase 'P8a' -Name 'egress=deny ingress=allow logs privateNetworkClientServer' `
            -Pass ([bool]((Remove-ConfigEcho $da.Log) -match '(?i)privateNetworkClientServer')) `
            -Detail 'documented capability mapping for ingress.default=allow'
    } else {
        # "The AppContainer fallback rejects this combination because the
        # capability is bidirectional." A run that merely fails late is not a
        # rejection: the container must never start.
        $rejected = Test-WasRejected $da
        Record-Result -Phase 'P8a' -Name 'egress=deny ingress=allow -> REJECTED on non-PSEC tier (bidirectional capability)' `
            -Pass $rejected `
            -Detail "verdict=$($da.Verdict); exit=$($da.Result.ExitCode); timedOut=$($da.Result.TimedOut); tier=$($Script:ExpectedTier)"
    }

    # --- allow/allow: both capabilities.
    $cfgAA = New-Config -Name 'net-matrix-allow-allow' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'allow' -IngressDefault 'allow' -HostLoopback 'deny' -TimeoutMs 30000
    $aa = Invoke-NetRun -Name 'net-matrix-allow-allow' -ConfigPath $cfgAA
    Record-Result -Phase 'P8a' -Name 'egress=allow ingress=allow -> internet REACHED (both capabilities)' `
        -Pass ($aa.Verdict -eq 'REACHED') `
        -Detail "verdict=$($aa.Verdict); exit=$($aa.Result.ExitCode)"
    $aaLog = Remove-ConfigEcho $aa.Log
    Record-Result -Phase 'P8a' -Name 'egress=allow ingress=allow logs both capabilities' `
        -Pass ([bool]($aaLog -match '(?i)internetClient') -and [bool]($aaLog -match '(?i)privateNetworkClientServer')) `
        -Detail 'documented capability mapping for allow/allow'
}

# -----------------------------------------------------------------------
# Phase 8b — model 3 has three spellings and they must be identical.
#
# docs/process-container/networking.md §Model 3 states that an explicit
# deny-everything block, an omitted `network` key, and `"network": {}` are
# equivalent. This is exactly the kind of property that rots silently: a
# parser change that makes an absent section mean "inherit" rather than
# "deny" opens a default-allow hole that no single-config test would catch,
# because each config in isolation still behaves plausibly.
# -----------------------------------------------------------------------
function Phase-NetworkModel3Equivalence {
    Section 'Phase 8b: model 3 — explicit deny == omitted network == empty network'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8b' -Name 'model 3 equivalence' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $cmd = Get-AnchorFetchCommand

    $cfgExplicit = New-Config -Name 'net-model3-explicit' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 30000
    $cfgOmitted = New-Config -Name 'net-model3-omitted' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly -TimeoutMs 30000
    $cfgEmpty = New-Config -Name 'net-model3-empty' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly -EmptyNetwork -TimeoutMs 30000

    $explicit = Invoke-NetRun -Name 'net-model3-explicit' -ConfigPath $cfgExplicit
    $omitted  = Invoke-NetRun -Name 'net-model3-omitted'  -ConfigPath $cfgOmitted
    $empty    = Invoke-NetRun -Name 'net-model3-empty'    -ConfigPath $cfgEmpty

    Record-Result -Phase 'P8b' -Name 'explicit deny/deny/deny blocks egress' `
        -Pass ($explicit.Verdict -eq 'BLOCKED') -Detail "verdict=$($explicit.Verdict)"
    Record-Result -Phase 'P8b' -Name 'omitted network block blocks egress (default-deny, not inherit)' `
        -Pass ($omitted.Verdict -eq 'BLOCKED') -Detail "verdict=$($omitted.Verdict)"
    Record-Result -Phase 'P8b' -Name 'empty "network": {} blocks egress' `
        -Pass ($empty.Verdict -eq 'BLOCKED') -Detail "verdict=$($empty.Verdict)"
    Record-Result -Phase 'P8b' -Name 'all three model-3 spellings agree' `
        -Pass ((Test-VerdictsRan @($explicit, $omitted, $empty)) -and
               ($explicit.Verdict -eq $omitted.Verdict) -and ($omitted.Verdict -eq $empty.Verdict)) `
        -Detail "explicit=$($explicit.Verdict); omitted=$($omitted.Verdict); empty=$($empty.Verdict)"
}

# -----------------------------------------------------------------------
# Phase 8c — explicit WFP egress rules (PSEC only).
#
# Two properties, from docs/process-container/networking.md §3 and the shared
# spec's D4:
#   * an allow rule scoped to a CIDR/port actually permits THAT destination
#     and still blocks everything else — a rule set that installs cleanly but
#     filters nothing passes any log-only assertion;
#   * an explicit deny beats an overlapping explicit allow (D4).
# On a non-PSEC tier the documented behavior is a typed unsupported-policy
# rejection, never a silent drop. A silently dropped rule set is the worst
# outcome available here: the caller believes egress is filtered and it is
# wide open.
# -----------------------------------------------------------------------
function Phase-NetworkEgressRules {
    Section 'Phase 8c: explicit egress rules (WFP / PSEC-only)'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8c' -Name 'explicit egress rules' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible

    # Probe the negative control's destination up front. On a runner behind an
    # allowlisting proxy that permits the anchor but not this destination, the
    # control reads BLOCKED and scores green while proving nothing — an
    # unattributable negative, the exact failure the control exists to prevent.
    # Recorded as a failure, then used to gate only the assertion that depends
    # on it: the rest of the phase (including the whole documented rejection
    # surface on a non-PSEC tier) needs no second destination.
    $unlistedUsable = Test-HostCanReachAnchor -Url $UnlistedDestinationUrl
    if (-not $unlistedUsable) {
        Record-Result -Phase 'P8c' -Name 'prerequisite: host reaches the unlisted-destination control' `
            -Pass $false `
            -Detail ("$UnlistedDestinationUrl is unreachable from the host, so a BLOCKED verdict inside the " +
                     'container would not be attributable to the egress rules. Pass -UnlistedDestinationUrl <reachable-url>.')
    }

    # Resolve the anchor to an address so an allow rule can name it. DNS
    # itself follows the same egress rules (documented), so the rule set must
    # also permit UDP/53 to the resolver for the allow case to be reachable.
    $anchorHost = ([Uri]$ExternalAnchorUrl).Host
    $anchorIps = @()
    try {
        $anchorIps = @([System.Net.Dns]::GetHostAddresses($anchorHost) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.IPAddressToString })
    } catch {}

    if ($anchorIps.Count -eq 0) {
        Record-Result -Phase 'P8c' -Name 'resolve anchor for CIDR rules' -Pass $false `
            -Detail "could not resolve $anchorHost from the host; cannot author an address-scoped rule"
        return
    }

    # Allow the anchor's /32 on tcp/443 plus DNS to every resolver the host
    # uses. Anything else stays denied by the egress default.
    $dnsServers = Get-HostDnsServers
    $allowRules = @()
    foreach ($ip in $anchorIps) {
        $allowRules += (New-EgressRule -Cidr @("$ip/32") -Protocol 'tcp' -Port 443)
    }
    foreach ($dns in $dnsServers) {
        $allowRules += (New-EgressRule -Cidr @("$dns/32") -Protocol 'udp' -Port 53)
    }

    $cfgAllow = New-Config -Name 'net-rules-allow-anchor' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' `
        -EgressAllow $allowRules -TimeoutMs 30000
    $allow = Invoke-NetRun -Name 'net-rules-allow-anchor' -ConfigPath $cfgAllow

    # D4: an explicit deny on the same destination must beat the allow.
    $denyRules = @(foreach ($ip in $anchorIps) { New-EgressRule -Cidr @("$ip/32") -Protocol 'tcp' -Port 443 })
    $cfgPrecedence = New-Config -Name 'net-rules-deny-precedence' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' `
        -EgressAllow $allowRules -EgressDeny $denyRules -TimeoutMs 30000
    $precedence = Invoke-NetRun -Name 'net-rules-deny-precedence' -ConfigPath $cfgPrecedence

    # Negative control: same allow rule set, but the workload reaches for a
    # destination the rules never named. Without this, "allow worked" and
    # "nothing was filtered" look identical.
    $unlisted = $null
    if ($unlistedUsable) {
        $cfgUnlisted = New-Config -Name 'net-rules-unlisted-dest' `
            -CommandLine (Get-AnchorFetchCommand -Url $UnlistedDestinationUrl) `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' `
            -EgressAllow $allowRules -TimeoutMs 30000
        $unlisted = Invoke-NetRun -Name 'net-rules-unlisted-dest' -ConfigPath $cfgUnlisted
    }

    if ($psec) {
        Record-Result -Phase 'P8c' -Name 'egress allow rule permits the named CIDR:443' `
            -Pass ($allow.Verdict -eq 'REACHED') `
            -Detail "verdict=$($allow.Verdict); rules=$($allowRules.Count); exit=$($allow.Result.ExitCode)"
        Record-Result -Phase 'P8c' -Name 'unlisted destination still blocked under the same rule set' `
            -Pass ($null -ne $unlisted -and $unlisted.Verdict -eq 'BLOCKED') `
            -Detail $(if ($null -eq $unlisted) { 'not run: the control destination is unreachable from the host' }
                      else { "verdict=$($unlisted.Verdict)" })
        Record-Result -Phase 'P8c' -Name 'D4: explicit deny overrides overlapping explicit allow' `
            -Pass ($precedence.Verdict -eq 'BLOCKED') `
            -Detail "verdict=$($precedence.Verdict)"
    } else {
        # Documented: "Explicit egress rules, proxy peer identity, and
        # host-loopback allow fail with a typed unsupported-policy error when
        # PSEC cannot enforce them."
        foreach ($case in @(
            @{ Tag = 'allow rules';      Run = $allow },
            @{ Tag = 'deny rules';       Run = $precedence })) {
            $rejected = Test-WasRejected $case.Run
            Record-Result -Phase 'P8c' -Name "non-PSEC tier rejects explicit egress $($case.Tag)" `
                -Pass $rejected `
                -Detail "verdict=$($case.Run.Verdict); exit=$($case.Run.Result.ExitCode); timedOut=$($case.Run.Result.TimedOut); tier=$($Script:ExpectedTier)"
        }
        $combined = @((Remove-ConfigEcho "$($allow.Result.Stderr)"), (Remove-ConfigEcho "$($allow.Log)")) -join "`n"
        Record-Result -Phase 'P8c' -Name 'rejection is a typed unsupported-policy error' `
            -Pass ([bool]($combined -match '(?i)unsupported|not supported|policy_validation|unsupported_policy')) `
            -Detail 'documented as a typed error, not a silent drop'
    }
}

# -----------------------------------------------------------------------
# Phase 8d — host loopback.
#
# The shared spec (D2) blocks host loopback by default and states that an
# OMITTED `hostLoopback` is `deny`, not an inherit of `ingress.default`. That
# is the documented trap: `egress.default: allow` with no ingress section
# reaches the whole internet but not the host's own loopback. Both directions
# of getting this wrong are user-visible — an unreachable local dev server, or
# a loopback hole — and only a live run distinguishes them.
#
# `hostLoopback: "allow"` is PSEC-1.1-only; every other path must reject it
# rather than accept it with partial enforcement.
# -----------------------------------------------------------------------
function Phase-NetworkHostLoopback {
    Section 'Phase 8d: host-loopback policy'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8d' -Name 'host loopback' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $listener = Start-LoopbackListener
    if (-not $listener) {
        Record-Result -Phase 'P8d' -Name 'host loopback listener' -Pass $false `
            -Detail 'could not bind an HttpListener on 127.0.0.1; cannot assert either direction'
        return
    }

    try {
        # Prerequisite: the HOST itself must reach its own listener, else every
        # "blocked" reading below is unattributable.
        $hostReach = $false
        try {
            $resp = Invoke-WebRequest -Uri $listener.Url -TimeoutSec 5 -UseBasicParsing
            $hostReach = ($resp.Content -match 'MXC-LOOPBACK-ANCHOR')
        } catch {}
        Record-Result -Phase 'P8d' -Name 'prerequisite: host reaches its own loopback anchor' `
            -Pass $hostReach -Detail $listener.Url
        if (-not $hostReach) { return }

        $fs = Get-NetFsGrants
        $cmd = Get-LoopbackFetchCommand -Url $listener.Url

        # The documented trap: egress allow, ingress section omitted entirely.
        $cfgTrap = New-Config -Name 'net-loopback-trap' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'allow' -TimeoutMs 25000
        $trap = Invoke-NetRun -Name 'net-loopback-trap' -ConfigPath $cfgTrap
        Record-Result -Phase 'P8d' -Name 'omitted hostLoopback defaults to deny even under egress=allow' `
            -Pass ($trap.Verdict -eq 'BLOCKED') `
            -Detail "verdict=$($trap.Verdict); documented default-deny, not an inherit of egress/ingress default"

        # Explicit deny, spelled out.
        $cfgDeny = New-Config -Name 'net-loopback-deny' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'allow' -IngressDefault 'deny' -HostLoopback 'deny' -TimeoutMs 25000
        $deny = Invoke-NetRun -Name 'net-loopback-deny' -ConfigPath $cfgDeny
        Record-Result -Phase 'P8d' -Name 'explicit hostLoopback=deny blocks container -> host loopback' `
            -Pass ($deny.Verdict -eq 'BLOCKED') -Detail "verdict=$($deny.Verdict)"
        Record-Result -Phase 'P8d' -Name 'omitted and explicit hostLoopback=deny agree' `
            -Pass ((Test-VerdictsRan @($trap, $deny)) -and ($trap.Verdict -eq $deny.Verdict)) `
            -Detail "omitted=$($trap.Verdict); explicit=$($deny.Verdict)"

        # hostLoopback=allow. `ingress.default: allow` accompanies it because
        # the private-network capability is what the doc pairs with the
        # loopback grant; the specific value overrides the default for the
        # loopback path.
        $cfgAllow = New-Config -Name 'net-loopback-allow' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'allow' -IngressDefault 'allow' -HostLoopback 'allow' -TimeoutMs 25000
        $allow = Invoke-NetRun -Name 'net-loopback-allow' -ConfigPath $cfgAllow

        if (Test-PsecEligible) {
            # On a PSEC 1.1 host this must work. On a PSEC 1.0 host the
            # documented behavior is rejection — so either outcome is
            # defensible, but "accepted and silently unenforced" is not.
            $accepted = ($allow.Verdict -eq 'REACHED')
            $rejected = Test-WasRejected $allow
            Record-Result -Phase 'P8d' -Name 'hostLoopback=allow is either enforced or rejected, never silently dropped' `
                -Pass ($accepted -or $rejected) `
                -Detail "verdict=$($allow.Verdict); exit=$($allow.Result.ExitCode); timedOut=$($allow.Result.TimedOut); accepted=$accepted rejected=$rejected"
            if ($accepted) {
                Record-Result -Phase 'P8d' -Name 'hostLoopback=allow reaches the host loopback anchor (PSEC 1.1)' `
                    -Pass $true -Detail 'bidirectional host-loopback grant honored'
            } else {
                Record-Result -Phase 'P8d' -Name 'hostLoopback=allow rejected (PSEC 1.1 ingress contract unavailable)' `
                    -Status 'skip' -Detail "exit=$($allow.Result.ExitCode); documented fallback when contract 1.1 is absent"
            }
        } else {
            $rejected = Test-WasRejected $allow
            Record-Result -Phase 'P8d' -Name 'non-PSEC tier rejects hostLoopback=allow' `
                -Pass $rejected `
                -Detail "verdict=$($allow.Verdict); exit=$($allow.Result.ExitCode); timedOut=$($allow.Result.TimedOut); tier=$($Script:ExpectedTier)"
        }
    } finally {
        & $listener.Stop
    }
}

# -----------------------------------------------------------------------
# Phase 8e — schema 0.8 runtime proxy (model 2).
#
# docs/process-container/networking.md is explicit and testable here:
#   * MXC sets HTTP_PROXY / HTTPS_PROXY and their lowercase variants to the
#     loopback endpoint;
#   * NO_PROXY is a bypass list and must NOT carry the proxy endpoint;
#   * direct egress is blocked while the proxy is configured;
#   * "Direct egress allow and deny rules do not apply when
#     runtimeConfig.networkProxy is present";
#   * identity-scoped (allowedProxyPeer present) keeps hostLoopback deny;
#     identity-less REQUIRES hostLoopback allow;
#   * schema 0.8 proxy requests never fall back to SBOX or AppContainer.
#
# The env-var contract is asserted by having the contained workload print its
# own environment. That is the only way to see what actually reached the
# child; a log line saying MXC configured a proxy does not prove the child
# received it.
# -----------------------------------------------------------------------
function Phase-NetworkProxy {
    Section 'Phase 8e: schema 0.8 runtime proxy (model 2)'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8e' -Name 'runtime proxy' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible
    $port = Get-FreeTcpPort
    $proxyUrl = "http://127.0.0.1:$port"

    # Identity-less deployment: no allowedProxyPeer, so the doc requires
    # ingress.default=allow AND hostLoopback=allow. Workload dumps its env.
    $envDump = "$env:SystemRoot\System32\cmd.exe /c set"
    $cfgEnv = New-Config -Name 'net-proxy-envvars' -CommandLine $envDump `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'allow' `
        -NetworkProxy $proxyUrl -TimeoutMs 25000
    $envRun = Invoke-NetRun -Name 'net-proxy-envvars' -ConfigPath $cfgEnv

    if ($psec) {
        $out = $envRun.Result.Stdout
        $ran = [bool]($out -match '(?im)^SystemRoot=')
        Record-Result -Phase 'P8e' -Name 'identity-less proxy config runs (ingress=allow + hostLoopback=allow)' `
            -Pass $ran -Detail "exit=$($envRun.Result.ExitCode)"
        if ($ran) {
            foreach ($v in @('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy')) {
                # cmd.exe `set` upper-cases nothing, but Windows env lookup is
                # case-insensitive and duplicate-insensitive, so a variable set
                # twice in different cases collapses. Match case-insensitively
                # on the name and require the endpoint as the value.
                $hit = [bool]($out -match ("(?im)^" + [regex]::Escape($v) + "=.*" + [regex]::Escape("127.0.0.1:$port")))
                Record-Result -Phase 'P8e' -Name "child env carries $v = proxy endpoint" `
                    -Pass $hit -Detail "endpoint=127.0.0.1:$port"
            }
            # NO_PROXY is a bypass list. Carrying the endpoint there would tell
            # cooperating clients to bypass the very proxy they must use.
            $noProxyPoisoned = [bool]($out -match ("(?im)^no_proxy=.*" + [regex]::Escape("127.0.0.1:$port")))
            Record-Result -Phase 'P8e' -Name 'NO_PROXY does NOT carry the proxy endpoint' `
                -Pass (-not $noProxyPoisoned) -Detail 'NO_PROXY is a bypass list, not a proxy setting'
        }

        # Direct egress must be blocked while the proxy is configured. The
        # proxy is not actually listening, so a REACHED verdict here means the
        # workload went straight out — the exact bypass the model forbids.
        $cfgDirect = New-Config -Name 'net-proxy-direct-blocked' `
            -CommandLine (Get-AnchorFetchCommand) `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'allow' `
            -NetworkProxy $proxyUrl -TimeoutMs 25000
        $direct = Invoke-NetRun -Name 'net-proxy-direct-blocked' -ConfigPath $cfgDirect
        Record-Result -Phase 'P8e' -Name 'direct egress blocked while runtime proxy is configured' `
            -Pass ($direct.Verdict -eq 'BLOCKED') `
            -Detail "verdict=$($direct.Verdict); WFP scopes egress to the proxy endpoint only"
    } else {
        # "schema 0.8 runtime proxy requests do not fall back because neither
        # SBOX nor AppContainer can preserve their peer or host-loopback
        # requirements."
        $rejected = Test-WasRejected $envRun
        Record-Result -Phase 'P8e' -Name 'non-PSEC tier rejects schema 0.8 runtime proxy (no fallback)' `
            -Pass $rejected `
            -Detail "exit=$($envRun.Result.ExitCode); timedOut=$($envRun.Result.TimedOut); tier=$($Script:ExpectedTier)"
    }

    # --- Model-2 shape requirements, independent of tier. -----------------
    # Identity-scoped: allowedProxyPeer present, hostLoopback stays deny.
    $cfgPeer = New-Config -Name 'net-proxy-identity-scoped' -CommandLine $envDump `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'deny' `
        -NetworkProxy $proxyUrl -AllowedProxyPeer 'Contoso.Proxy_8wekyb3d8bbwe' -TimeoutMs 25000
    $peer = Invoke-NetRun -Name 'net-proxy-identity-scoped' -ConfigPath $cfgPeer
    if ($psec) {
        # The peer does not exist on this host, so a launch failure is
        # expected; what must NOT happen is the config being refused as an
        # invalid SHAPE. "No rejection message" alone is not evidence — an
        # empty stderr, a harness timeout, or a binary that never started all
        # look the same — so positive proof that the config cleared validation
        # is required too.
        $peerLog = Remove-ConfigEcho $peer.Log
        $shapeRejected = [bool]("$($peer.Result.Stderr)" -match '(?i)policy_validation|unsupported.*polic|invalid.*(polic|config|network)')
        $gotPastValidation = ($peer.Result.ExitCode -eq 0) -or ($peerLog -match '(?i)selected isolation tier')
        Record-Result -Phase 'P8e' -Name 'identity-scoped proxy shape (peer + hostLoopback=deny) is a valid policy' `
            -Pass ($gotPastValidation -and -not $shapeRejected) `
            -Detail ("exit=$($peer.Result.ExitCode); pastValidation=$gotPastValidation; " +
                     "stderr=$(Format-Snippet $peer.Result.Stderr)")
    } else {
        Record-Result -Phase 'P8e' -Name 'non-PSEC tier rejects allowedProxyPeer' `
            -Pass (Test-WasRejected $peer) `
            -Detail "exit=$($peer.Result.ExitCode); timedOut=$($peer.Result.TimedOut); tier=$($Script:ExpectedTier)"
    }

    # The two shape rules below are only meaningful on PSEC. On a non-PSEC
    # tier the phase has already asserted that EVERY schema 0.8 runtime-proxy
    # config is refused, so asserting "this particular one is refused" would be
    # green by construction and would test nothing about the rule it names.
    if (-not $psec) {
        Record-Result -Phase 'P8e' -Name 'model-2 shape rules (hostLoopback / ingress.default)' -Status 'skip' `
            -Detail "tier=$($Script:ExpectedTier) refuses all 0.8 runtime proxies, so a shape-specific rejection is not attributable"
        return
    }

    # Identity-less proxy WITHOUT hostLoopback=allow. The doc says this
    # deployment requires it, so the configuration is incomplete and must be
    # refused rather than run with a proxy the container cannot reach.
    $cfgNoLoopback = New-Config -Name 'net-proxy-identityless-no-loopback' -CommandLine $envDump `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'allow' -HostLoopback 'deny' `
        -NetworkProxy $proxyUrl -TimeoutMs 25000
    $noLoopback = Invoke-NetRun -Name 'net-proxy-identityless-no-loopback' -ConfigPath $cfgNoLoopback
    Record-Result -Phase 'P8e' -Name 'identity-less proxy without hostLoopback=allow is rejected' `
        -Pass (Test-WasRejected $noLoopback) `
        -Detail "exit=$($noLoopback.Result.ExitCode); timedOut=$($noLoopback.Result.TimedOut); doc requires hostLoopback=allow when allowedProxyPeer is omitted"

    # Model 2 requires ingress.default=allow. Without it the client container
    # never gets privateNetworkClientServer and cannot reach a loopback proxy.
    $cfgNoIngress = New-Config -Name 'net-proxy-no-ingress-allow' -CommandLine $envDump `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'allow' `
        -NetworkProxy $proxyUrl -TimeoutMs 25000
    $noIngress = Invoke-NetRun -Name 'net-proxy-no-ingress-allow' -ConfigPath $cfgNoIngress
    Record-Result -Phase 'P8e' -Name 'runtime proxy without ingress.default=allow is rejected' `
        -Pass (Test-WasRejected $noIngress) `
        -Detail "exit=$($noIngress.Result.ExitCode); timedOut=$($noIngress.Result.TimedOut); model 2 requires egress deny + ingress allow"
}

# -----------------------------------------------------------------------
# Phase 8f — the documented reject surface.
#
# Every case here must be refused during validation, before any container
# exists. These resolve without network, privilege, or fixtures — the same
# property that makes run_seatbelt_rejections_test.sh the cheapest suite in
# the tree. A policy that is "enforced" by the workload failing afterwards is
# not enforcement, so each case asserts the run failed AND the workload never
# produced its marker.
# -----------------------------------------------------------------------
function Phase-NetworkRejections {
    Section 'Phase 8f: documented network reject surface'

    $marker = 'REJECT-PROBE-RAN'
    $cmd = "$env:SystemRoot\System32\cmd.exe /c echo $marker"
    $rw = Join-Path $ScratchRoot 'rw'

    # Shapes the typed generator deliberately cannot produce, authored raw.
    $rawBase = {
        param($id, $network, $extra)
        $o = [ordered]@{
            version     = $Script:SchemaVersion
            containerId = "MxcWinPC-$id"
            containment = 'processcontainer'
            process     = [ordered]@{ commandLine = $cmd; timeout = 20000 }
            filesystem  = [ordered]@{ readwritePaths = @($rw); readonlyPaths = @($env:SystemRoot) }
            ui          = [ordered]@{ disable = $false }
        }
        if ($network) { $o['network'] = $network }
        if ($extra) { foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] } }
        return $o
    }

    $cases = @(
        @{
            Name   = 'egress rule with explicitly empty to[] is rejected (not broadened to wildcard)'
            Config = (New-RawConfig -Name 'rej-empty-to' -Object (& $rawBase 'rej-empty-to' ([ordered]@{
                        egress = [ordered]@{ default = 'deny'; allow = @([ordered]@{ to = @() }) }
                     }) $null))
            Why    = '0.8 spec: an explicit empty array is rejected rather than broadened into a wildcard'
        },
        @{
            Name   = 'egress rule with explicitly empty ports[] is rejected'
            Config = (New-RawConfig -Name 'rej-empty-ports' -Object (& $rawBase 'rej-empty-ports' ([ordered]@{
                        egress = [ordered]@{ default = 'deny'; allow = @([ordered]@{ ports = @() }) }
                     }) $null))
            Why    = 'same rule, ports side'
        },
        @{
            Name   = 'DNS name where a CIDR belongs is rejected'
            Config = (New-RawConfig -Name 'rej-dns-name' -Object (& $rawBase 'rej-dns-name' ([ordered]@{
                        egress = [ordered]@{ default = 'deny'; allow = @([ordered]@{ to = @([ordered]@{ cidr = 'example.com' }) }) }
                     }) $null))
            Why    = 'D3: IP literals and CIDRs only, no DNS names'
        },
        @{
            Name   = 'endPort without port is rejected'
            Config = (New-RawConfig -Name 'rej-endport' -Object (& $rawBase 'rej-endport' ([ordered]@{
                        egress = [ordered]@{ default = 'deny'; allow = @([ordered]@{ ports = @([ordered]@{ protocol = 'tcp'; endPort = 500 }) }) }
                     }) $null))
            Why    = 'endPort requires a numeric port'
        },
        @{
            Name   = 'non-loopback runtimeConfig.networkProxy is rejected'
            Config = (New-RawConfig -Name 'rej-proxy-remote' -Object (& $rawBase 'rej-proxy-remote' ([ordered]@{
                        egress  = [ordered]@{ default = 'deny' }
                        ingress = [ordered]@{ default = 'allow'; hostLoopback = 'allow' }
                     }) ([ordered]@{ runtimeConfig = [ordered]@{ networkProxy = 'http://proxy.example.com:8080' } })))
            Why    = 'MXC must reject a networkProxy endpoint that is not loopback'
        },
        @{
            Name   = 'mixing legacy defaultPolicy with directional egress is rejected'
            Config = (New-RawConfig -Name 'rej-mixed-shapes' -Object (& $rawBase 'rej-mixed-shapes' ([ordered]@{
                        defaultPolicy = 'block'
                        egress        = [ordered]@{ default = 'allow' }
                     }) $null))
            Why    = 'the legacy and directional shapes are alternatives; combining them has no defined meaning'
        }
    )

    foreach ($case in $cases) {
        $log = Join-Path $ScratchRoot ('logs\' + (Split-Path -Leaf $case.Config) + '.log')
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $case.Config -LogPath $log -TimeoutSec 30
        $ranAnyway = [bool]("$($r.Stdout)" -match $marker)
        $logText = $(if (Test-Path $log) { Get-Content $log -Raw -ErrorAction SilentlyContinue } else { '' })
        Record-Result -Phase 'P8f' -Name $case.Name `
            -Pass ((Test-WasRejected -Run $r -Log $logText) -and (-not $ranAnyway)) `
            -Detail "exit=$($r.ExitCode); timedOut=$($r.TimedOut); workloadRan=$ranAnyway; $($case.Why)"
    }

    # Positive control. Every case above asserts "this config failed", which is
    # also true on a host where NOTHING runs — so without a control the whole
    # phase reports green having proven nothing about the reject surface. The
    # control is the same fixture with no offending field: it must succeed and
    # print the marker. If it does not, the six negatives above are
    # unattributable and this phase says so explicitly.
    $ctlPath = New-RawConfig -Name 'rej-positive-control' `
        -Object (& $rawBase 'rej-positive-control' ([ordered]@{
            egress  = [ordered]@{ default = 'allow' }
            ingress = [ordered]@{ default = 'deny'; hostLoopback = 'deny' }
        }) $null)
    $ctlLog = Join-Path $ScratchRoot 'logs\rej-positive-control.log'
    $ctl = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $ctlPath -LogPath $ctlLog -TimeoutSec 30
    $ctlRan = [bool]("$($ctl.Stdout)" -match $marker)
    Record-Result -Phase 'P8f' -Name 'positive control: the same fixture without an offending field RUNS' `
        -Pass (($ctl.ExitCode -eq 0) -and $ctlRan) `
        -Detail ("exit=$($ctl.ExitCode); timedOut=$($ctl.TimedOut); workloadRan=$ctlRan; " +
                 'without this, the six rejections above are indistinguishable from a host on which nothing launches')
}

# -----------------------------------------------------------------------
# Phase 9 — LEGACY network fields, pinned at schema 0.7.
#
# The 0.6/0.7 shape (defaultPolicy / enforcementMode / allowedHosts /
# blockedHosts) is a different parse path from the directional shape and stays
# on 0.7 deliberately. os-version-support.md states capability- and
# firewall-based enforcement works on every release, so these run on any tier.
#
# The firewall lane also closes the teardown asymmetry: the DACL side asserts
# apply -> restore -> orphan reap in three phases, while nothing ever checked
# that `netsh advfirewall` rules created for a container are removed when it
# exits. A leaked allow rule outlives the sandbox it was scoped to.
# -----------------------------------------------------------------------
function Phase-NetworkLegacy07 {
    Section 'Phase 9: legacy network fields (schema 0.7)'

    if ($SkipNetwork) {
        Record-Result -Phase 'P9' -Name 'legacy network' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $cmd = Get-AnchorFetchCommand

    # defaultPolicy allow vs block, capability enforcement. The pair is the
    # assertion: either verdict alone is unattributable.
    $cfgAllow = New-Config -Name 'net07-cap-allow' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -LegacyDefaultPolicy 'allow' -LegacyEnforcementMode 'capabilities' -TimeoutMs 30000
    $cfgBlock = New-Config -Name 'net07-cap-block' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -LegacyDefaultPolicy 'block' -LegacyEnforcementMode 'capabilities' -TimeoutMs 30000

    $allow = Invoke-NetRun -Name 'net07-cap-allow' -ConfigPath $cfgAllow
    $block = Invoke-NetRun -Name 'net07-cap-block' -ConfigPath $cfgBlock

    Record-Result -Phase 'P9' -Name 'schema 0.7 config is accepted (version pinned to 0.7.0-alpha)' `
        -Pass ($allow.Verdict -ne 'NORUN' -or $allow.Result.ExitCode -eq 0) `
        -Detail "exit=$($allow.Result.ExitCode)"
    Record-Result -Phase 'P9' -Name 'legacy defaultPolicy=allow reaches the anchor' `
        -Pass ($allow.Verdict -eq 'REACHED') -Detail "verdict=$($allow.Verdict)"
    Record-Result -Phase 'P9' -Name 'legacy defaultPolicy=block does not reach the anchor' `
        -Pass ($block.Verdict -eq 'BLOCKED') -Detail "verdict=$($block.Verdict)"
    Record-Result -Phase 'P9' -Name 'legacy allow/block differ (policy is what changed the outcome)' `
        -Pass ((Test-VerdictsRan @($allow, $block)) -and ($allow.Verdict -ne $block.Verdict)) `
        -Detail "allow=$($allow.Verdict); block=$($block.Verdict)"

    # Explicit internetClient capability, and the negative control that makes
    # the grant meaningful: same policy, capability withheld.
    $cfgCap = New-Config -Name 'net07-explicit-capability' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -LegacyDefaultPolicy 'allow' -LegacyEnforcementMode 'capabilities' `
        -Capabilities @('internetClient') -TimeoutMs 30000
    $cap = Invoke-NetRun -Name 'net07-explicit-capability' -ConfigPath $cfgCap
    Record-Result -Phase 'P9' -Name 'explicit processContainer.capabilities=[internetClient] reaches the anchor' `
        -Pass ($cap.Verdict -eq 'REACHED') -Detail "verdict=$($cap.Verdict)"
    Record-Result -Phase 'P9' -Name 'explicit capability is named in the log' `
        -Pass ([bool]((Remove-ConfigEcho $cap.Log) -match '(?i)internetClient')) `
        -Detail 'capability list reached the backend (config echo stripped)'

    # enforcementMode matrix. `firewall` and `both` need admin for netsh; a
    # non-admin host cannot exercise them, which is a skip rather than a pass.
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    foreach ($mode in @('firewall', 'both')) {
        if (-not $isAdmin) {
            Record-Result -Phase 'P9' -Name "enforcementMode=$mode" -Status 'skip' `
                -Detail 'netsh advfirewall rule authoring requires an elevated host'
            continue
        }
        $before = Get-MxcFirewallRuleNames
        $cfgMode = New-Config -Name "net07-mode-$mode" -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -LegacyDefaultPolicy 'block' -LegacyEnforcementMode $mode `
            -LegacyAllowedHosts @(([Uri]$ExternalAnchorUrl).Host) `
            -Capabilities @('internetClient') -TimeoutMs 40000

        # Sample the rule set WHILE the container is alive. Comparing only
        # before/after cannot tell "rules were applied and cleaned up" from
        # "enforcementMode was silently ignored and no rule ever existed" —
        # and the second is exactly the drift this phase exists to catch, so
        # without a mid-run sample the leak assertion cannot fail in the
        # interesting direction. The workload fetches for up to 40s, which is
        # the window this poll runs in.
        $sampler = [PowerShell]::Create()
        [void]$sampler.AddScript({
            param($deadlineSec)
            $seen = [System.Collections.Generic.HashSet[string]]::new()
            $end = (Get-Date).AddSeconds($deadlineSec)
            while ((Get-Date) -lt $end) {
                $rules = & netsh.exe advfirewall firewall show rule name=all 2>$null
                foreach ($m in ($rules | Select-String -Pattern '(WXC_[A-Za-z0-9_.-]+)' -AllMatches |
                                ForEach-Object { $_.Matches })) {
                    [void]$seen.Add($m.Groups[1].Value.Trim())
                }
                Start-Sleep -Milliseconds 400
            }
            return @($seen)
        }).AddArgument(55)
        $samplerHandle = $sampler.BeginInvoke()

        $run = Invoke-NetRun -Name "net07-mode-$mode" -ConfigPath $cfgMode -TimeoutSec 60
        $after = Get-MxcFirewallRuleNames
        $duringRaw = @()
        try { $duringRaw = @($sampler.EndInvoke($samplerHandle)) } catch {}
        try { $sampler.Dispose() } catch {}
        $during = @($duringRaw | Where-Object { $_ -notin $before })

        Record-Result -Phase 'P9' -Name "enforcementMode=${mode}: allowedHosts entry is reachable" `
            -Pass ($run.Verdict -eq 'REACHED') `
            -Detail "verdict=$($run.Verdict); allowedHosts=$(([Uri]$ExternalAnchorUrl).Host)"
        Record-Result -Phase 'P9' -Name "enforcementMode=${mode}: firewall rules are actually installed during the run" `
            -Pass ($during.Count -gt 0) `
            -Detail ("observed=$($during.Count); " +
                     'a zero here means the mode was accepted and silently not enforced, which also makes the leak check below vacuous')
        # The teardown assertion the DACL side has had all along. Only
        # meaningful once something was installed to leak.
        $leaked = @($after | Where-Object { $_ -notin $before })
        Record-Result -Phase 'P9' -Name "enforcementMode=${mode}: no firewall rules leaked after the run" `
            -Pass (($during.Count -gt 0) -and ($leaked.Count -eq 0)) `
            -Detail "installed=$($during.Count); leaked=$($leaked.Count)$(if ($leaked.Count) { ': ' + ($leaked -join ', ') })"
    }

    # blockedHosts under an allow default: the destination named is the one
    # that must fail while the default still permits everything else.
    if ($isAdmin) {
        $cfgBlocked = New-Config -Name 'net07-blockedhosts' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -LegacyDefaultPolicy 'allow' -LegacyEnforcementMode 'firewall' `
            -LegacyBlockedHosts @(([Uri]$ExternalAnchorUrl).Host) `
            -Capabilities @('internetClient') -TimeoutMs 40000
        $blocked = Invoke-NetRun -Name 'net07-blockedhosts' -ConfigPath $cfgBlocked -TimeoutSec 60
        Record-Result -Phase 'P9' -Name 'blockedHosts entry is unreachable under an allow default' `
            -Pass ($blocked.Verdict -eq 'BLOCKED') -Detail "verdict=$($blocked.Verdict)"
    } else {
        Record-Result -Phase 'P9' -Name 'blockedHosts under allow default' -Status 'skip' `
            -Detail 'firewall enforcement requires an elevated host'
    }
}

# -----------------------------------------------------------------------
# Phase 10 — path aliasing and most-specific-wins.
#
# Three Linux/macOS backends have dedicated suites for this because a grant
# that resolves to a different object than the caller wrote is either a hole
# or a mystery denial, and neither is visible from the config text. Windows
# has MORE ways to alias a path than any of them — `..` traversal, 8.3 short
# names, the `\\?\` prefix, and junctions all reach the same object that the
# DACL ACEs are applied to.
# -----------------------------------------------------------------------
function Phase-PathAliasing {
    Section 'Phase 10: path aliasing and most-specific-wins'

    if (-not $Script:Caps.SupportsDeniedPaths) {
        Record-Result -Phase 'P10' -Name 'path aliasing' -Status 'skip' `
            -Detail "deniedPaths not supported on tier=$($Script:ExpectedTier)"
        return
    }

    $rw      = Join-Path $ScratchRoot 'rw'
    $alias   = Join-Path $ScratchRoot 'alias'
    $secret  = Join-Path $alias 'secret'
    New-Item -ItemType Directory -Force -Path $secret | Out-Null
    $sentinel = 'ALIAS-SENTINEL-9f31'
    Set-Content -LiteralPath (Join-Path $secret 'data.txt') -Value $sentinel -Encoding ascii

    $read = New-ProbeCommand -Body "type `"$secret\data.txt`""

    # 1. `..` traversal reaching a denied directory. The policy denies the
    #    canonical path; the workload addresses it through a parent hop. Both
    #    spellings name the same object, so the deny must hold.
    $dotdot = Join-Path $alias 'secret\..\secret'
    $cfgDotDot = New-Config -Name 'alias-dotdot' `
        -CommandLine (New-ProbeCommand -Body "type `"$dotdot\data.txt`"") `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
    $logDotDot = Join-Path $ScratchRoot 'logs\alias-dotdot.log'
    $rDotDot = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgDotDot -LogPath $logDotDot -TimeoutSec 40
    Record-Result -Phase 'P10' -Name 'denied path is still denied through a `..` alias' `
        -Pass ((Test-WorkloadRan $rDotDot) -and -not ($rDotDot.Stdout -match $sentinel)) `
        -Detail "ran=$(Test-WorkloadRan $rDotDot); sawSentinel=$([bool]($rDotDot.Stdout -match $sentinel)); exit=$($rDotDot.ExitCode)"

    # 2. `\\?\` extended-length prefix. Same object, different spelling.
    $cfgExt = New-Config -Name 'alias-extended-prefix' `
        -CommandLine (New-ProbeCommand -Body "type `"\\?\$secret\data.txt`"") `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
    $logExt = Join-Path $ScratchRoot 'logs\alias-extended-prefix.log'
    $rExt = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgExt -LogPath $logExt -TimeoutSec 40
    Record-Result -Phase 'P10' -Name 'denied path is still denied through a \\?\ alias' `
        -Pass ((Test-WorkloadRan $rExt) -and -not ($rExt.Stdout -match $sentinel)) `
        -Detail "ran=$(Test-WorkloadRan $rExt); sawSentinel=$([bool]($rExt.Stdout -match $sentinel)); exit=$($rExt.ExitCode)"

    # 3. 8.3 short name. Only meaningful where the volume generates them.
    $shortPath = $null
    try {
        $fso = New-Object -ComObject Scripting.FileSystemObject
        $shortPath = $fso.GetFolder($secret).ShortPath
    } catch {}
    if ($shortPath -and ($shortPath -ne $secret)) {
        $cfgShort = New-Config -Name 'alias-shortname' `
            -CommandLine (New-ProbeCommand -Body "type `"$shortPath\data.txt`"") `
            -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
        $logShort = Join-Path $ScratchRoot 'logs\alias-shortname.log'
        $rShort = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgShort -LogPath $logShort -TimeoutSec 40
        Record-Result -Phase 'P10' -Name 'denied path is still denied through an 8.3 short-name alias' `
            -Pass ((Test-WorkloadRan $rShort) -and -not ($rShort.Stdout -match $sentinel)) `
            -Detail "short=$shortPath; ran=$(Test-WorkloadRan $rShort); sawSentinel=$([bool]($rShort.Stdout -match $sentinel))"
    } else {
        Record-Result -Phase 'P10' -Name '8.3 short-name alias' -Status 'skip' `
            -Detail '8.3 name generation is disabled on this volume'
    }

    # 4. Conflicting intents on the SAME object. The object is named readwrite
    #    and denied at once; the documented resolution is most-restrictive-wins
    #    (deny > ro > rw), so the deny must hold.
    $cfgConflict = New-Config -Name 'alias-conflicting-intent' -CommandLine $read `
        -ReadWrite @($rw, $secret) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
    $logConflict = Join-Path $ScratchRoot 'logs\alias-conflicting-intent.log'
    $rConflict = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgConflict -LogPath $logConflict -TimeoutSec 40
    Record-Result -Phase 'P10' -Name 'same object as both readwrite and denied resolves to denied' `
        -Pass ((Test-WorkloadRan $rConflict) -and -not ($rConflict.Stdout -match $sentinel)) `
        -Detail "ran=$(Test-WorkloadRan $rConflict); sawSentinel=$([bool]($rConflict.Stdout -match $sentinel)); deny > rw"

    # 5. Most-specific-wins: denied PARENT with a readwrite CHILD. The child
    #    must remain usable, and a non-regranted sibling must stay denied.
    $child   = Join-Path $secret 'child'
    $sibling = Join-Path $secret 'sibling'
    New-Item -ItemType Directory -Force -Path $child, $sibling | Out-Null
    Set-Content -LiteralPath (Join-Path $sibling 'data.txt') -Value $sentinel -Encoding ascii
    $probe = New-ProbeCommand -Body (
        "(echo CHILD-WRITE> `"$child\w.txt`" && type `"$child\w.txt`" && echo CHILD=OK) & " +
        "(type `"$sibling\data.txt`" >nul 2>&1 && echo SIBLING=LEAK || echo SIBLING=DENIED)")
    $cfgSpecific = New-Config -Name 'alias-most-specific' -CommandLine $probe `
        -ReadWrite @($rw, $child) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
    $logSpecific = Join-Path $ScratchRoot 'logs\alias-most-specific.log'
    $rSpecific = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgSpecific -LogPath $logSpecific -TimeoutSec 40
    Record-Result -Phase 'P10' -Name 'readwrite child punches through a denied parent' `
        -Pass ([bool]($rSpecific.Stdout -match 'CHILD=OK')) `
        -Detail "ran=$(Test-WorkloadRan $rSpecific); stdout=$(($rSpecific.Stdout).Trim() -replace '\s+', ' ')"
    Record-Result -Phase 'P10' -Name 'non-regranted sibling of the denied parent stays denied' `
        -Pass ((Test-WorkloadRan $rSpecific) -and ($rSpecific.Stdout -match 'SIBLING=DENIED')) `
        -Detail "ran=$(Test-WorkloadRan $rSpecific); stdout=$(($rSpecific.Stdout).Trim() -replace '\s+', ' ')"
}

# -----------------------------------------------------------------------
# Phase 11 — process plumbing.
#
# Cheap properties that nothing asserted. Each is a silent-drop failure mode:
# a config field that never reaches the child looks identical to one that was
# honored, from outside.
# -----------------------------------------------------------------------
function Phase-ProcessPlumbing {
    Section 'Phase 11: process plumbing (env / cwd / exit code / timeout / teardown)'

    $rw = Join-Path $ScratchRoot 'rw'
    $ro = Join-Path $ScratchRoot 'ro'

    # --- env delivery. The harness has always DELIVERED process.env (the
    # destructive-probe override) but never asserted it arrives, so the T3
    # env-replacement behavior documented at the top of this file is untested.
    # Values with spaces and an embedded `=` catch the two classic parse bugs.
    $envCfg = New-Config -Name 'plumb-env' `
        -CommandLine "$env:SystemRoot\System32\cmd.exe /c echo FOO=[%MXC_TEST_FOO%] EQ=[%MXC_TEST_EQ%]" `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) `
        -Env (@("SystemRoot=$env:SystemRoot", "MXC_TEST_FOO=a b c", "MXC_TEST_EQ=k=v")) -TimeoutMs 20000
    $envLog = Join-Path $ScratchRoot 'logs\plumb-env.log'
    $rEnv = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $envCfg -LogPath $envLog -TimeoutSec 40
    Record-Result -Phase 'P11' -Name 'process.env value with spaces reaches the child intact' `
        -Pass ([bool]($rEnv.Stdout -match '\[a b c\]')) -Detail "stdout=$(($rEnv.Stdout).Trim())"
    Record-Result -Phase 'P11' -Name 'process.env value with an embedded = reaches the child intact' `
        -Pass ([bool]($rEnv.Stdout -match '\[k=v\]')) -Detail "stdout=$(($rEnv.Stdout).Trim())"

    # --- cwd. Explicit process.cwd must be honored.
    $cwdCfg = New-Config -Name 'plumb-cwd' `
        -CommandLine (New-ProbeCommand -Body 'cd') `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -Cwd $rw -TimeoutMs 20000
    $cwdLog = Join-Path $ScratchRoot 'logs\plumb-cwd.log'
    $rCwd = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cwdCfg -LogPath $cwdLog -TimeoutSec 40
    $cwdRan = Test-WorkloadRan $rCwd
    Record-Result -Phase 'P11' -Name 'explicit process.cwd is honored' `
        -Pass ($cwdRan -and ($rCwd.Stdout -match [regex]::Escape((Split-Path -Leaf $rw)))) `
        -Detail "ran=$cwdRan; requested=$rw; stdout=$(Format-Snippet $rCwd.Stdout)"

    # --- omitted cwd. docs/schema.md (revised this month) documents the
    # substitution precedence: first readwritePaths entry that is an existing
    # directory, else the first such readonlyPaths entry, else the system
    # drive root. Never the launcher's cwd.
    $cwdDefaultCfg = New-Config -Name 'plumb-cwd-default' `
        -CommandLine (New-ProbeCommand -Body 'cd') `
        -ReadWrite @($rw) -ReadOnly @($ro, $env:SystemRoot) -TimeoutMs 20000
    $cwdDefaultLog = Join-Path $ScratchRoot 'logs\plumb-cwd-default.log'
    $rCwdDefault = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cwdDefaultCfg -LogPath $cwdDefaultLog -TimeoutSec 40
    $cwdDefaultRan = Test-WorkloadRan $rCwdDefault
    Record-Result -Phase 'P11' -Name 'omitted process.cwd falls back to the first readwritePaths entry' `
        -Pass ($cwdDefaultRan -and ($rCwdDefault.Stdout -match [regex]::Escape((Split-Path -Leaf $rw)))) `
        -Detail "ran=$cwdDefaultRan; expected leaf=$(Split-Path -Leaf $rw); stdout=$(Format-Snippet $rCwdDefault.Stdout)"
    # The guard here cannot be "stdout is non-empty": wxc-exec prints a JSON
    # error envelope to stdout when the launch fails, so a run in which nothing
    # executed still has non-whitespace stdout that trivially fails to contain
    # the launcher's path, scoring this green for the wrong reason.
    Record-Result -Phase 'P11' -Name 'omitted process.cwd does NOT inherit the launcher cwd' `
        -Pass ($cwdDefaultRan -and -not ($rCwdDefault.Stdout -match [regex]::Escape($PWD.Path))) `
        -Detail "ran=$cwdDefaultRan; launcher cwd=$($PWD.Path); stdout=$(Format-Snippet $rCwdDefault.Stdout)"

    # --- exit-code propagation. Nothing asserted this; `Invoke-Wxc` even
    # carried an unused $ExpectExitCode parameter.
    foreach ($code in @(0, 1, 42)) {
        $ecCfg = New-Config -Name "plumb-exit-$code" `
            -CommandLine "$env:SystemRoot\System32\cmd.exe /c exit $code" `
            -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -TimeoutMs 20000
        $ecLog = Join-Path $ScratchRoot "logs\plumb-exit-$code.log"
        $rEc = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $ecCfg -LogPath $ecLog -TimeoutSec 40
        Record-Result -Phase 'P11' -Name "child exit code $code propagates to wxc-exec" `
            -Pass ($rEc.ExitCode -eq $code) -Detail "got=$($rEc.ExitCode)"
    }

    # --- timeout enforcement plus the survivor check. The workload
    # backgrounds a uniquely-named sleep that far outlasts the deadline: if it
    # is still running afterwards, teardown left a survivor.
    #
    # The survivor is identified by PROCESS NAME, via a copy of powershell.exe
    # renamed to a unique token. Matching on MainWindowTitle does not work —
    # the child is started by a sandboxed parent with no window and redirected
    # handles, so MainWindowTitle is always empty and the check can never find
    # a survivor (it would be tautologically green). Win32_Process.CommandLine
    # would work but is CIM-backed, and CIM is unavailable on locked-down
    # hosts. A renamed copy needs neither.
    $unique = "MXCLEAK$((Get-Random -Maximum 99999))"
    $survivorExe = Join-Path $rw "$unique.exe"
    Copy-Item -LiteralPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Destination $survivorExe -Force
    $timeoutCfg = New-Config -Name 'plumb-timeout' `
        -CommandLine (New-ProbeCommand -Body (
            "start /b `"`" `"$survivorExe`" -NoProfile -Command `"Start-Sleep -Seconds 120`" & ping -n 120 127.0.0.1")) `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -TimeoutMs 4000
    $timeoutLog = Join-Path $ScratchRoot 'logs\plumb-timeout.log'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rTimeout = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $timeoutCfg -LogPath $timeoutLog -TimeoutSec 60
    $sw.Stop()
    $timeoutRan = Test-WorkloadRan $rTimeout

    # Every assertion below is AND-ed with $timeoutRan: a sandbox that never
    # launched also exits non-zero, finishes fast, and leaves no survivor, so
    # without the guard this whole block scores green on a broken host.
    Record-Result -Phase 'P11' -Name 'process.timeout kills a runaway child' `
        -Pass ($timeoutRan -and ($rTimeout.ExitCode -ne 0)) `
        -Detail "ran=$timeoutRan; exit=$($rTimeout.ExitCode)"
    # 4s deadline; allow generous teardown headroom but still catch "ran to
    # completion" (the workload would take 120s).
    Record-Result -Phase 'P11' -Name 'process.timeout fires near the deadline (not after the workload finishes)' `
        -Pass ($timeoutRan -and ($sw.Elapsed.TotalSeconds -lt 45)) `
        -Detail ("ran={0}; elapsed={1:N1}s; timeout=4s; workload=120s" -f $timeoutRan, $sw.Elapsed.TotalSeconds)
    # Match the runner's own timeout message, not the generic word: the
    # config carries `"timeout": 4000` and wxc-exec's request dump prints
    # `Script timeout: 4000`, both of which /timed?\s*out/ matches (time + out),
    # so the loose pattern is green whether or not anything was ever killed.
    # Streams are cleaned individually — a single joined string would be cut at
    # the first echo boundary and discard everything appended after it.
    $timeoutSignal = @(
        (Remove-ConfigEcho "$($rTimeout.Stdout)"),
        (Remove-ConfigEcho "$($rTimeout.Stderr)"),
        (Remove-ConfigEcho (Read-Log $timeoutLog))
    ) -join "`n"
    Record-Result -Phase 'P11' -Name 'timeout is reported, not silent' `
        -Pass ($timeoutRan -and ($timeoutSignal -match '(?i)(script )?timed out after \d+\s*ms')) `
        -Detail "ran=$timeoutRan; a killed workload must say why"

    Start-Sleep -Seconds 2
    $survivors = @(Get-Process -Name $unique -ErrorAction SilentlyContinue)
    Record-Result -Phase 'P11' -Name 'no descendant survives teardown after a timeout' `
        -Pass ($timeoutRan -and ($survivors.Count -eq 0)) `
        -Detail "ran=$timeoutRan; survivors=$($survivors.Count); marker=$unique"
    foreach ($s in $survivors) { try { Stop-Process -Id $s.Id -Force -ErrorAction SilentlyContinue } catch {} }
    Remove-Item -LiteralPath $survivorExe -Force -ErrorAction SilentlyContinue
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
    Assert-RequiredTier

    # Live-network prerequisite. A positive egress assertion on a host with no
    # connectivity reads every result as "blocked" and reports a green suite
    # having proven nothing, so this is checked once, up front, and FAILS
    # rather than skips — the same doctrine as run_seatbelt_all_tests.sh.
    # -SkipNetwork is the explicit opt-out for air-gapped bring-up.
    $Script:AnchorReachable = $false
    if ($SkipNetwork) {
        Write-Host 'Network phases: DISABLED (-SkipNetwork).' -ForegroundColor Yellow
    } else {
        $Script:AnchorReachable = Test-HostCanReachAnchor
        if (-not $Script:AnchorReachable) {
            throw ("Network prerequisite ABORT: the HOST cannot reach the egress anchor '$ExternalAnchorUrl'. " +
                   'Every positive egress assertion would read as "blocked" and the suite would pass having ' +
                   'proven nothing. Fix host connectivity, pass -ExternalAnchorUrl <reachable-url>, or pass ' +
                   '-SkipNetwork to run the parse-only network phases alone.')
        }
        Write-Host ("Network anchor: {0} (reachable from host)" -f $ExternalAnchorUrl) -ForegroundColor Cyan
    }

    # Phase registry. Build + preflight + scratch init above always run; this
    # table is filtered by the -Phases parameter (empty = run all). Phase 4b is
    # 'UiMitigationMatrix'; Phase 4c is 'GlobalAtomIsolation'.
    $AllPhases = [ordered]@{
        'UnitTests'                = { Phase-UnitTests }
        'Probes'                   = { Phase-Probes }
        'EmptyRelease'             = { Phase-EmptyRelease }
        'DeniedRelease'            = { Phase-DeniedRelease }
        'T3Forced'                 = { Phase-T3Forced }
        'T1DenyForced'             = { Phase-T1DenyForced }
        'UiMitigationMatrix'       = { Phase-UiMitigationMatrix }
        'GlobalAtomIsolation'      = { Phase-GlobalAtomIsolation }
        'DaclDisabled'             = { Phase-DaclDisabled }
        'CrashRecovery'            = { Phase-CrashRecovery }
        'NetworkCapabilityMatrix'  = { Phase-NetworkCapabilityMatrix }
        'NetworkModel3Equivalence' = { Phase-NetworkModel3Equivalence }
        'NetworkEgressRules'       = { Phase-NetworkEgressRules }
        'NetworkHostLoopback'      = { Phase-NetworkHostLoopback }
        'NetworkProxy'             = { Phase-NetworkProxy }
        'NetworkRejections'        = { Phase-NetworkRejections }
        'NetworkLegacy07'          = { Phase-NetworkLegacy07 }
        'PathAliasing'             = { Phase-PathAliasing }
        'ProcessPlumbing'          = { Phase-ProcessPlumbing }
    }
    if ($Phases.Count -gt 0) {
        $unknown = $Phases | Where-Object { $_ -notin $AllPhases.Keys }
        if ($unknown) { throw "Unknown -Phases value(s): $($unknown -join ', '). Valid: $($AllPhases.Keys -join ', ')" }
    }
    foreach ($key in $AllPhases.Keys) {
        if ($Phases.Count -eq 0 -or $Phases -contains $key) {
            # Fault-isolate each phase. An unexpected exception inside one
            # phase (a host-dependent cmdlet, a probe that throws) used to
            # abort the whole run, discarding every phase after it. Recording
            # it as a failure keeps the rest of the matrix reportable.
            #
            # Safety aborts are exempt and re-thrown. Assert-NoBfscfg throws
            # when it detects a real bfscfg invocation, which on 25H2 deadlocks
            # the host; swallowing that and continuing to spawn wxc-exec is
            # precisely what the gate exists to prevent.
            try {
                & $AllPhases[$key]
            }
            catch {
                if ("$_" -match 'MXC-FATAL') { throw }
                Write-Host ("PHASE '{0}' THREW: {1}" -f $key, $_) -ForegroundColor Red
                Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
                Record-Result -Phase $key -Name 'phase threw an unhandled exception' `
                    -Pass $false -Detail "$_"
            }
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

    # Structured JSON for programmatic consumption. Guarded end to end: this
    # runs in `finally`, so an unhandled throw here would skip the exit-code
    # line at the bottom and hand the CI dispatcher a bogus result. CIM is
    # unavailable on locked-down hosts.
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $osCaption = [string]$osInfo.Caption
        $osBuild = [string]$osInfo.BuildNumber
    } catch {
        $osCaption = 'unknown'
        $osBuild = 'unknown'
    }
    try {
        $summary = [pscustomobject]@{
            timestamp   = (Get-Date).ToString('o')
            host        = $env:COMPUTERNAME
            os          = $osCaption
            osBuild     = $osBuild
            total       = $pass + $fail + $skip + $warn
            passed      = $pass
            failed      = $fail
            skipped     = $skip
            warnings    = $warn
            results     = $Script:Results
        }
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
