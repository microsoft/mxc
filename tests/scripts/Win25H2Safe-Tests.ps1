# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Win25H2Safe-Tests.ps1
#
# Exercises the BaseContainer-fallback work (downlevel-phase5 branch) on a
# Windows 11 25H2 host without ever invoking bfscfg.exe (which would
# hard-lock the bfs.sys minifilter on 25H2).
#
# Safety model (`tier2_bfs` Cargo feature OFF, the default):
#   * Test-Preflight refuses to run if either wxc-exec binary reports
#     `bfsCompiledIn=true` in --probe output. This is the load-bearing
#     gate; everything else is belt-and-suspenders.
#   * With `tier2_bfs` off, `fallback_detector::find_bfscfg_exe`
#     returns `Ok(None)` unconditionally and the spawn site itself is
#     gated. The dispatcher's natural T2→T3 fallback fires for any
#     policy with rw/ro/denied paths.
#   * Empty-policy runs still label the selected tier "appcontainer-bfs"
#     because `detect()` short-circuits to T2 when there is nothing to
#     configure. At runtime that path is a no-op — `configure()`
#     short-circuits before any bfscfg invocation.
#   * Every run is post-checked: if the captured log contains the
#     substring "bfscfg" (proof of an actual spawn), the run is
#     reported as failed and the harness aborts before the next test.
#   * The harness relies on **natural** tier selection — there is no
#     `-ForceTier` parameter and no `MXC_FORCE_TIER` env-var manipulation
#     (the env var is `#[cfg(test)]`-gated and has no effect on the
#     production wxc-exec binary). With `tier2_bfs` off, the detector
#     drops to T3 for any policy with rw/ro/denied paths, which is
#     exactly what the assertions below expect.

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
    [string]$ScratchRoot    = (Join-Path $env:TEMP 'mxc-25h2-tests'),
    # Default results/log files live in $env:TEMP but OUTSIDE $ScratchRoot
    # so `Initialize-Scratch`'s recursive nuke can't conflict with the
    # `Start-Transcript` file handle (the script starts the transcript
    # BEFORE wiping the scratch tree). The previous default landed them
    # under $ScratchRoot and tripped a "file in use" abort on every run.
    [string]$ResultsFile    = (Join-Path $env:TEMP 'Win25H2Safe-Tests.results.txt'),
    [string]$ResultsJson    = (Join-Path $env:TEMP 'Win25H2Safe-Tests.results.json'),
    [string]$CargoLog       = (Join-Path $env:TEMP 'Win25H2Safe-Tests.cargo.log'),
    [switch]$SkipBuild,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The UI-mitigation probe binary refuses EXITWINDOWS / WIN32K by
# default — running those operations outside a sandbox can log out
# the interactive user. Set the explicit override here so the AC
# child wxc_ui_probe inherits it via wxc-exec's env-passthrough.
# Without this, Phase 4b's EXITWINDOWS / WIN32K assertions fail with
# "DIAG: refused".
$env:MXC_PROBE_DESTRUCTIVE_OK = '1'

# -----------------------------------------------------------------------
# Result accumulator
# -----------------------------------------------------------------------
$Script:Results = [System.Collections.Generic.List[object]]::new()

function Record-Result {
    param(
        [Parameter(Mandatory)] [string]$Phase,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [bool]$Pass,
        [string]$Detail = ''
    )
    $entry = [pscustomobject]@{
        Phase  = $Phase
        Name   = $Name
        Pass   = $Pass
        Detail = $Detail
    }
    $Script:Results.Add($entry) | Out-Null
    $tag = if ($Pass) { '[PASS]' } else { '[FAIL]' }
    $color = if ($Pass) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1} :: {2} {3}" -f $tag, $Phase, $Name, $(if ($Detail) { "($Detail)" } else { '' })) -ForegroundColor $color
}

function Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
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
    Write-Host ("bfscfg.exe present in System32: {0}" -f $bfsPresent)
    if (-not $bfsPresent) {
        Write-Warning 'bfscfg.exe was not found in System32. The harness assumes 25H2-shaped hosts.'
    }

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
        [Nullable[bool]]$Injection          = $null
    )
    $obj = [ordered]@{
        version     = '0.5.0-dev'
        containerId = "MxcWin25H2-$Name"
        containment = 'appcontainer'
        process     = [ordered]@{
            commandLine = $CommandLine
            timeout     = $TimeoutMs
        }
    }
    if ($ReadWrite.Count -gt 0 -or $ReadOnly.Count -gt 0 -or $Denied.Count -gt 0) {
        $fs = [ordered]@{}
        if ($ReadWrite.Count -gt 0) { $fs['readwritePaths'] = @($ReadWrite) }
        if ($ReadOnly.Count -gt 0)  { $fs['readonlyPaths']  = @($ReadOnly) }
        if ($Denied.Count -gt 0)    { $fs['deniedPaths']    = @($Denied) }
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
# enforces this). With the feature off, `find_bfscfg_exe` returns
# `Ok(None)` unconditionally, so the detector drops to T3
# (`appcontainer-dacl`) for any policy with rw/ro/denied paths. The
# empty-policy probe still labels T2 because `detect()` short-circuits
# to T2 when there is nothing to configure — the runtime behavior is
# nonetheless the no-op T2 path, never spawning bfscfg.
# -----------------------------------------------------------------------
function Phase-Probes {
    Section 'Phase 1: --probe (read-only)'

    $rw = Join-Path $ScratchRoot 'rw'
    $denied = Join-Path $ScratchRoot 'denied'

    $probeEmpty = Invoke-Probe -Wxc $WxcRelease -Phase 'P1' -Name 'probe-no-config'
    if ($probeEmpty) {
        Record-Result -Phase 'P1' -Name 'BC API absent on this host' -Pass (-not $probeEmpty.probes.baseContainerApiPresent) -Detail "baseContainerApiPresent=$($probeEmpty.probes.baseContainerApiPresent)"
        Record-Result -Phase 'P1' -Name 'bfsCompiledIn=false (safety gate)' -Pass (-not $probeEmpty.probes.bfsCompiledIn) -Detail "bfsCompiledIn=$($probeEmpty.probes.bfsCompiledIn)"
        Record-Result -Phase 'P1' -Name 'bfscfgPresent=false when feature off' -Pass (-not $probeEmpty.probes.bfscfgPresent) -Detail "bfscfgPresent=$($probeEmpty.probes.bfscfgPresent)"
        Record-Result -Phase 'P1' -Name 'empty policy probe -> tier=appcontainer-bfs (cosmetic: detect() short-circuits)' -Pass ($probeEmpty.tier -eq 'appcontainer-bfs') -Detail "tier=$($probeEmpty.tier)"
        Record-Result -Phase 'P1' -Name 'empty policy probe -> needsDaclAugmentation=false' -Pass ($probeEmpty.needsDaclAugmentation -eq $false) -Detail "needsDaclAugmentation=$($probeEmpty.needsDaclAugmentation)"
    }

    $cfgRw = New-Config -Name 'probe-rw' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw)
    $probeRw = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgRw -Phase 'P1' -Name 'probe-rw-config'
    if ($probeRw) {
        Record-Result -Phase 'P1' -Name 'rw-paths probe -> tier=appcontainer-dacl (T2 gated out)' -Pass ($probeRw.tier -eq 'appcontainer-dacl') -Detail "tier=$($probeRw.tier)"
        Record-Result -Phase 'P1' -Name 'rw-paths probe -> needsDaclAugmentation=true' -Pass ($probeRw.needsDaclAugmentation -eq $true) -Detail "needsDaclAugmentation=$($probeRw.needsDaclAugmentation)"
    }

    $cfgDenied = New-Config -Name 'probe-denied' -CommandLine 'cmd /c exit 0' -Denied @($denied)
    $probeDenied = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgDenied -Phase 'P1' -Name 'probe-denied-config'
    if ($probeDenied) {
        Record-Result -Phase 'P1' -Name 'denied probe -> tier=appcontainer-dacl (T2 gated out)' -Pass ($probeDenied.tier -eq 'appcontainer-dacl') -Detail "tier=$($probeDenied.tier)"
        Record-Result -Phase 'P1' -Name 'denied probe -> needsDaclAugmentation=true' -Pass ($probeDenied.needsDaclAugmentation -eq $true) -Detail "needsDaclAugmentation=$($probeDenied.needsDaclAugmentation)"
    }

    $cfgRefuse = New-Config -Name 'probe-refuse' -CommandLine 'cmd /c exit 0' -ReadWrite @($rw) -AllowDaclMutation $false
    $probeRefuse = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfgRefuse -Phase 'P1' -Name 'probe-allow-dacl-false'
    if ($probeRefuse) {
        # With T2 gated out, rw-paths probe falls through to T3, which
        # requires DACL augmentation. allowDaclMutation=false therefore
        # trips DaclFallbackDisabled and the detector returns an error
        # (tier omitted).
        #
        # Under Set-StrictMode -Version Latest, accessing an absent
        # property throws; check existence via PSObject.Properties
        # instead of `$null -eq $obj.foo`.
        $tierMissing = -not [bool]$probeRefuse.PSObject.Properties['tier']
        $errorStr    = if ($probeRefuse.PSObject.Properties['error']) { [string]$probeRefuse.error } else { '' }
        Record-Result -Phase 'P1' -Name 'allowDaclMutation=false + rw-paths probe -> error (T3 needs DACL)' -Pass ($tierMissing -and ($errorStr -match 'DACL fallback')) -Detail "tierMissing=$tierMissing; error=$errorStr"
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
    # Empty-policy run naturally selects T2; the assertion is that
    # bfscfg.exe was NOT actually invoked (configure() short-circuits).
    Assert-NoBfscfg -LogContent $logContent -Phase 'P2' -Name 'empty-release' -AllowBfsTierSelection

    Record-Result -Phase 'P2' -Name 'release exit=0' -Pass ($r.ExitCode -eq 0) -Detail "exit=$($r.ExitCode); stdout=$($r.Stdout.Trim())"
    Record-Result -Phase 'P2' -Name 'AppContainer ran the child (stdout round-trip)' -Pass ($r.Stdout -match 'P2-empty-release-ok')
    Record-Result -Phase 'P2' -Name 'selected isolation tier: appcontainer-bfs (expected, no invocation)' -Pass ([bool]($logContent -match '(?im)selected isolation tier:.*?appcontainer-bfs'))
    Record-Result -Phase 'P2' -Name 'no bfscfg invocation in log' -Pass (-not ($logContent -match '(?im)Output from bfscfg\.exe'))
    Record-Result -Phase 'P2' -Name 'UI Job Object assigned telemetry' -Pass ([bool]($logContent -match 'UI Job Object assigned'))
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
    Record-Result -Phase 'P3' -Name 'selected isolation tier: appcontainer-dacl (T2 gated out)' -Pass ([bool]($logContent -match '(?im)selected isolation tier:.*?appcontainer-dacl'))
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
    $cfg = New-Config -Name 't3-forced' -CommandLine $cmd -ReadWrite @($rw) -ReadOnly @($ro) -Denied @($denied)
    $log = Join-Path $ScratchRoot 'logs\t3-forced.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log
    $logContent = Read-Log $log
    Assert-NoBfscfg -LogContent $logContent -Phase 'P4' -Name 't3-forced'

    $aclRwAfter     = Get-Acl-Snapshot $rw
    $aclRoAfter     = Get-Acl-Snapshot $ro
    $aclDeniedAfter = Get-Acl-Snapshot $denied
    $stateAfter     = @(Get-StateFiles)

    Record-Result -Phase 'P4' -Name 'child exit=0' -Pass ($r.ExitCode -eq 0) -Detail "exit=$($r.ExitCode)"
    Record-Result -Phase 'P4' -Name 'selected isolation tier: appcontainer-dacl' -Pass ([bool]($logContent -match '(?im)selected isolation tier:.*?appcontainer-dacl'))
    Record-Result -Phase 'P4' -Name 'UI Job Object assigned telemetry' -Pass ([bool]($logContent -match 'UI Job Object assigned'))
    Record-Result -Phase 'P4' -Name 'Win32k mitigation applied telemetry (ui.disable=false -> not expected)' -Pass (-not ($logContent -match 'Win32k mitigation applied')) -Detail 'this config has ui.disable=false'
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

    Record-Result -Phase 'P4' -Name 'ui.disable=true emits Win32k mitigation applied' -Pass ([bool]($logContent2 -match 'Win32k mitigation applied')) -Detail "child exit=$($r2.ExitCode) (expected to fail; cmd.exe needs Win32k)"
    Record-Result -Phase 'P4' -Name 'ui.disable=true emits selected isolation tier: appcontainer-dacl' -Pass ([bool]($logContent2 -match '(?im)selected isolation tier:.*?appcontainer-dacl'))
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
    Record-Result -Phase 'P4' -Name 'sandbox blocks ping: selected isolation tier: appcontainer-dacl' -Pass ([bool]($logContentPing -match '(?im)selected isolation tier:.*?appcontainer-dacl'))
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
        # Denied + control: must fail both ways.
        Probe-Read  'DENIED_READ'    $denied  'readme.txt'
        Probe-Write 'DENIED_WRITE'   $denied  'denied_attempt.tmp'
        Probe-Read  'CONTROL_READ'   $control 'readme.txt'
        Probe-Write 'CONTROL_WRITE'  $control 'control_attempt.tmp'
    )
    $matrixCmd = 'cmd /c ' + ($clauses -join ' & ')

    $cfgMatrix = New-Config -Name 't3-access-matrix' -CommandLine $matrixCmd -ReadWrite @($rw) -ReadOnly @($ro) -Denied @($denied)
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
        Record-Result -Phase 'P4' -Name "matrix $Key=$Want ($Reason)" -Pass ($got -eq $Want) -Detail "got=$got; full=$matrixSummary"
    }

    Assert-Matrix 'RW_WRITE'       'PASS' 'rw grant must allow child to create files'
    Assert-Matrix 'RW_READ'        'PASS' 'rw grant must allow child to read its own file'
    Assert-Matrix 'RO_READ'        'PASS' 'ro grant must allow reads (tests ACE inheritance to existing children)'
    Assert-Matrix 'RO_WRITE'       'FAIL' 'ro grant must NOT allow writes'
    Assert-Matrix 'DENIED_READ'    'FAIL' 'denied path must block reads'
    Assert-Matrix 'DENIED_WRITE'   'FAIL' 'denied path must block writes'
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
#   1. Skip the phase entirely if the BaseContainer API is not present on
#      this host (most current 25H2 hosts). T1 force without the API
#      backing it cannot exercise the deny.
#   2. Create a marker file under a denied directory. Force T1. Have the
#      child try to `type` the marker. The child must exit non-zero AND
#      not echo the marker contents.
# -----------------------------------------------------------------------
function Phase-T1DenyForced {
    Section 'Phase 4c: T1 deny-ACE empirical test (skipped if BC API absent)'
    Clear-StateFiles

    # Use the release-build probe to discover BC API presence — same JSON
    # surface as Phase 1.
    $probe = Invoke-Probe -Wxc $WxcRelease -Phase 'P4c' -Name 'bc-presence-probe'
    if (-not $probe) {
        Record-Result -Phase 'P4c' -Name 'probe succeeded' -Pass $false -Detail 'probe returned null; cannot proceed'
        return
    }
    if (-not $probe.probes.baseContainerApiPresent) {
        Record-Result -Phase 'P4c' -Name 'BC API present (required for T1 test)' -Pass $true -Detail 'SKIPPED: baseContainerApiPresent=false on this host'
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
# Phase 4b — UI mitigation behavior matrix (T3 forced, debug build)
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
    Section 'Phase 4b: UI mitigation behavior matrix (T3 forced)'

    $rw = Join-Path $ScratchRoot 'rw'

    # ---------------- Scenario A: maximal UILIMIT bits -----------------
    # ui: disable=false (so Win32k is allowed but UILIMIT bits gate
    # specific operations), clipboard=none (block both R+W),
    # injection=false. base_process_ui: isolation=container (HANDLES +
    # GLOBALATOMS), desktopSystemControl=false (DESKTOP + EXITWINDOWS),
    # systemSettings=none (SYSTEMPARAMETERS + DISPLAYSETTINGS), ime=false.
    $probeArgsA = 'GLOBALATOMS READCLIPBOARD WRITECLIPBOARD SYSTEMPARAMETERS DISPLAYSETTINGS DESKTOP EXITWINDOWS HANDLES'
    $cmdA = "`"$UiProbeDebug`" $probeArgsA"
    $cfgA = New-Config -Name 'ui-matrix-A-allbits' `
        -CommandLine $cmdA `
        -ReadWrite @($rw) `
        -UiDisable $false `
        -Clipboard 'none' `
        -Injection $false `
        -BpUiIsolation 'container' `
        -BpUiDesktopControl $false `
        -BpUiSystemSettings 'none' `
        -BpUiIme $false
    $logA = Join-Path $ScratchRoot 'logs\ui-matrix-A.log'
    $rA = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgA -LogPath $logA
    $logContentA = Read-Log $logA
    Assert-NoBfscfg -LogContent $logContentA -Phase 'P4b' -Name 'ui-matrix-A'

    $matrixA = @{}
    foreach ($line in ($rA.Stdout -split "`r?`n")) {
        if ($line -match '^(?<k>GLOBALATOMS|READCLIPBOARD|WRITECLIPBOARD|SYSTEMPARAMETERS|DISPLAYSETTINGS|DESKTOP|EXITWINDOWS|HANDLES|WIN32K)=(?<v>PASS|FAIL)\s*$') {
            $matrixA[$matches['k']] = $matches['v']
        }
    }
    $summaryA = ($matrixA.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '

    Record-Result -Phase 'P4b' -Name 'scenarioA: UI Job Object assigned telemetry' -Pass ([bool]($logContentA -match 'UI Job Object assigned'))
    Record-Result -Phase 'P4b' -Name 'scenarioA: selected isolation tier: appcontainer-dacl' -Pass ([bool]($logContentA -match '(?im)selected isolation tier:.*?appcontainer-dacl'))
    # ui.disable=false on this run: Win32k mitigation applied must NOT appear.
    Record-Result -Phase 'P4b' -Name 'scenarioA: no Win32k mitigation applied (ui.disable=false)' -Pass (-not ($logContentA -match 'Win32k mitigation applied'))

    foreach ($tag in @('GLOBALATOMS','READCLIPBOARD','WRITECLIPBOARD','SYSTEMPARAMETERS','DISPLAYSETTINGS','DESKTOP','EXITWINDOWS','HANDLES')) {
        $got = if ($matrixA.ContainsKey($tag)) { $matrixA[$tag] } else { '<missing>' }
        Record-Result -Phase 'P4b' -Name "scenarioA: $tag blocked (probe -> PASS)" -Pass ($got -eq 'PASS') -Detail "got=$got; full=$summaryA"
    }

    # ---------------- Scenario B: ui.disable=true (Win32k mitigation) ----
    # WIN32K probe makes a Win32k syscall (GetMessageW). With the
    # mitigation in place the kernel terminates the process. If the
    # mitigation is NOT honored the probe prints WIN32K=FAIL and exits 0.
    $cmdB = "`"$UiProbeDebug`" WIN32K"
    $cfgB = New-Config -Name 'ui-matrix-B-win32k' `
        -CommandLine $cmdB `
        -ReadWrite @($rw) `
        -UiDisable $true
    $logB = Join-Path $ScratchRoot 'logs\ui-matrix-B.log'
    $rB = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgB -LogPath $logB
    $logContentB = Read-Log $logB
    Assert-NoBfscfg -LogContent $logContentB -Phase 'P4b' -Name 'ui-matrix-B'

    $printedFail = ($rB.Stdout -match '(?m)^WIN32K=FAIL\s*$')
    $printedPass = ($rB.Stdout -match '(?m)^WIN32K=PASS\s*$')

    Record-Result -Phase 'P4b' -Name 'scenarioB: Win32k mitigation applied telemetry' -Pass ([bool]($logContentB -match 'Win32k mitigation applied'))
    Record-Result -Phase 'P4b' -Name 'scenarioB: selected isolation tier: appcontainer-dacl' -Pass ([bool]($logContentB -match '(?im)selected isolation tier:.*?appcontainer-dacl'))
    # Mitigation worked iff the child never reported WIN32K=FAIL. Child
    # exit code is incidental — under the mitigation the process is killed
    # by the kernel; without it the probe completes and exits 0.
    Record-Result -Phase 'P4b' -Name 'scenarioB: child did NOT report WIN32K=FAIL (mitigation honored)' -Pass (-not $printedFail) -Detail "exit=$($rB.ExitCode); stdout=$($rB.Stdout.Trim())"
    Record-Result -Phase 'P4b' -Name 'scenarioB: child did NOT report WIN32K=PASS' -Pass (-not $printedPass) -Detail 'probe never returns PASS for WIN32K (process is killed before printing)'
}

# -----------------------------------------------------------------------
# Phase 5 — allowDaclMutation=false rejection under forced T3
# -----------------------------------------------------------------------
function Phase-DaclDisabled {
    Section 'Phase 5: debug build, T3 forced, allowDaclMutation=false'
    Clear-StateFiles

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
    Section 'Phase 6: debug build, T3 forced, taskkill mid-run (crash recovery)'
    Clear-StateFiles

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
    Set-Content -LiteralPath $CargoLog -Value "Win25H2Safe-Tests cargo log — $(Get-Date -Format 'o')`n" -Encoding utf8
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
    Initialize-Scratch

    Phase-UnitTests
    Phase-Probes
    Phase-EmptyRelease
    Phase-DeniedRelease
    Phase-T3Forced
    Phase-T1DenyForced
    Phase-UiMitigationMatrix
    Phase-DaclDisabled
    Phase-CrashRecovery
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
    $passed = @($Script:Results | Where-Object { $_.Pass })
    $failed = @($Script:Results | Where-Object { -not $_.Pass })
    $pass = $passed.Count
    $fail = $failed.Count
    Write-Host ("Total: {0}    Passed: {1}    Failed: {2}" -f ($pass + $fail), $pass, $fail)
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
        total       = $pass + $fail
        passed      = $pass
        failed      = $fail
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
