# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# WinProcessContainer.Common.ps1 — shared helpers for the Windows
# process-container suite (run_processcontainer_*.ps1).
#
# Dot-source this, do not Import-Module it: helpers read context variables
# ($ScratchRoot, $Script:ExpectedTier, ...) that Initialize-WpcContext sets in
# the caller's scope. As a module those names would bind to module scope.

# The probe binary refuses EXITWINDOWS / WIN32K unless it sees
# MXC_PROBE_DESTRUCTIVE_OK=1 — running them uncontained can log the user out.
# The T3 runner replaces the child environment with `process.env` when that is
# non-empty, so a process-level `$env:` never reaches the child; the override
# goes per-run through New-Config -Env (see Get-ProbeEnvWithDestructive). That
# block must be complete — CreateProcessW needs at least %SystemRoot% and
# fails with ERROR_ENVVAR_NOT_FOUND on a one-var block.


# Result accumulator
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

# Probes report TAG=PASS / TAG=FAIL, where PASS/FAIL describe the probe's
# notion of the outcome, not the harness verdict — so a green [PASS] line
# containing "got=FAIL" reads as a contradiction. These translate the tokens
# into verbs for display only. Callers pass the verb pair for the probe
# family: UI probes use blocked/allowed, the filesystem matrix allowed/denied.
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

# Pre-flight
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
}

function Assert-BfsSafety {
    # Refuse to run against a binary built with the tier2_bfs feature: T2 is
    # out of scope here, and spawning bfscfg.exe hard-locks the bfs.sys
    # minifilter on 25H2. Compile-time exclusion is what makes the suite safe;
    # this verifies it once per process.
    param([switch]$Quiet)
    $probe = & $WxcDebug --probe 2>$null | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $probe.probes.bfsCompiledIn) {
        throw "Preflight: $WxcDebug does not expose ``bfsCompiledIn`` in --probe output. Rebuild from a tree that has the tier2_bfs gate."
    }
    if ($probe.probes.bfsCompiledIn) {
        throw "Preflight ABORT: $WxcDebug was built with --features tier2_bfs. On 25H2 this risks an OS hang. Rebuild without the feature before re-running."
    }
    if (-not $Quiet) { Write-Host 'bfsCompiledIn: false' }
}

# Scratch + helpers
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
    Confirm-Scratch
}

function Confirm-Scratch {
    # Create whatever is missing without touching what is already there. The
    # entry script wipes the tree once and then hands the same path to every
    # child; a child that re-wiped would delete the logs and fixtures the
    # children before it produced.
    Assert-SafeScratchRoot
    if (-not (Test-Path $ScratchRoot)) {
        New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
    }
    foreach ($sub in @(
        'logs'
        'configs'
        'rw'
        'ro'
        'denied'
        # `control` is intentionally NOT named in any policy. Used by the
        # access-matrix sub-test to confirm AppContainer denies paths that
        # were never granted, not just ones explicitly denied.
        'control'
        # `alias` holds the path-aliasing fixtures: the same object reached
        # via `..`, an 8.3 short name, and the \\?\ prefix.
        'alias'
        # Per-child result documents, merged by the entry script.
        'results'
    )) {
        $path = Join-Path $ScratchRoot $sub
        if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null }
    }
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

$Script:StateFileBaseline = @()

function Reset-StateFileBaseline {
    # Records what is already in the shared dacl-restore directory so a phase
    # can assert "no NEW state file appeared". Deleting instead would destroy
    # the recovery records of unrelated MXC processes on the same host.
    $Script:StateFileBaseline = @(Get-StateFiles | ForEach-Object { $_.Name })
}

function Get-NewStateFiles {
    $baseline = @($Script:StateFileBaseline)
    Get-StateFiles | Where-Object { $baseline -notcontains $_.Name }
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

# Config generation
# Build a COMPLETE environment block (current process env + the destructive
# override) for the contained probe. See the note at the top of this file.
# Smallest environment a cmd.exe workload can still launch under, plus the
# caller's own variables. `process.env` replaces the environment outright, so
# a block with only the variable under test fails at CreateProcess.
# A caller-supplied process.env replaces the block wholesale, and Windows
# refuses to create a contained process whose env lacks SYSTEMROOT or
# LOCALAPPDATA (REQUIRED_CHILD_ENV_VARS in launch_diagnostics.rs). Both are
# included here so a fixture testing something else does not fail on that.
function Get-MinimalEnv {
    param([string[]]$Extra = @())
    $base = @()
    foreach ($name in 'SystemRoot', 'SystemDrive', 'windir', 'ComSpec', 'PATH', 'PATHEXT', 'LOCALAPPDATA', 'TEMP', 'TMP') {
        $value = [System.Environment]::GetEnvironmentVariable($name)
        if ($value) { $base += "$name=$value" }
    }
    return @($base + $Extra)
}

# The spec dump that names capabilities and UI limits is written only on the
# legacy SBOX path; PSEC logs a version+size line instead. Assertions that read
# the dump have nothing to read on a PSEC run.
function Test-SpecDumpAvailable {
    param([string]$LogContent)
    return -not ($LogContent -match 'process security environment spec built')
}

# Assert capability names reached the backend, skipping where the run took the
# PSEC path and produced no spec dump to read.
function Record-CapabilityLogged {
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()][string]$LogContent,
        [Parameter(Mandatory)][string[]]$Capability,
        [string]$Detail = ''
    )
    if (-not (Test-SpecDumpAvailable $LogContent)) {
        Record-Result -Phase $Phase -Name $Name -Status 'skip' `
            -Detail 'PSEC path selected; capabilities appear only in the legacy SBOX spec dump'
        return
    }
    $missing = @($Capability | Where-Object { $LogContent -notmatch ('(?i)' + [regex]::Escape($_)) })
    Record-Result -Phase $Phase -Name $Name -Pass ($missing.Count -eq 0) `
        -Detail ("$Detail; missing=[" + ($missing -join ', ') + ']')
}

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

# Derive the expected tier from --probe rather than hardcoding it, so the
# harness runs unchanged on T1 and T3 hosts. `tier2_bfs` is always off
# (Assert-BfsSafety enforces it), so the tier is the same for every policy
# shape: base-container when the empty-policy probe resolves to it, else
# appcontainer-dacl.
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
        # BaseContainer augments for denied paths only where the OS cannot
        # enforce them natively.
        'base-container'    { return ([bool]$HasDenied -and -not $Script:Caps.SupportsDeniedPaths) }
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

# Read the tier name back out of a run log. The logger stamps a timestamp
# before every write, so `[1789195588] ` sits between the label and the name.
function Get-SelectedTier {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$LogContent)
    $m = [regex]::Match($LogContent, '(?im)selected isolation tier:(?:\s|\[[^\]]*\])*([A-Za-z][A-Za-z0-9_-]*)')
    return $(if ($m.Success) { $m.Groups[1].Value.Trim() } else { '' })
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

# The two helpers above read BaseContainer's "[ui subsystem]" telemetry, which
# log_sandbox_spec() emits only behind `if !use_process_security_environment`.
# A PSEC run emits none of it regardless of how the limits were applied, so
# asserting on those tokens is unsound both ways — and a NEGATED assertion
# passes vacuously, which is the dangerous direction.
#
# Fail-closed: skip only on positive proof that PSEC built a spec. A run that
# died earlier matches neither marker and is asserted as before.
function Test-UiTelemetryAvailable {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$LogContent)
    if ($Script:ExpectedTier -eq 'appcontainer-dacl') { return $true }
    return -not ($LogContent -match '(?im)process security environment spec built \(PSEC')
}

# Record a BaseContainer UI-telemetry assertion, skipping it when the run took
# the PSEC path. $Expected is the value the token grep should return, so a
# caller asserting "mitigation NOT applied" passes -Expected $false rather than
# negating the result itself (which would defeat the skip).
function Record-UiTelemetryResult {
    param(
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()][string]$LogContent,
        [Parameter(Mandatory)][ValidateSet('ui-restrictions', 'win32k')][string]$Check,
        [bool]$Expected = $true,
        [string]$Detail = ''
    )
    if (-not (Test-UiTelemetryAvailable -LogContent $LogContent)) {
        $skipDetail = 'PSEC path selected; BaseContainer emits UI telemetry only on the legacy SBOX path'
        if ($Detail) { $skipDetail = "$Detail; $skipDetail" }
        Record-Result -Phase $Phase -Name $Name -Status 'skip' -Detail $skipDetail
        return
    }
    $actual = if ($Check -eq 'win32k') {
        Test-Win32kMitigationApplied -LogContent $LogContent
    } else {
        Test-UiRestrictionsApplied -LogContent $LogContent
    }
    Record-Result -Phase $Phase -Name $Name -Pass ($actual -eq $Expected) -Detail $Detail
}

# Default schema version for generated configs. Everything the 0.8 stable
# schema can express is authored at 0.8; the legacy network fields stay at 0.7
# (the legacy area builds those via -RawNetwork + -SchemaVersion), because 0.8
# is where the directional egress/ingress shape became the documented way to
# express network intent and no doc describes mixing the two in one config.
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
        [Nullable[bool]]$InheritDefaultEnv  = $null,
        # lifecycle.* — never exercised by any area before the lifecycle phase.
        [Nullable[bool]]$DestroyOnExit      = $null,
        [Nullable[bool]]$PreservePolicy     = $null,
        # telemetry.enabled — the config kill-switch (one of three independent
        # terms; it can only ever subtract from consent, never grant).
        [Nullable[bool]]$TelemetryEnabled   = $null,
        # Override the emitted schema version. Only for version-gating cases:
        # the default follows the legacy/directional split below.
        [string]$SchemaVersion              = $null,
        # `process` is the intent alias that must resolve to the concrete
        # Windows backend; `processcontainer` is the concrete name.
        [string]$Containment                = 'processcontainer',
        # processContainer.capabilities — the AppContainer capability list.
        [string[]]$Capabilities             = @(),
        [Nullable[bool]]$LeastPrivilege     = $null,
        [Nullable[bool]]$LearningMode       = $null,
        # processContainer.captureDenials.*
        [ValidateSet('block', 'allow')] [string]$CaptureDenialsMode = $null,
        [string]$CaptureDenialsOutputPath   = $null,
        [Nullable[bool]]$CaptureDenialsRetainEtl = $null,

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
        # Verbatim `network` block, for shapes the directional parameters above
        # cannot express -- the legacy 0.7 fields in particular. Pair it with
        # -SchemaVersion; it replaces the whole block rather than merging.
        [System.Collections.Specialized.OrderedDictionary]$RawNetwork = $null
    )

    $obj = [ordered]@{
        version     = $(if ($SchemaVersion) { $SchemaVersion } else { $Script:SchemaVersion })
        containerId = "MxcWinPC-$Name"
        # `appcontainer` is not in the stable containment enum at 0.7 or 0.8;
        # `processcontainer` is the concrete Windows backend on both.
        containment = $Containment
        process     = [ordered]@{
            commandLine = $CommandLine
            timeout     = $TimeoutMs
        }
    }
    if ($Cwd) { $obj['process']['cwd'] = $Cwd }
    if ($null -ne $Env -and $Env.Count -gt 0) { $obj['process']['env'] = @($Env) }
    if ($null -ne $InheritDefaultEnv) { $obj['process']['inheritDefaultEnv'] = [bool]$InheritDefaultEnv }
    if ($null -ne $DestroyOnExit -or $null -ne $PreservePolicy) {
        $lc = [ordered]@{}
        if ($null -ne $DestroyOnExit)  { $lc['destroyOnExit']  = [bool]$DestroyOnExit }
        if ($null -ne $PreservePolicy) { $lc['preservePolicy'] = [bool]$PreservePolicy }
        $obj['lifecycle'] = $lc
    }
    if ($null -ne $TelemetryEnabled) {
        $obj['telemetry'] = [ordered]@{ enabled = [bool]$TelemetryEnabled }
    }
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
    if ($null -ne $RawNetwork) {
        $obj['network'] = $RawNetwork
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
    if ($null -ne $LearningMode)    { $pc['learningMode']   = [bool]$LearningMode }
    if ($CaptureDenialsMode -or $CaptureDenialsOutputPath -or $null -ne $CaptureDenialsRetainEtl) {
        $cd = [ordered]@{}
        if ($CaptureDenialsMode)       { $cd['mode']       = $CaptureDenialsMode }
        if ($CaptureDenialsOutputPath) { $cd['outputPath'] = $CaptureDenialsOutputPath }
        if ($null -ne $CaptureDenialsRetainEtl) { $cd['retainEtl'] = [bool]$CaptureDenialsRetainEtl }
        $pc['captureDenials'] = $cd
    }
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

# Test runners
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

# Tier prerequisite
#
# Every expectation in this harness is derived from $Script:ExpectedTier, so
# the suite is self-consistent on ANY host — which also means a host that
# silently fell back to T3 runs the T3 assertions and reports green. A CI job
# named "process-t1" that never touched BaseContainer has proven nothing. When
# -RequireTier is passed the mismatch is a hard abort, not a skip.
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

# Network test infrastructure

# Documented in docs/process-container/networking.md §2: PSEC is the only
# ProcessContainer path that receives schema 0.8 egress filters, proxy peer
# identity, or host-loopback configuration. The probe does not name the
# process-creation contract, so the tier stands in for it — `base-container`
# is the only tier that can be on PSEC. A base-container host still running
# the transitional SBOX contract fails these, which is the correct signal.
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
    param([string]$Url = $ExternalAnchorUrl, [int]$TimeoutSec = 10, [switch]$IgnoreProxyEnv)
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    # curl honors HTTP_PROXY/HTTPS_PROXY. When a phase has deliberately pointed
    # those at a dead endpoint, an unqualified fetch reports BLOCKED whether or
    # not direct egress is actually restricted, so -IgnoreProxyEnv is required
    # for any assertion about the direct path.
    $noproxy = $(if ($IgnoreProxyEnv) { '--noproxy * ' } else { '' })
    return "$env:SystemRoot\System32\cmd.exe /c `"$curl --silent --show-error $noproxy--max-time $TimeoutSec --output NUL $Url && echo NET=REACHED || echo NET=BLOCKED`""
}

# Classify a completed run into REACHED / BLOCKED / NORUN. NORUN covers "the
# sandbox never got far enough to print", which no network assertion may score.
#
# Only stdout is examined, and that is load-bearing: on failure wxc-exec
# flushes the redacted config to stderr, and that echo contains the literal
# `echo NET=REACHED` from process.commandLine. Scanning stderr would score
# every failed run REACHED and make NORUN unreachable.
function Get-NetVerdict {
    param([Parameter(Mandatory)] $Result)
    $out = "$($Result.Stdout)"
    if ($out -match 'NET=REACHED') { return 'REACHED' }
    if ($out -match 'NET=BLOCKED') { return 'BLOCKED' }
    return 'NORUN'
}

# Strip wxc-exec's redacted config/request echo out of a captured stream.
#
# Without this a log assertion searches the harness's own config text, so a
# config carrying `capabilities: ["internetClient"]` matches whether or not the
# backend honored it — the silent drop the assertion exists to catch. The echo
# is a prefix, so keep the tail; JSON bodies are skipped by brace depth because
# a sandboxed TEMP path contains braces, balanced within its own line.
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
# Exit code alone cannot tell them apart: Invoke-Wxc synthesizes -1 on timeout,
# and wxc-exec exits -1 when the launch API fails on an unprepared host. Either
# would score every "must be rejected" assertion green on a host where nothing
# runs. So this requires positive evidence of a refusal and treats an
# unexplained failure as "not a rejection".
function Test-WasRejected {
    param(
        [Parameter(Mandatory)] [object]$Run,
        # Markers matched here come from the runner, never from a config echo.
        [string]$Log
    )
    $result = $(if ($Run.PSObject.Properties['Result']) { $Run.Result } else { $Run })
    if ($result.TimedOut) { return $false }
    if ($result.ExitCode -eq 0) { return $false }
    # wxc-exec exits 1 when it refuses a request and -1 when a launch API
    # fails, so a -1 is never a rejection no matter what else the log says.
    if ($result.ExitCode -eq -1) { return $false }
    if ($Run.PSObject.Properties['Verdict'] -and $Run.Verdict -ne 'NORUN') { return $false }

    $text = $Log
    if (-not $text -and $Run.PSObject.Properties['Log']) { $text = $Run.Log }
    $err = "$(if ($result.PSObject.Properties['Stderr']) { $result.Stderr })"
    $both = "$text`n$err"

    # Reached the launch API, so validation had already accepted the policy.
    if ($both -match '(?i)create_process_failed|CreateProcessInSandbox failed|CreateProcessSecurityEnvironment failed') {
        return $false
    }
    # Validation failures surface as config_parse or policy_validation.
    if ($both -match '"code"\s*:\s*"backend_error"') { return $false }
    # No tier could be built on this host, so the policy was never judged.
    # Emitted as a ConfigRejected event, which the typed checks above miss.
    if ($both -match '"reason"\s*:\s*"runner_unavailable"') { return $false }

    # Positive evidence. wxc-exec prints this banner for every request it
    # refuses, at parse stage and at backend validate. Requiring it means an
    # unexplained non-zero exit is NOT counted as a rejection.
    return [bool]($both -match '(?im)^\s*Request error\s*$' -or
                  $both -match '(?i)Configuration parse error' -or
                  $both -match '"code"\s*:\s*"(config_parse|policy_validation)"')
}

# The non-network counterpart of Get-NetVerdict's NORUN state.
#
# Every negative assertion is satisfied by a workload that never started, so
# on a mis-provisioned host it reports green having proven nothing.
# New-ProbeCommand prefixes an unconditional marker echo; a negative assertion
# must be AND-ed with this.
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
# A raw TcpListener, not HttpListener: the latter goes through http.sys and
# needs a URL ACL reservation an unelevated account lacks, so it fails to bind
# on exactly the hosts this phase must run on. The accept loop sits on a
# background runspace so the harness thread stays free.
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
# firewall` phase can assert MXC removes what it installed. Rules are named
# `WXC_<principal>_<millis>[_<action>_<index>]`, so an anchored `WXC_` prefix
# is the exact filter. netsh rather than Get-NetFirewallRule, which is
# CIM-backed and unavailable on locked-down hosts.
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


# Phase 8 — schema 0.8 directional network policy.
#
# Asserts the documented contract (docs/process-container/networking.md and
# docs/sandbox-policy/0.8.0/networking/networking.md), not the current code, so
# an assertion that outruns the backend fails by design. Every positive is
# paired with a negative control on an otherwise identical config: from one run
# on a host with no connectivity, "reached it" and "blocked by policy" look the
# same.

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
    return [pscustomobject]@{
        Result  = $r
        Log     = $logContent
        Verdict = (Get-NetVerdict -Result $r)
    }
}

# Suite context, dispatch, and reporting.
#
# The helpers above read their inputs by bare name ($ScratchRoot, $WxcDebug,
# $Script:ExpectedTier, ...); Initialize-WpcContext puts those names in scope.
# This file must be DOT-SOURCED so its `$Script:` assignments land in the
# calling script, the same scope the helpers resolve against.

# Captured while this file is being dot-sourced, when $PSScriptRoot still
# refers to <repo>\tests\scripts\lib.
$Script:WpcLibRoot    = $PSScriptRoot
$Script:WpcScriptRoot = Split-Path -Parent $PSScriptRoot
$Script:WpcRepoRoot   = Split-Path -Parent (Split-Path -Parent $Script:WpcScriptRoot)

function Initialize-WpcContext {
    # Resolves every path and switch the suite needs and publishes them into
    # the calling script's scope -- the one place a default is written down.
    #
    # The entry script resolves the context once and writes it to a JSON file;
    # each area is then launched with just -ContextJson. An explicitly supplied
    # parameter always wins over the file, so a standalone run with an override
    # behaves the same either way.
    #
    # -RequireTier is deliberately not [ValidateSet]-decorated: the attribute
    # binds to the variable and this function assigns through it, so the value
    # is validated below instead.
    [CmdletBinding()]
    param(
        [string]$ContextJson,
        [string]$RepoRoot,
        [string]$CargoRoot,
        [string]$WxcDebug,
        [string]$WxcRelease,
        [string]$UiProbeDebug,
        [string]$UiProbeRelease,
        [string]$ScratchRoot,
        [string]$ResultsFile,
        [string]$ResultsJson,
        [string]$CapsJson,
        [string]$RequireTier,
        [string]$ExternalAnchorUrl,
        [string]$UnlistedDestinationUrl,
        [switch]$SkipBuild,
        [switch]$KeepArtifacts,
        [switch]$SkipNetwork,
        [switch]$ReuseScratch,
        [string[]]$Phases,
        # Entry script only: build, run the full banner preflight, and wipe the
        # scratch tree. Children inherit all three.
        [switch]$Fresh
    )

    if ($ContextJson) {
        if (-not (Test-Path $ContextJson)) { throw "Context file not found: $ContextJson" }
        $inherited = Get-Content -Raw -LiteralPath $ContextJson | ConvertFrom-Json
        foreach ($prop in $inherited.PSObject.Properties) {
            if ($PSBoundParameters.ContainsKey($prop.Name)) { continue }
            if (-not $PSCmdlet.MyInvocation.MyCommand.Parameters.ContainsKey($prop.Name)) { continue }
            Set-Variable -Name $prop.Name -Value $prop.Value -Scope Local
        }
    }

    $suite = [System.IO.Path]::GetFileNameWithoutExtension((Get-PSCallStack)[1].ScriptName)
    if (-not $suite) { $suite = 'WinProcessContainer' }
    $Script:WpcSuiteName = $suite

    if (-not $RepoRoot)       { $RepoRoot       = $Script:WpcRepoRoot }
    if (-not $CargoRoot)      { $CargoRoot      = Join-Path $RepoRoot 'src' }
    if (-not $WxcDebug)       { $WxcDebug       = Join-Path $RepoRoot 'src\target\debug\wxc-exec.exe' }
    if (-not $WxcRelease)     { $WxcRelease     = Join-Path $RepoRoot 'src\target\release\wxc-exec.exe' }
    if (-not $UiProbeDebug)   { $UiProbeDebug   = Join-Path $RepoRoot 'src\target\debug\wxc-ui-probe.exe' }
    if (-not $UiProbeRelease) { $UiProbeRelease = Join-Path $RepoRoot 'src\target\release\wxc-ui-probe.exe' }
    if (-not $ScratchRoot)    { $ScratchRoot    = Join-Path $env:TEMP 'mxc-wpc-tests' }
    # Results/transcript live in $env:TEMP but OUTSIDE $ScratchRoot, so the
    # recursive wipe cannot collide with an open Start-Transcript handle.
    if (-not $ResultsFile)    { $ResultsFile    = Join-Path $env:TEMP "$suite.results.txt" }
    if (-not $ResultsJson)    { $ResultsJson    = Join-Path $env:TEMP "$suite.results.json" }
    if (-not $ExternalAnchorUrl)      { $ExternalAnchorUrl      = 'https://dev.azure.com' }
    if (-not $UnlistedDestinationUrl) { $UnlistedDestinationUrl = 'https://example.com' }

    $validTiers = @('base-container', 'appcontainer-dacl')
    if ($RequireTier -and $RequireTier -notin $validTiers) {
        throw "Invalid -RequireTier '$RequireTier'. Valid values: $($validTiers -join ', ')."
    }

    $Script:RepoRoot               = $RepoRoot
    $Script:CargoRoot              = $CargoRoot
    $Script:WxcDebug               = $WxcDebug
    $Script:WxcRelease             = $WxcRelease
    $Script:UiProbeDebug           = $UiProbeDebug
    $Script:UiProbeRelease         = $UiProbeRelease
    $Script:ScratchRoot            = $ScratchRoot
    $Script:ResultsFile            = $ResultsFile
    $Script:ResultsJson            = $ResultsJson
    $Script:RequireTier            = $RequireTier
    $Script:ExternalAnchorUrl      = $ExternalAnchorUrl
    $Script:UnlistedDestinationUrl = $UnlistedDestinationUrl
    $Script:SkipBuild              = [bool]$SkipBuild
    $Script:KeepArtifacts          = [bool]$KeepArtifacts
    $Script:SkipNetwork            = [bool]$SkipNetwork
    $Script:Phases                 = @($Phases)
    $Script:WpcFatal               = $false

    if ($Fresh) {
        Test-Preflight
    } else {
        foreach ($bin in @($WxcDebug, $WxcRelease)) {
            if (-not (Test-Path $bin)) { throw "Binary not found at $bin. Run run_processcontainer_all_tests.ps1, or pass -ContextJson." }
        }
    }
    Assert-BfsSafety -Quiet:(-not $Fresh)

    if ($Fresh -or -not $ReuseScratch) { Initialize-Scratch } else { Confirm-Scratch }

    # Host capabilities. The entry script probes once and hands the result to
    # every child; a standalone child probes for itself.
    if ($CapsJson -and (Test-Path $CapsJson)) {
        $Script:Caps = Get-Content -Raw -LiteralPath $CapsJson | ConvertFrom-Json
    } else {
        $Script:Caps = Get-HostCapabilities
    }
    $Script:ExpectedTier = $Script:Caps.BaselineTier
    Assert-RequiredTier

    # Live-network prerequisite. A positive egress assertion on a host with no
    # connectivity reads every result as "blocked" and reports a green suite
    # having proven nothing, so this is checked up front and FAILS rather than
    # skips — the same doctrine as run_seatbelt_all_tests.sh. -SkipNetwork is
    # the explicit opt-out for air-gapped bring-up.
    $Script:AnchorReachable = $false
    if ($SkipNetwork) {
        if ($Fresh) { Write-Host 'Network phases: DISABLED (-SkipNetwork).' -ForegroundColor Yellow }
    } else {
        $Script:AnchorReachable = Test-HostCanReachAnchor
        if (-not $Script:AnchorReachable) {
            throw ("Network prerequisite ABORT: the HOST cannot reach the egress anchor '$ExternalAnchorUrl'. " +
                   'Every positive egress assertion would read as "blocked" and the suite would pass having ' +
                   'proven nothing. Fix host connectivity, pass -ExternalAnchorUrl <reachable-url>, or pass ' +
                   '-SkipNetwork to run the parse-only network phases alone.')
        }
        if ($Fresh) { Write-Host ("Network anchor: {0} (reachable from host)" -f $ExternalAnchorUrl) -ForegroundColor Cyan }
    }

    if ($Fresh) {
        Write-Host ("Host capabilities: expectedTier={0} baseContainerUsable={1} apiPresent={2} bfscfgPresent={3} bfsCompiledIn={4} supportsDeniedPaths={5}" -f `
            $Script:Caps.BaselineTier, $Script:Caps.BaseContainerUsable, $Script:Caps.BaseContainerApiPresent, `
            $Script:Caps.BfscfgPresent, $Script:Caps.BfsCompiledIn, $Script:Caps.SupportsDeniedPaths) -ForegroundColor Cyan
    }
}

function Invoke-WpcPhase {
    # Fault-isolates one phase: an unexpected exception is recorded as a failure
    # rather than aborting, so the rest of the matrix stays reportable. MXC-FATAL
    # is latched instead, so Complete-WpcChild exits 78 and the entry script
    # stops dispatching.
    param(
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [scriptblock]$Body
    )
    try {
        & $Body
    }
    catch {
        $fatal = "$_" -match 'MXC-FATAL'
        Write-Host ("PHASE '{0}' THREW: {1}" -f $Key, $_) -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
        Record-Result -Phase $Key -Name 'phase threw an unhandled exception' -Pass $false -Detail "$_"
        if ($fatal) { $Script:WpcFatal = $true }
    }
}

function Get-WpcTally {
    param([object[]]$Results)
    $r = @($Results)
    [pscustomobject]@{
        Passed   = @($r | Where-Object { $_.Status -eq 'pass' })
        Failed   = @($r | Where-Object { $_.Status -eq 'fail' })
        Skipped  = @($r | Where-Object { $_.Status -eq 'skip' })
        Warned   = @($r | Where-Object { $_.Status -eq 'warn' })
    }
}

function Complete-WpcChild {
    # Terminal step of every per-area script: persist this script's assertions
    # for the entry script to merge, print a one-line tally, and exit.
    #
    # Exit codes are the contract with run_processcontainer_all_tests.ps1:
    #   0  every assertion passed (skip/warn do not fail)
    #   1  at least one failed, or nothing ran at all
    #   78 MXC-FATAL — stop the suite
    #
    # "Nothing ran" fails on purpose: a script recording no assertions has
    # proven nothing, and calling that success is the false green to avoid.
    $t = Get-WpcTally -Results $Script:Results
    $total = $t.Passed.Count + $t.Failed.Count + $t.Skipped.Count + $t.Warned.Count

    if ($Script:ResultsJson) {
        try {
            $doc = [pscustomobject]@{
                suite     = $Script:WpcSuiteName
                timestamp = (Get-Date).ToString('o')
                total     = $total
                passed    = $t.Passed.Count
                failed    = $t.Failed.Count
                skipped   = $t.Skipped.Count
                warnings  = $t.Warned.Count
                fatal     = $Script:WpcFatal
                results   = $Script:Results
            }
            $dir = Split-Path -Parent $Script:ResultsJson
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            ($doc | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $Script:ResultsJson -Encoding utf8 -Force
        } catch {
            Write-Host "warning: could not write results JSON: $_" -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host ("{0}: total={1} passed={2} failed={3} skipped={4} warnings={5}" -f `
        $Script:WpcSuiteName, $total, $t.Passed.Count, $t.Failed.Count, $t.Skipped.Count, $t.Warned.Count)

    # Standalone runs end here too, so leave the console as it was found.
    Reset-WpcConsoleColor

    if ($Script:WpcFatal) { exit 78 }
    if ($t.Failed.Count -gt 0 -or $total -eq 0) { exit 1 }
    exit 0
}

function Write-WpcContextFile {
    # Freeze the resolved suite context so every area inherits identical values
    # instead of re-deriving its own and disagreeing with its siblings.
    param([Parameter(Mandatory)] [string]$Path)
    $ctx = [ordered]@{
        RepoRoot               = $Script:RepoRoot
        CargoRoot              = $Script:CargoRoot
        WxcDebug               = $Script:WxcDebug
        WxcRelease             = $Script:WxcRelease
        UiProbeDebug           = $Script:UiProbeDebug
        UiProbeRelease         = $Script:UiProbeRelease
        ScratchRoot            = $Script:ScratchRoot
        CapsJson               = Join-Path $Script:ScratchRoot 'results\host-capabilities.json'
        ExternalAnchorUrl      = $Script:ExternalAnchorUrl
        UnlistedDestinationUrl = $Script:UnlistedDestinationUrl
        RequireTier            = [string]$Script:RequireTier
        # [bool] casts matter: these land in the caller's scope, where the entry
        # script's own param block types them as [switch], and ConvertTo-Json
        # writes a SwitchParameter as {"IsPresent":...} rather than a bool.
        SkipNetwork            = [bool]$Script:SkipNetwork
        KeepArtifacts          = [bool]$Script:KeepArtifacts
        ReuseScratch           = $true
    }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ($ctx | ConvertTo-Json -Depth 4) | Out-File -LiteralPath $Path -Encoding utf8 -Force
}

function Write-WpcChildOutput {
    # Re-emit an area script's output through this host so it reaches the
    # transcript, restoring the colour the child itself used.
    #
    # Colour is an attribute of the writing process's console, not bytes in the
    # stream, so it does not survive the pipe and a full-suite run would be
    # monochrome. Re-derive it from the line shapes Record-Result and Section
    # emit, so standalone and merged runs look identical.
    param([Parameter(ValueFromPipeline)] [object]$Line)
    begin { $inBanner = $false }
    process {
        $text = if ($null -eq $Line) { '' } else { [string]$Line }
        $color = $null
        if ($text -match '^={10,}\s*$') {
            # Section draws a bar, the title, then another bar. Toggling on the
            # bars colours the title without having to recognize the title text.
            $color = 'Cyan'
            $inBanner = -not $inBanner
        } elseif ($inBanner) {
            $color = 'Cyan'
        } else {
            switch -Regex ($text) {
                '^\s*\[PASS\]'          { $color = 'Green' }
                '^\s*\[FAIL\]'          { $color = 'Red' }
                '^\s*\[(SKIP|WARN)\]'   { $color = 'Yellow' }
                'MXC-FATAL'             { $color = 'Red' }
                '^PHASE .+ THREW:'      { $color = 'Red' }
                '^\s*warning:'          { $color = 'Yellow' }
            }
        }
        if ($color) { Write-Host $text -ForegroundColor $color } else { Write-Host $text }
    }
}

function Reset-WpcConsoleColor {
    # A process killed between set-foreground and restore — or a native binary
    # that sets the attribute itself — leaves the console tinted and every later
    # line inherits it. Re-assert a known state between areas. The Console
    # colour APIs throw when stdout is redirected (the CI case), so guard them.
    param([object]$To = $null)
    try {
        if ($null -ne $To) { [Console]::ForegroundColor = $To } else { [Console]::ResetColor() }
    } catch {}
}

function Get-WpcConsoleColor {
    # Snapshot the host's foreground colour, or $null when there is no console
    # to read (redirected output, CI). Paired with Reset-WpcConsoleColor.
    try { return [Console]::ForegroundColor } catch { return $null }
}

function Write-WpcSummary {
    # Renders the merged result set. Shared so a single-script run and the
    # full suite report failures in the same shape.
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Results)
    $t = Get-WpcTally -Results $Results
    $pass = $t.Passed.Count; $fail = $t.Failed.Count
    $skip = $t.Skipped.Count; $warn = $t.Warned.Count
    Write-Host ("Total: {0}    Passed: {1}    Failed: {2}    Skipped: {3}    Warnings: {4}" -f `
        ($pass + $fail + $skip + $warn), $pass, $fail, $skip, $warn)
    foreach ($group in @(
        @{ Items = $t.Warned;  Title = 'Warnings (constraint not enforced on this host):'; Color = 'Yellow' }
        @{ Items = $t.Skipped; Title = 'Skipped (not applicable on this host):';           Color = 'Yellow' }
        @{ Items = $t.Failed;  Title = 'Failures:';                                        Color = 'Red' }
    )) {
        if ($group.Items.Count -eq 0) { continue }
        Write-Host ''
        Write-Host $group.Title -ForegroundColor $group.Color
        foreach ($r in $group.Items) {
            Write-Host ("  [{0}] {1} :: {2}" -f $r.Phase, $r.Name, $r.Detail) -ForegroundColor $group.Color
        }
    }
}

