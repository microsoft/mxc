# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Test-PathEnumeration.ps1
#
# Empirically answers the open question in docs/downlevel-fallback-threat-model.md:
# can a Tier 3 sandboxed child enumerate host paths that no policy grants?
#
# Test setup:
#   Scratch tree with four sibling directories:
#     rw/      — granted in readwritePaths
#     ro/      — granted in readonlyPaths
#     denied/  — listed in deniedPaths (explicit Deny ACE)
#     control/ — NOT named in any policy (AppContainer baseline only)
#   Each is pre-staged with `readme.txt`, `canary.txt`, and a `subdir/`
#   so we can see all enumeration shapes (file, file, directory).
#
# Two probes run inside one forced-T3 child:
#
#   A. `if exist <dir>\readme.txt`
#      Tests whether a known filename is visible via path lookup. This
#      is the cheapest leak: the child only needs to *suspect* a name to
#      confirm it.
#
#   B. `dir /b <dir>` between BEGIN_X / END_X markers.
#      Tests whether the directory itself is enumerable. This is the
#      larger leak: the child doesn't need to guess any names; the
#      directory hands them over.
#
# For each directory we report:
#   EXIST=VISIBLE|HIDDEN    — result of probe A
#   LIST=ENUMERABLE|BLOCKED|EMPTY  — result of probe B (with sample entries)
#
# Exit code: 0 always (this is an information-gathering tool, not a
# regression check). Both leak signals are surfaced in the report.

[CmdletBinding()]
param(
    # This script lives in `<repo>\tests\scripts\`; the repo root is two levels up.
    [string]$RepoRoot    = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$WxcDebug    = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-exec.exe'),
    [string]$ScratchRoot = (Join-Path $env:TEMP 'mxc-enum-probe'),
    [switch]$SkipBuild,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -----------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------
if (-not $SkipBuild) {
    $cargoRoot = Join-Path $RepoRoot 'src'
    Push-Location $cargoRoot
    try {
        Write-Host "Building wxc-exec (debug)..." -ForegroundColor Cyan
        & cargo build -p wxc 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path $WxcDebug)) { throw "wxc-exec not found at $WxcDebug" }

# -----------------------------------------------------------------------
# Scratch
# -----------------------------------------------------------------------
if (Test-Path $ScratchRoot) {
    Remove-Item -Recurse -Force -LiteralPath $ScratchRoot
}
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null

foreach ($d in @('rw','ro','denied','control')) {
    $dirPath = Join-Path $ScratchRoot $d
    New-Item -ItemType Directory -Path $dirPath | Out-Null
    'readme content' | Out-File -LiteralPath (Join-Path $dirPath 'readme.txt') -Encoding ascii -Force
    'canary content' | Out-File -LiteralPath (Join-Path $dirPath 'canary.txt') -Encoding ascii -Force
    New-Item -ItemType Directory -Path (Join-Path $dirPath 'subdir') | Out-Null
    'inner'          | Out-File -LiteralPath (Join-Path $dirPath 'subdir\inner.txt') -Encoding ascii -Force
}

$rw      = Join-Path $ScratchRoot 'rw'
$ro      = Join-Path $ScratchRoot 'ro'
$denied  = Join-Path $ScratchRoot 'denied'
$control = Join-Path $ScratchRoot 'control'

# -----------------------------------------------------------------------
# Probe command
# -----------------------------------------------------------------------
# All chained into one `cmd /c` so the entire probe runs in one
# forced-T3 child. Tagged output (TAG=VALUE lines and BEGIN_X / END_X
# markers) is mixed with dir's natural output; the parser separates
# them after the fact.
$probes = @(
    # Existence probe (probe A above) — single line of TAG=VALUE per dir.
    "(if exist ""$rw\readme.txt"" (echo RW_EXIST=VISIBLE) else (echo RW_EXIST=HIDDEN))",
    "(if exist ""$ro\readme.txt"" (echo RO_EXIST=VISIBLE) else (echo RO_EXIST=HIDDEN))",
    "(if exist ""$denied\readme.txt"" (echo DENIED_EXIST=VISIBLE) else (echo DENIED_EXIST=HIDDEN))",
    "(if exist ""$control\readme.txt"" (echo CONTROL_EXIST=VISIBLE) else (echo CONTROL_EXIST=HIDDEN))",
    # Listing probe (probe B) — BEGIN_X / END_X markers bracket each
    # directory's `dir /b` output. The parser collects lines between
    # markers and classifies them as filenames or error text.
    # `2>&1` merges dir's stderr (where "Access is denied." goes on
    # failure) into stdout so we can classify the outcome.
    "echo BEGIN_RW & dir /b ""$rw"" 2>&1 & echo END_RW",
    "echo BEGIN_RO & dir /b ""$ro"" 2>&1 & echo END_RO",
    "echo BEGIN_DENIED & dir /b ""$denied"" 2>&1 & echo END_DENIED",
    "echo BEGIN_CONTROL & dir /b ""$control"" 2>&1 & echo END_CONTROL"
)
$probeCmd = 'cmd /c ' + ($probes -join ' & ')

# -----------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------
$configPath = Join-Path $ScratchRoot 'config.json'
$config = [ordered]@{
    version     = '0.5.0-dev'
    containerId = 'MxcEnumProbeTest'
    containment = 'appcontainer'
    process     = [ordered]@{
        commandLine = $probeCmd
        timeout     = 30000
    }
    filesystem  = [ordered]@{
        readwritePaths = @($rw)
        readonlyPaths  = @($ro)
        deniedPaths    = @($denied)
    }
    fallback    = [ordered]@{ allowDaclMutation = $true }
    ui          = [ordered]@{ disable = $false }
}
($config | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $configPath -Encoding utf8 -Force

# -----------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "Running probe inside forced-T3 AppContainer..." -ForegroundColor Cyan
$logPath = Join-Path $ScratchRoot 'wxc.log'
$env:MXC_FORCE_TIER = 'appcontainer-dacl'
try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $WxcDebug
    $psi.Arguments = "--debug --log-file `"$logPath`" `"$configPath`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    if (-not $proc.WaitForExit(60000)) {
        try { $proc.Kill() } catch {}
        throw "wxc-exec timed out"
    }
    $exitCode = $proc.ExitCode
} finally {
    Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue
}

$exitColor = if ($exitCode -eq 0) { 'Green' } else { 'Yellow' }
Write-Host "wxc-exec exit code: $exitCode" -ForegroundColor $exitColor

# Always dump stdout for diagnosis.
$stdoutPath = Join-Path $ScratchRoot 'probe.stdout.txt'
$stdout | Out-File -LiteralPath $stdoutPath -Encoding utf8 -Force
$stderrPath = Join-Path $ScratchRoot 'probe.stderr.txt'
$stderr | Out-File -LiteralPath $stderrPath -Encoding utf8 -Force

# Sanity check: the wxc log must show we actually got T3 routing.
$logContent = if (Test-Path $logPath) { Get-Content -Raw -LiteralPath $logPath } else { '' }
$tierSelected = if ($logContent -match 'tier_selected=(\S+)') { $matches[1] } else { '<unknown>' }
Write-Host "Tier selected: $tierSelected" -ForegroundColor $(if ($tierSelected -eq 'appcontainer-dacl') { 'Green' } else { 'Red' })
if ($tierSelected -ne 'appcontainer-dacl') {
    Write-Warning "Probe didn't run on T3; the empirical result below is not meaningful."
}

# -----------------------------------------------------------------------
# Parse
# -----------------------------------------------------------------------
$exists = @{}
foreach ($line in ($stdout -split "`r?`n")) {
    if ($line -match '^(?<k>RW|RO|DENIED|CONTROL)_EXIST=(?<v>VISIBLE|HIDDEN)\s*$') {
        $exists[$matches['k']] = $matches['v']
    }
}

function Get-ListSection {
    param([string]$Output, [string]$Tag)
    if ($Output -match "(?ms)^BEGIN_$Tag\s*$\s*(?<body>.*?)^END_$Tag\s*$") {
        return $matches['body']
    }
    return $null
}

$lists = @{}
foreach ($tag in @('RW','RO','DENIED','CONTROL')) {
    $body = Get-ListSection -Output $stdout -Tag $tag
    if ($null -eq $body) {
        $lists[$tag] = [pscustomobject]@{ Status='<missing>'; Entries=@(); Raw='' }
        continue
    }
    $rawLines = @($body -split "`r?`n" |
                  ForEach-Object { $_.Trim() } |
                  Where-Object { $_ -and $_ -notmatch '^Access is denied\.?$' -and $_ -notmatch '^File Not Found$' })
    if ($body -match 'Access is denied') {
        $lists[$tag] = [pscustomobject]@{ Status='BLOCKED'; Entries=$rawLines; Raw=$body }
    } elseif ($rawLines.Count -eq 0) {
        $lists[$tag] = [pscustomobject]@{ Status='EMPTY'; Entries=@(); Raw=$body }
    } else {
        $lists[$tag] = [pscustomobject]@{ Status='ENUMERABLE'; Entries=$rawLines; Raw=$body }
    }
}

# -----------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------
Write-Host ""
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host "Results" -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan

$expected = @{ RW='LEAK_EXPECTED'; RO='LEAK_EXPECTED'; DENIED='NO_LEAK_EXPECTED'; CONTROL='NO_LEAK_EXPECTED' }

foreach ($tag in @('RW','RO','DENIED','CONTROL')) {
    $existResult = if ($exists.ContainsKey($tag)) { $exists[$tag] } else { '<missing>' }
    $listResult  = $lists[$tag]
    $entries     = if ($listResult.Entries.Count -gt 0) { $listResult.Entries -join ',' } else { '' }

    $leakObserved = ($existResult -eq 'VISIBLE') -or ($listResult.Status -eq 'ENUMERABLE')
    $expectedLeak = ($expected[$tag] -eq 'LEAK_EXPECTED')
    $color = if ($leakObserved -eq $expectedLeak) { 'Green' } else { 'Yellow' }

    Write-Host ""
    Write-Host "  $tag (expected $($expected[$tag])):" -ForegroundColor $color
    Write-Host "    EXIST: $existResult" -ForegroundColor $color
    Write-Host "    LIST:  $($listResult.Status)$(if ($entries) { "  [$entries]" })" -ForegroundColor $color
}

# Headline finding
Write-Host ""
Write-Host ('-' * 72)
$deniedLeak  = ($exists['DENIED']  -eq 'VISIBLE') -or ($lists['DENIED'].Status  -eq 'ENUMERABLE')
$controlLeak = ($exists['CONTROL'] -eq 'VISIBLE') -or ($lists['CONTROL'].Status -eq 'ENUMERABLE')

if ($deniedLeak -or $controlLeak) {
    Write-Host "Headline: ENUMERATION LEAK DETECTED" -ForegroundColor Yellow
    if ($deniedLeak)  { Write-Host "  - Paths with explicit Deny ACE are enumerable from inside T3" -ForegroundColor Yellow }
    if ($controlLeak) { Write-Host "  - Paths with no policy (AppContainer baseline) are enumerable from inside T3" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "Implication: out-of-scope item #1 in docs/downlevel-fallback-threat-model.md"
    Write-Host "is a real concern, not theoretical. The threat model already documents this;"
    Write-Host "callers who need name-disclosure protection should not rely on T3."
} else {
    Write-Host "Headline: NO ENUMERATION LEAK" -ForegroundColor Green
    Write-Host ""
    Write-Host "Implication: out-of-scope item #1 in docs/downlevel-fallback-threat-model.md"
    Write-Host "is theoretical on this host build. The threat model can be updated to weaken"
    Write-Host "that out-of-scope claim (or move it to in-scope) pending corroboration on"
    Write-Host "other 25H2 / post-25H2 builds."
}
Write-Host ""

if (-not $KeepArtifacts) {
    Remove-Item -Recurse -Force -LiteralPath $ScratchRoot
} else {
    Write-Host "Artifacts kept at: $ScratchRoot"
    Write-Host "  config:  $configPath"
    Write-Host "  log:     $logPath"
}

exit 0
