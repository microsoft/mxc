# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Test-ProjfsMatrix.ps1
#
# ProjFS-T3 spike step 2 harness. Spiritual descendant of
# `mxc.green:user/gudge/downlevel_phase6_t3_enumeration:test_scripts/Test-PathEnumeration.ps1`
# — same rw/ro/denied/control four-directory scratch, same per-directory
# stat-by-name + enumerate probes, plus step-2's write probes against rw
# and ro. Drives `wxc-projfs-probe` instead of `wxc-exec --force-tier=T3`.
#
# Output: writes both a human-readable summary and the full JSON report.
# Use `-Json` to emit just the JSON for piping to a comparison tool.
#
# Exit code is always 0 — this is information-gathering, not a regression
# gate. Read the headline lines printed before the matrix table for the
# pass/fail summary.

[CmdletBinding()]
param(
    [string]$RepoRoot   = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))),
    [string]$ProbeExe   = (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'src\target\debug\wxc-projfs-probe.exe'),
    [string]$ScratchRoot = (Join-Path $env:TEMP 'projfs-matrix'),
    [switch]$SkipBuild,
    [switch]$KeepArtifacts,
    [switch]$Json,
    # Create a junction inside rw/ to additionally exercise reparse refusal.
    # Requires no elevation. Off by default to keep the matrix output clean.
    [switch]$IncludeJunction
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $SkipBuild) {
    $cargoRoot = Join-Path $RepoRoot 'src'
    Push-Location $cargoRoot
    try {
        if (-not $Json) { Write-Host "Building wxc-projfs-probe + wxc-projfs-probe-child..." -ForegroundColor Cyan }
        & cargo build -p wxc_projfs_probe -p wxc_projfs_probe_child 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path $ProbeExe)) { throw "wxc-projfs-probe not found at $ProbeExe" }

# Scratch tree with four sibling directories — same shape as
# Test-PathEnumeration.ps1 so the result tables compare directly.
if (Test-Path $ScratchRoot) { Remove-Item -Recurse -Force -LiteralPath $ScratchRoot }
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
foreach ($d in @('rw','ro','denied','control')) {
    $p = Join-Path $ScratchRoot $d
    New-Item -ItemType Directory -Path $p | Out-Null
    'readme content' | Out-File -LiteralPath (Join-Path $p 'readme.txt') -Encoding ascii -Force
    'canary content' | Out-File -LiteralPath (Join-Path $p 'canary.txt') -Encoding ascii -Force
    New-Item -ItemType Directory -Path (Join-Path $p 'subdir') | Out-Null
    'inner'          | Out-File -LiteralPath (Join-Path $p 'subdir\inner.txt') -Encoding ascii -Force
}

if ($IncludeJunction) {
    cmd /c "mklink /J `"$ScratchRoot\rw\sneaky-junction`" `"$env:USERPROFILE`"" | Out-Null
}

# Capture host ACL state before — we'll compare after the probe to confirm
# no host-side mutation occurred. AC SID for our test profile should NOT
# appear in any host DACL.
$preAcls = @{}
foreach ($d in @('rw','ro','denied','control')) {
    $preAcls[$d] = (Get-Acl (Join-Path $ScratchRoot $d)).Sddl
}

# Clean any stale virt roots from previous runs so the unique-per-run leaf
# doesn't accumulate.
$acFolder = "$env:LOCALAPPDATA\Packages\mxc.projfs.spike\AC"
if (Test-Path $acFolder) {
    Get-ChildItem -Force $acFolder -Filter "projfs-probe-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -Recurse -Force -LiteralPath $_.FullName -ErrorAction SilentlyContinue }
}

$rawJson = & $ProbeExe `
    --rw "$ScratchRoot\rw" `
    --ro "$ScratchRoot\ro" `
    --check-dir rw --check-dir ro --check-dir denied --check-dir control `
    --write-probe rw --write-probe ro
$exit = $LASTEXITCODE

# Capture host ACL state after — compare against pre.
$postAcls = @{}
foreach ($d in @('rw','ro','denied','control')) {
    $postAcls[$d] = (Get-Acl (Join-Path $ScratchRoot $d)).Sddl
}
$aclMutated = $false
foreach ($d in @('rw','ro','denied','control')) {
    if ($preAcls[$d] -ne $postAcls[$d]) { $aclMutated = $true }
}

if ($Json) {
    Write-Output $rawJson
    if (-not $KeepArtifacts) { Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue }
    exit 0
}

$obj = $rawJson | ConvertFrom-Json

Write-Host ""
Write-Host "ProjFS-T3 step 2 matrix" -ForegroundColor Cyan
Write-Host "----------------------" -ForegroundColor Cyan
Write-Host ("exit code:          {0}" -f $exit)
Write-Host ("AC profile:         {0}" -f $obj.ac_profile.profile_name)
Write-Host ("AC SID:             {0}" -f $obj.ac_profile.sid_string)
Write-Host ("virt root:          {0}" -f $obj.virt_start.root_path)
Write-Host ("policy branches:    {0}" -f (($obj.virt_start.policy.branches | ForEach-Object { '{0}={1}' -f $_.name, $_.mode }) -join ', '))
Write-Host ("host ACLs unchanged: {0}" -f (-not $aclMutated))
Write-Host ""

Write-Host "Per-directory matrix:" -ForegroundColor Cyan
$obj.ac_child.child_json.per_dir |
    Select-Object name,
        @{n='stat'; e={$_.exist.state}},
        @{n='enum'; e={$_.list.state}},
        @{n='entries'; e={$_.list.entries -join ','}} |
    Format-Table -AutoSize

Write-Host "Write probes:" -ForegroundColor Cyan
$obj.ac_child.child_json.write_probes |
    Select-Object branch,
        @{n='modify'; e={"$($_.modify_existing.state) (err=$($_.modify_existing.last_error))"}},
        @{n='create'; e={"$($_.create_new.state) (err=$($_.create_new.last_error))"}} |
    Format-Table -AutoSize

# Headline summary mirroring the threat-model doc's tables.
function HeadlineCheck($name, $cond, $detail = $null) {
    $icon = if ($cond) { '[ok]' } else { '[FAIL]' }
    $color = if ($cond) { 'Green' } else { 'Red' }
    $line = if ($detail) { "{0,-6} {1} -- {2}" -f $icon, $name, $detail } else { "{0,-6} {1}" -f $icon, $name }
    Write-Host $line -ForegroundColor $color
}

$pd  = @{}
foreach ($r in $obj.ac_child.child_json.per_dir) { $pd[$r.name] = $r }
$wp  = @{}
foreach ($r in $obj.ac_child.child_json.write_probes) { $wp[$r.branch] = $r }

Write-Host ""
Write-Host "Headline:" -ForegroundColor Cyan
HeadlineCheck "rw  stat=VISIBLE    enum=ENUMERABLE"    ($pd['rw'].exist.state -eq 'VISIBLE' -and $pd['rw'].list.state -eq 'ENUMERABLE')
HeadlineCheck "ro  stat=VISIBLE    enum=ENUMERABLE"    ($pd['ro'].exist.state -eq 'VISIBLE' -and $pd['ro'].list.state -eq 'ENUMERABLE')
HeadlineCheck "denied  stat=HIDDEN  enum=BLOCKED"      ($pd['denied'].exist.state -eq 'HIDDEN' -and $pd['denied'].list.state -eq 'BLOCKED')
HeadlineCheck "control stat=HIDDEN  enum=BLOCKED"      ($pd['control'].exist.state -eq 'HIDDEN' -and $pd['control'].list.state -eq 'BLOCKED')
HeadlineCheck "rw  modify=SUCCEEDED"                   ($wp['rw'].modify_existing.state -eq 'SUCCEEDED')
HeadlineCheck "ro  modify=DENIED"                      ($wp['ro'].modify_existing.state -eq 'DENIED') "PRE_CONVERT_TO_FULL veto"
HeadlineCheck "rw  create=SUCCEEDED"                   ($wp['rw'].create_new.state -eq 'SUCCEEDED')
HeadlineCheck "ro  create=DENIED  (placeholder DACL)"  ($wp['ro'].create_new.state -eq 'DENIED') "FILE_ADD_FILE not granted to AC SID on the placeholder dir's DACL"
HeadlineCheck "host ACLs unchanged"                    (-not $aclMutated)

if (-not $KeepArtifacts) {
    Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue
}
