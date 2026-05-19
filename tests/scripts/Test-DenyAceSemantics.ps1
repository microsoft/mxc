# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Test-DenyAceSemantics.ps1
#
# Empirical answer to "do Deny ACEs targeting AppContainer SIDs enforce
# in the AppContainer's access check?" — a question on which the
# mxc.green:user/gudge/downlevel_phase6_t3_enumeration:filesystem_dacl
# module is implicitly betting (its add_deny_aces path) but for which
# the Test-LowBoxSidOnlyAccess.ps1 empirical script in that branch
# tested only Allow-ACE configurations.
#
# Method:
#
#   - Build wxc-projfs-probe / probe-child.
#   - Use the probe in a one-shot mode (no policy → synthetic default
#     scratch) only to read the AC SID it derives.
#   - Create a host file under a directory that ALSO inherits an
#     `ALL APPLICATION PACKAGES` ACE (we use `%LOCALAPPDATA%\Packages\
#     mxc.projfs.spike\AC\` — the AC's own profile root, which has
#     full AC SID access by design).
#   - For each DACL variant {A, B, C}: set the ACL on the file, run
#     wxc-projfs-probe --direct-read <file>, observe whether the AC
#     child's CreateFileW / ReadFile succeeded.
#
# Headlines:
#
#   A. Allow + (nothing)  → AC can read?    expect YES (baseline rail)
#   B. Allow + Deny       → AC can read?    if YES, Deny ACEs are ignored
#   C. (no Allow grant)   → AC can read?    expect NO  (baseline rail)
#
# Exit code is always 0. The headline lines summarize the answer.

[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))),
    [string]$ProbeExe = (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'src\target\debug\wxc-projfs-probe.exe'),
    [switch]$SkipBuild,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $SkipBuild) {
    $cargoRoot = Join-Path $RepoRoot 'src'
    Push-Location $cargoRoot
    try {
        Write-Host "Building wxc-projfs-probe + wxc-projfs-probe-child..." -ForegroundColor Cyan
        & cargo build -p wxc_projfs_probe -p wxc_projfs_probe_child 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path $ProbeExe)) { throw "wxc-projfs-probe not found at $ProbeExe" }

# Discover the AC SID by running the probe with --no-ac and parsing JSON.
Write-Host "Discovering AC SID via probe..." -ForegroundColor Cyan
$json = & $ProbeExe --no-ac 2>$null
$obj  = $json | ConvertFrom-Json
$acSid = $obj.ac_profile.sid_string
$acFolder = $obj.ac_profile.folder_path
Write-Host "AC SID    : $acSid"
Write-Host "AC folder : $acFolder"

# Test file path. We put it under the AC profile root so the launching
# user can ACL it freely AND the AC has inherited access if we want it.
# But: the directory permissions we control will be those of the file
# we explicitly set, so inheritance doesn't matter for this test.
$testDir = Join-Path $acFolder 'deny-ace-test'
if (Test-Path $testDir) { Remove-Item -Recurse -Force -LiteralPath $testDir }
New-Item -ItemType Directory -Path $testDir | Out-Null
$testFile = Join-Path $testDir 'readme.txt'
'control content' | Out-File -LiteralPath $testFile -Encoding ascii -Force

# Build a DACL on $testFile using icacls.exe rather than Set-Acl. Set-Acl
# via System.IO.FileSecurity ends up marking both DACL and SACL sections
# as modified (the SE_DACL_PROTECTED bit lives at the descriptor level),
# which triggers a SACL write that needs SeSecurityPrivilege. icacls's
# /grant /deny /inheritance commands operate on the DACL only.
function Apply-Dacl([string]$Path, [string]$Variant) {
    # Strip inherited ACEs (and prevent further inheritance). Without
    # this, the AC SID inherits an Allow from the AC profile root and
    # all three variants look identical.
    & icacls $Path /inheritance:r | Out-Null
    # Remove any default explicit ACEs left after /inheritance:r so we
    # start from a known minimal DACL containing only SY:(F) implicitly.
    # icacls /inheritance:r leaves the existing explicit ACEs in place
    # (the file inherited owner=launching-user defaults so there is no
    # explicit ACE yet; this is a no-op in practice for our setup).
    & icacls $Path /grant:r "*S-1-5-18:(F)"      | Out-Null  # SYSTEM
    & icacls $Path /grant:r "*S-1-5-32-544:(F)"  | Out-Null  # Administrators
    & icacls $Path /grant:r "${env:USERNAME}:(F)"| Out-Null  # launching user

    switch ($Variant) {
        'A' {
            & icacls $Path /grant:r "*${acSid}:(R)" | Out-Null
        }
        'B' {
            # Both Allow and Deny on the same AC SID. icacls writes
            # them in canonical order (Deny then Allow) by default.
            & icacls $Path /grant:r "*${acSid}:(R)" | Out-Null
            & icacls $Path /deny    "*${acSid}:(F)" | Out-Null
        }
        'C' {
            # No AC grant.
        }
        default { throw "unknown variant: $Variant" }
    }
}

function Run-AcRead([string]$Label, [string]$Variant) {
    Apply-Dacl $testFile $Variant
    $actual = (Get-Acl -LiteralPath $testFile).Sddl

    # Clean any stale virt root the probe might have left.
    Get-ChildItem -Force $acFolder -Filter "projfs-probe-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -Recurse -Force -LiteralPath $_.FullName -ErrorAction SilentlyContinue }

    $rawJson = & $ProbeExe --direct-read $testFile 2>$null
    $rep = $rawJson | ConvertFrom-Json
    $dr = $rep.ac_child.child_json.direct_reads | Select-Object -First 1
    [pscustomobject]@{
        case         = $Label
        variant      = $Variant
        applied_sddl = $actual
        state        = $dr.state
        last_error   = $dr.last_error
        bytes_read   = $dr.bytes_read
    }
}

$rA = Run-AcRead 'A: Allow only'  'A'
$rB = Run-AcRead 'B: Allow+Deny'  'B'
$rC = Run-AcRead 'C: No grant'    'C'

Write-Host ""
Write-Host "Results:" -ForegroundColor Cyan
@($rA, $rB, $rC) | Format-Table case, state, last_error, bytes_read -AutoSize

Write-Host ""
Write-Host "Verdict:" -ForegroundColor Cyan
function Verdict($expected, $actual, $name) {
    $ok = ($actual -eq $expected)
    $icon  = if ($ok) { '[ok]' } else { '[!!]' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("{0,-6} {1}   actual={2}  expected={3}" -f $icon, $name, $actual, $expected) -ForegroundColor $color
}

# Sanity rails: A should succeed (AC has explicit allow), C should fail.
Verdict 'SUCCEEDED' $rA.state 'A baseline rail: AC reads with explicit Allow'
Verdict 'DENIED'    $rC.state 'C baseline rail: AC denied with no Allow'

# The decisive cell:
Write-Host ""
if ($rB.state -eq 'DENIED') {
    Write-Host "Deny ACEs targeting AppContainer SIDs DO enforce on this host." -ForegroundColor Green
    Write-Host "  mxc.green::filesystem_dacl::add_deny_aces is doing real work." -ForegroundColor Green
    Write-Host "  ProjFS-T3 fix for RO-create-new CAN use a Deny ACE on the placeholder DACL." -ForegroundColor Green
} elseif ($rB.state -eq 'SUCCEEDED') {
    Write-Host "Deny ACEs targeting AppContainer SIDs do NOT enforce on this host." -ForegroundColor Yellow
    Write-Host "  -> mxc.green::filesystem_dacl::add_deny_aces is a paper guarantee: the Deny ACEs sit in the DACL but the kernel ignores them at AC access-check time. Threat-model claim for deniedPaths under T3 should be revisited." -ForegroundColor Yellow
    Write-Host "  -> ProjFS-T3 fix for RO-create-new must use SELECTIVE ALLOW (grant read subset, omit FILE_ADD_FILE) on the placeholder DACL, NOT a Deny ACE." -ForegroundColor Yellow
} else {
    Write-Host "Case B returned an unexpected state ($($rB.state)). Re-run with -Verbose." -ForegroundColor Red
}

if (-not $KeepArtifacts) {
    Remove-Item -Recurse -Force -LiteralPath $testDir -ErrorAction SilentlyContinue
}
