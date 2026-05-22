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
    [string]$RepoRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$ProbeExe = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-projfs-probe.exe'),
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
    & icacls $Path /inheritance:r | Out-Null
    & icacls $Path /grant:r "*S-1-5-18:(F)"      | Out-Null  # SYSTEM
    & icacls $Path /grant:r "*S-1-5-32-544:(F)"  | Out-Null  # Administrators
    & icacls $Path /grant:r "${env:USERNAME}:(F)"| Out-Null  # launching user

    switch ($Variant) {
        'A' {
            # Allow only — explicit grant to the specific AC SID.
            & icacls $Path /grant:r "*${acSid}:(R)" | Out-Null
        }
        'B' {
            # Allow + Deny on the specific AC SID.
            & icacls $Path /grant:r "*${acSid}:(R)" | Out-Null
            & icacls $Path /deny    "*${acSid}:(F)" | Out-Null
        }
        'C' {
            # No AC grant.
        }
        'D' {
            # AAP allow (broad) + Deny on the specific AC SID. If the
            # specific deny wins (canonical-order: deny before allow),
            # the AC is denied. If AAP's grant is consulted via a
            # separate code path, the AC is allowed.
            & icacls $Path /grant:r '*S-1-15-2-1:(R)' | Out-Null   # ALL APPLICATION PACKAGES
            & icacls $Path /deny    "*${acSid}:(F)"   | Out-Null
        }
        'E' {
            # AAP allow only, no specific-SID grant. Used as a probe
            # under both AAP-on and LPAC-on modes to confirm that
            # PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY
            # opt-out is actually taking effect.
            & icacls $Path /grant:r '*S-1-15-2-1:(R)' | Out-Null
        }
        default { throw "unknown variant: $Variant" }
    }
}

function Run-AcRead([string]$Label, [string]$Variant, [bool]$Lpac) {
    Apply-Dacl $testFile $Variant
    Get-ChildItem -Force $acFolder -Filter "projfs-probe-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -Recurse -Force -LiteralPath $_.FullName -ErrorAction SilentlyContinue }

    $extraArgs = @()
    if ($Lpac) { $extraArgs += '--lpac' }
    $rawJson = & $ProbeExe --direct-read $testFile @extraArgs 2>$null
    $rep = $rawJson | ConvertFrom-Json
    $dr = $rep.ac_child.child_json.direct_reads | Select-Object -First 1
    [pscustomobject]@{
        case        = $Label
        variant     = $Variant
        lpac        = $Lpac
        state       = $dr.state
        last_error  = $dr.last_error
        bytes_read  = $dr.bytes_read
    }
}

$results = @()
foreach ($cfg in @(
    @{ V='A'; L='A: Allow only' },
    @{ V='B'; L='B: Allow + Deny (specific AC SID)' },
    @{ V='C'; L='C: No grant' },
    @{ V='D'; L='D: AAP Allow + Deny (specific AC SID)' },
    @{ V='E'; L='E: AAP Allow only' }
)) {
    foreach ($lpac in @($false, $true)) {
        $results += Run-AcRead $cfg.L $cfg.V $lpac
    }
}
$rA  = $results | Where-Object { $_.variant -eq 'A' -and -not $_.lpac } | Select-Object -First 1
$rB  = $results | Where-Object { $_.variant -eq 'B' -and -not $_.lpac } | Select-Object -First 1
$rC  = $results | Where-Object { $_.variant -eq 'C' -and -not $_.lpac } | Select-Object -First 1
$rD  = $results | Where-Object { $_.variant -eq 'D' -and -not $_.lpac } | Select-Object -First 1
$rE  = $results | Where-Object { $_.variant -eq 'E' -and -not $_.lpac } | Select-Object -First 1
$rBL = $results | Where-Object { $_.variant -eq 'B' -and $_.lpac } | Select-Object -First 1
$rEL = $results | Where-Object { $_.variant -eq 'E' -and $_.lpac } | Select-Object -First 1

Write-Host ""
Write-Host "Results (regular AppContainer):" -ForegroundColor Cyan
$results | Where-Object { -not $_.lpac } | Format-Table case, state, last_error, bytes_read -AutoSize

Write-Host "Results (LPAC opt-out):" -ForegroundColor Cyan
$results | Where-Object { $_.lpac } | Format-Table case, state, last_error, bytes_read -AutoSize

Write-Host ""
Write-Host "Verdict:" -ForegroundColor Cyan
function Verdict($expected, $actual, $name) {
    $ok = ($actual -eq $expected)
    $icon  = if ($ok) { '[ok]' } else { '[!!]' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("{0,-6} {1}   actual={2}  expected={3}" -f $icon, $name, $actual, $expected) -ForegroundColor $color
}

# Baseline rails (regular AC).
Verdict 'SUCCEEDED' $rA.state 'A: AC reads with explicit Allow                   '
Verdict 'DENIED'    $rC.state 'C: AC denied with no Allow                         '

# Decisive cells.
Write-Host ""
Write-Host "B (specific Allow + specific Deny, regular AC):" -ForegroundColor Cyan
Write-Host "  result: $($rB.state)  err=$($rB.last_error)"
Write-Host ""
Write-Host "D (AAP Allow + specific-AC-SID Deny, regular AC):" -ForegroundColor Cyan
Write-Host "  result: $($rD.state)  err=$($rD.last_error)"
Write-Host ""
Write-Host "E vs E-LPAC (AAP Allow only, both AC modes):" -ForegroundColor Cyan
Write-Host "  regular AC : $($rE.state)   err=$($rE.last_error)"
Write-Host "  LPAC AC    : $($rEL.state)  err=$($rEL.last_error)"
Write-Host ""
Write-Host "B-LPAC (specific Allow + specific Deny, LPAC):" -ForegroundColor Cyan
Write-Host "  result: $($rBL.state)  err=$($rBL.last_error)"

Write-Host ""
Write-Host "Interpretation:" -ForegroundColor Cyan
if ($rB.state -eq 'DENIED') {
    Write-Host "  - Deny ACE for specific AC SID overrides Allow ACE for same SID (canonical-order semantics)." -ForegroundColor Green
}
if ($rD.state -eq 'DENIED') {
    Write-Host "  - Specific-AC-SID Deny ACE overrides ALL APPLICATION PACKAGES Allow ACE." -ForegroundColor Green
    Write-Host "    The deniedPaths story under T1/T2/T3 is robust to inherited AAP grants." -ForegroundColor Green
} elseif ($rD.state -eq 'SUCCEEDED') {
    Write-Host "  - WARNING: AAP Allow won over specific-AC-SID Deny." -ForegroundColor Yellow
    Write-Host "    deniedPaths needs to also strip AAP grants, not just add Deny." -ForegroundColor Yellow
}
if ($rE.state -eq 'SUCCEEDED' -and $rEL.state -eq 'DENIED') {
    Write-Host "  - LPAC opt-out demonstrably works: regular AC inherits AAP membership and is granted; LPAC AC is not and is denied." -ForegroundColor Green
} elseif ($rE.state -eq 'SUCCEEDED' -and $rEL.state -eq 'SUCCEEDED') {
    Write-Host "  - LPAC opt-out had NO effect on this host (still granted via AAP). Check PROC_THREAD_ATTRIBUTE wiring." -ForegroundColor Yellow
}
if ($rBL.state -eq 'DENIED') {
    Write-Host "  - Specific-AC-SID Deny still enforces under LPAC." -ForegroundColor Green
}

if (-not $KeepArtifacts) {
    Remove-Item -Recurse -Force -LiteralPath $testDir -ErrorAction SilentlyContinue
}
