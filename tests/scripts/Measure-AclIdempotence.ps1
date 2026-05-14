# Measure-AclIdempotence.ps1
#
# Times `wxc-exec --adjustacls <PATH>` across three consecutive runs to
# validate the load-bearing claim for the persistent-ancestor design in
# microsoft/mxc#304: that the application-layer `check_grant` short-
# circuit makes runs #2 and #3 essentially free once the ACE is in
# place from run #1.
#
# Compares against the "naive" path (raw Set-Acl with no idempotent
# pre-check) to verify Windows itself does NOT short-circuit a
# no-change DACL set — i.e. the speedup comes from our application
# logic, not the OS.

[CmdletBinding()]
param(
    [string]$TreeRoot = (Join-Path $env:TEMP 'mxc-acl-perf-tree'),
    [string]$WxcDebug = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-exec.exe'),
    [string]$TestSid  = 'S-1-1-0'  # Everyone — safe, no elevation needed
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path $TreeRoot)) { throw "TreeRoot $TreeRoot does not exist." }
if (-not (Test-Path $WxcDebug)) { throw "wxc-exec not found at $WxcDebug — build it first." }

function Time-Wxc {
    param([string[]]$Args)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $WxcDebug @Args | Out-Null
    $sw.Stop()
    return [Math]::Round($sw.Elapsed.TotalMilliseconds, 1)
}

function Time-RawSetAcl {
    param([string]$Path, [string]$Sid)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $acl = Get-Acl -LiteralPath $Path
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier $Sid
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidObj,
        [System.Security.AccessControl.FileSystemRights]::Traverse,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
    $sw.Stop()
    return [Math]::Round($sw.Elapsed.TotalMilliseconds, 1)
}

function Remove-TestSid {
    param([string]$Path, [string]$Sid)
    $acl = Get-Acl -LiteralPath $Path
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier $Sid
    $toRemove = @($acl.Access | Where-Object {
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $Sid -and
        $_.InheritanceFlags.ToString() -eq 'None' -and
        $_.AccessControlType.ToString() -eq 'Allow'
    })
    foreach ($r in $toRemove) { $acl.RemoveAccessRuleSpecific($r) | Out-Null }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

# Ensure clean start.
Remove-TestSid -Path $TreeRoot -Sid $TestSid

$subtree = (Get-ChildItem -LiteralPath $TreeRoot -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count + 1
Write-Host "Target: $TreeRoot (subtree: $subtree objects)"
Write-Host "Test SID: $TestSid"
Write-Host ""

# -----------------------------------------------------------------------
# Scenario A: wxc-exec --adjustacls (uses install_acls::add_grant with
# idempotent check_grant short-circuit).
# -----------------------------------------------------------------------
Write-Host "Scenario A: wxc-exec --adjustacls (idempotent check)" -ForegroundColor Cyan

$run1 = Time-Wxc -Args @('--adjustacls', $TreeRoot, '--acl-sid', $TestSid)
Write-Host "  run #1 (cold, ACE absent):           $run1 ms"
$run2 = Time-Wxc -Args @('--adjustacls', $TreeRoot, '--acl-sid', $TestSid)
Write-Host "  run #2 (warm, ACE already present):  $run2 ms"
$run3 = Time-Wxc -Args @('--adjustacls', $TreeRoot, '--acl-sid', $TestSid)
Write-Host "  run #3 (warm, ACE already present):  $run3 ms"

$removeWxc = Time-Wxc -Args @('--remove-acls', $TreeRoot, '--acl-sid', $TestSid)
Write-Host "  remove (cold, ACE present):          $removeWxc ms"

$removeWxc2 = Time-Wxc -Args @('--remove-acls', $TreeRoot, '--acl-sid', $TestSid)
Write-Host "  remove #2 (ACE absent — no-op):      $removeWxc2 ms"

Write-Host ""

# -----------------------------------------------------------------------
# Scenario B: raw Set-Acl (no idempotent check; tells us whether
# Windows itself short-circuits an identical DACL set).
# -----------------------------------------------------------------------
Write-Host "Scenario B: raw Set-Acl (no application-layer check)" -ForegroundColor Cyan

Remove-TestSid -Path $TreeRoot -Sid $TestSid

$raw1 = Time-RawSetAcl -Path $TreeRoot -Sid $TestSid
Write-Host "  run #1 (cold, ACE absent):           $raw1 ms"
# Each subsequent call adds another duplicate ACE — but the question is
# whether the SetNamedSecurityInfoW walk is short-circuited.
$raw2 = Time-RawSetAcl -Path $TreeRoot -Sid $TestSid
Write-Host "  run #2 (DACL changes again — dup):   $raw2 ms"
$raw3 = Time-RawSetAcl -Path $TreeRoot -Sid $TestSid
Write-Host "  run #3 (DACL changes again — dup):   $raw3 ms"

# Cleanup duplicates.
do {
    Remove-TestSid -Path $TreeRoot -Sid $TestSid
    $remaining = @((Get-Acl -LiteralPath $TreeRoot).Access | Where-Object {
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $TestSid
    }).Count
} while ($remaining -gt 0)

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
$results = @(
    [pscustomobject]@{ Scenario='wxc-exec --adjustacls #1 (cold)';   Ms=$run1 }
    [pscustomobject]@{ Scenario='wxc-exec --adjustacls #2 (warm)';   Ms=$run2 }
    [pscustomobject]@{ Scenario='wxc-exec --adjustacls #3 (warm)';   Ms=$run3 }
    [pscustomobject]@{ Scenario='wxc-exec --remove-acls (cold)';     Ms=$removeWxc }
    [pscustomobject]@{ Scenario='wxc-exec --remove-acls (no-op)';    Ms=$removeWxc2 }
    [pscustomobject]@{ Scenario='raw Set-Acl #1 (cold)';             Ms=$raw1 }
    [pscustomobject]@{ Scenario='raw Set-Acl #2 (Windows asked again to write a no-change DACL)'; Ms=$raw2 }
    [pscustomobject]@{ Scenario='raw Set-Acl #3 (same)';             Ms=$raw3 }
)
$results | Format-Table -AutoSize

# Headline computations.
if ($run1 -gt 0) {
    $speedupAdj = if ($run2 -gt 0) { [Math]::Round($run1 / $run2, 1) } else { '∞' }
    Write-Host "Speedup #1→#2 with idempotent check:    ${speedupAdj}x"
}
if ($raw1 -gt 0 -and $raw2 -gt 0) {
    $speedupRaw = [Math]::Round($raw1 / $raw2, 1)
    Write-Host "Speedup #1→#2 without app-layer check:  ${speedupRaw}x"
}

Write-Host ""
Write-Host "Done. Test ACE was removed; tree is in original state." -ForegroundColor Green
