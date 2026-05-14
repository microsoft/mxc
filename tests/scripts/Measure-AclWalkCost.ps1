# Measure-AclWalkCost.ps1
#
# Empirically measures the cost of adding / removing an ACE on a
# directory as a function of (subtree size, inheritance flag). Used
# to inform the architectural decision in microsoft/mxc#304: is the
# `Set-Acl with InheritanceFlags=None` walk actually fast on populated
# trees, and how fast vs. an inheriting grant?
#
# Prerequisite: a test tree at `-TreeRoot` shaped as:
#   <TreeRoot>\
#     32 files
#     l1-1\ ... l1-8\         (8 folders)
#       32 files
#       l2-1\ ... l2-8\       (8 each, 64 total)
#         32 files
#         l3-1\ ... l3-8\     (8 each, 512 total)
#           32 files
# Total: 585 dirs, 18,720 files, 19,305 objects, ~18 MB.
#
# Builds nothing. Modifies no MXC state. Uses S-1-1-0 ("Everyone") as
# the test SID — well-known, safe to grant/remove, harmless on a
# scratch tree.

[CmdletBinding()]
param(
    [string]$TreeRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'temp'),
    [string]$Sid = 'S-1-1-0'  # Everyone — safe and well-known
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path $TreeRoot)) {
    throw "TreeRoot $TreeRoot does not exist. Build the tree first."
}

# Pick representative paths at each depth.
$pathRoot = $TreeRoot
$pathL1   = Join-Path $TreeRoot 'l1-1'
$pathL2   = Join-Path $TreeRoot 'l1-1\l2-1'
$pathL3   = Join-Path $TreeRoot 'l1-1\l2-1\l3-1'

foreach ($p in @($pathL1, $pathL2, $pathL3)) {
    if (-not (Test-Path $p)) { throw "Missing $p — is the tree shape correct?" }
}

# Subtree sizes (object count INCLUDING the target itself).
function Get-SubtreeObjectCount {
    param([string]$Path)
    (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
        Measure-Object).Count + 1
}

Write-Host "Counting subtree sizes..." -ForegroundColor Cyan
$sizeRoot = Get-SubtreeObjectCount $pathRoot
$sizeL1   = Get-SubtreeObjectCount $pathL1
$sizeL2   = Get-SubtreeObjectCount $pathL2
$sizeL3   = Get-SubtreeObjectCount $pathL3
Write-Host "  $pathRoot : $sizeRoot objects"
Write-Host "  $pathL1   : $sizeL1 objects"
Write-Host "  $pathL2   : $sizeL2 objects"
Write-Host "  $pathL3   : $sizeL3 objects"
Write-Host ""

# Build SID object once.
$sidObj = New-Object System.Security.Principal.SecurityIdentifier $Sid

function Add-Ace {
    param([string]$Path, [bool]$Inheriting)

    $acl = Get-Acl -LiteralPath $Path
    $inhFlags = if ($Inheriting) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidObj,
        [System.Security.AccessControl.FileSystemRights]::Traverse,
        $inhFlags,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Remove-Ace {
    param([string]$Path, [bool]$Inheriting)
    $acl = Get-Acl -LiteralPath $Path
    $inhFlagsStr = if ($Inheriting) { 'ContainerInherit, ObjectInherit' } else { 'None' }
    $toRemove = @($acl.Access | Where-Object {
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $Sid -and
        $_.InheritanceFlags.ToString() -eq $inhFlagsStr -and
        $_.AccessControlType.ToString() -eq 'Allow'
    })
    foreach ($r in $toRemove) {
        $acl.RemoveAccessRuleSpecific($r) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Time-Operation {
    param([scriptblock]$Op)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $Op
    $sw.Stop()
    return [Math]::Round($sw.Elapsed.TotalMilliseconds, 1)
}

$results = @()

foreach ($pair in @(
    @{ Path = $pathL3;   Size = $sizeL3;   Label = 'L3' },
    @{ Path = $pathL2;   Size = $sizeL2;   Label = 'L2' },
    @{ Path = $pathL1;   Size = $sizeL1;   Label = 'L1' },
    @{ Path = $pathRoot; Size = $sizeRoot; Label = 'Root' }
)) {
    foreach ($inhTuple in @(@{ Inh = $false; Tag = 'NON-inh' }, @{ Inh = $true; Tag = 'inh' })) {
        $addMs = Time-Operation { Add-Ace -Path $pair.Path -Inheriting $inhTuple.Inh }
        $rmMs  = Time-Operation { Remove-Ace -Path $pair.Path -Inheriting $inhTuple.Inh }
        $results += [pscustomobject]@{
            Target       = $pair.Label
            Subtree      = $pair.Size
            Inheritance  = $inhTuple.Tag
            AddMs        = $addMs
            RemoveMs     = $rmMs
            TotalMs      = $addMs + $rmMs
        }
        Write-Host ("  {0,-4} {1,-7} subtree={2,7}  add={3,7} ms  remove={4,7} ms" -f `
            $pair.Label, $inhTuple.Tag, $pair.Size, $addMs, $rmMs)
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Summary (sorted by subtree size)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
$results | Sort-Object Subtree, Inheritance | Format-Table -AutoSize Target, Subtree, Inheritance, AddMs, RemoveMs, TotalMs

# Key derived metric: per-object-walked cost.
Write-Host "Per-object cost (TotalMs / Subtree):" -ForegroundColor Cyan
$results | Sort-Object Subtree, Inheritance | ForEach-Object {
    $perObj = if ($_.Subtree -gt 0) { [Math]::Round($_.TotalMs / $_.Subtree, 4) } else { 0 }
    Write-Host ("  {0,-4} {1,-7}  {2,-7} objects   {3} ms / object" -f `
        $_.Target, $_.Inheritance, $_.Subtree, $perObj)
}

Write-Host ""
Write-Host "Done. Test SID grants were added + removed in pairs; nothing left behind." -ForegroundColor Green
