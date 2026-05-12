# Investigate-T3DriveTraverse.ps1
#
# Tests hypothesis (1) from microsoft/mxc#304: T3 directory enumeration
# fails because FindFirstFile requires FILE_TRAVERSE on every ancestor.
#
# Setup (PREREQUISITE, run once as admin against your chosen drive):
#
#   $acl = Get-Acl X:\
#   $sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-15-2-1'
#   $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
#       $sid,
#       [System.Security.AccessControl.FileSystemRights]::Traverse,
#       [System.Security.AccessControl.InheritanceFlags]::None,
#       [System.Security.AccessControl.PropagationFlags]::None,
#       [System.Security.AccessControl.AccessControlType]::Allow
#   )
#   $acl.AddAccessRule($rule)
#   Set-Acl -Path X:\ -AclObject $acl
#
# Use Set-Acl (not icacls /grant) — the latter rewrites the directory's
# DACL in a way that triggers Windows to walk every descendant on the
# volume to re-canonicalize inheritance, even when the new ACE itself
# is non-inheriting. On a populated drive that's an O(file-count) walk
# you don't want. Set-Acl with explicit InheritanceFlags=None /
# PropagationFlags=None still walks but does no per-file work.
#
# Then this script can run non-elevated. It:
#
#   1. Verifies ALL APP PKGS has the traverse ACE on D:\.
#   2. Creates D:\TEMP\mxc-t3-drive-traverse\rw with files.
#   3. Manually grants the AppContainer SID `(X)` on D:\TEMP\ and
#      D:\TEMP\mxc-t3-drive-traverse\ (user-doable, non-inheriting).
#   4. Runs wxc-exec under T3 with `cmd /c dir /b <rw> 2>&1`.
#   5. Reports ENUMERABLE / BLOCKED.
#   6. Cleans up its per-run grants (your D:\ pre-grant stays).
#
# Outcomes:
#   ENUMERABLE → hypothesis (1) confirmed; option (1) in #304 viable.
#   BLOCKED    → hypothesis (1) refuted; something else is going on.

[CmdletBinding()]
param(
    [string]$RepoRoot    = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$WxcDebug    = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-exec.exe'),
    [string]$DriveRoot   = 'D:\',
    [string]$ScratchRoot = 'D:\TEMP\mxc-t3-drive-traverse',
    [string]$ContainerId = 'MxcT3DriveTraverse'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -----------------------------------------------------------------------
# Pre-flight: verify ALL APP PKGS has traverse on the drive root
# -----------------------------------------------------------------------
if (-not (Test-Path $DriveRoot)) {
    throw "Drive root $DriveRoot does not exist."
}
$drvAcl = Get-Acl $DriveRoot
$aapAce = @($drvAcl.Access | Where-Object {
    $_.IdentityReference.Value -match 'ALL APPLICATION PACKAGES' -or
    ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier] -and $_.IdentityReference.Value -eq 'S-1-15-2-1')
})
if ($aapAce.Count -eq 0) {
    Write-Host "FAIL: ALL APPLICATION PACKAGES has no ACE on $DriveRoot." -ForegroundColor Red
    Write-Host "Apply the prerequisite Set-Acl recipe from the script header first." -ForegroundColor Yellow
    exit 1
}
foreach ($a in $aapAce) {
    Write-Host "$DriveRoot grants $($a.IdentityReference): $($a.FileSystemRights) (Inheritance=$($a.InheritanceFlags), Propagation=$($a.PropagationFlags))" -ForegroundColor Green
}

# -----------------------------------------------------------------------
# Derive the AppContainer SID for our test container
# -----------------------------------------------------------------------
$signature = @"
[DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int DeriveAppContainerSidFromAppContainerName(string n, out System.IntPtr sid);
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern bool ConvertSidToStringSidW(System.IntPtr sid, out System.IntPtr str);
[DllImport("kernel32.dll")]
public static extern System.IntPtr LocalFree(System.IntPtr p);
[DllImport("advapi32.dll")]
public static extern System.IntPtr FreeSid(System.IntPtr p);
"@
Add-Type -MemberDefinition $signature -Name H -Namespace MxcDrvAcl -ErrorAction SilentlyContinue
function Get-AcSid {
    param([string]$Name)
    $sid = [System.IntPtr]::Zero
    $hr = [MxcDrvAcl.H]::DeriveAppContainerSidFromAppContainerName($Name, [ref]$sid)
    if ($hr -ne 0) { throw "Derive failed: 0x$($hr.ToString('X8'))" }
    try {
        $str = [System.IntPtr]::Zero
        $ok = [MxcDrvAcl.H]::ConvertSidToStringSidW($sid, [ref]$str)
        if (-not $ok) { throw "Convert failed" }
        try { return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($str) }
        finally { [MxcDrvAcl.H]::LocalFree($str) | Out-Null }
    } finally { [MxcDrvAcl.H]::FreeSid($sid) | Out-Null }
}
$acSid = Get-AcSid -Name $ContainerId
Write-Host "AppContainer SID for '$ContainerId': $acSid" -ForegroundColor Cyan

# -----------------------------------------------------------------------
# Scratch tree
# -----------------------------------------------------------------------
if (Test-Path $ScratchRoot) { Remove-Item -Recurse -Force -LiteralPath $ScratchRoot }
# Ensure D:\TEMP\ exists (created by us if missing, so user-owned).
$tempDir = Split-Path -Parent $ScratchRoot
if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$rw = Join-Path $ScratchRoot 'rw'
New-Item -ItemType Directory -Path $rw | Out-Null
'A' | Out-File -LiteralPath (Join-Path $rw 'a.txt') -Encoding ascii -Force
'B' | Out-File -LiteralPath (Join-Path $rw 'b.txt') -Encoding ascii -Force

# Ancestors that need traverse grants (excluding the drive root, which the
# user pre-granted to ALL APP PKGS).
$ancestors = @($tempDir, $ScratchRoot)

# -----------------------------------------------------------------------
# Per-run grants on the user-owned ancestors (Set-Acl, non-inheriting)
# -----------------------------------------------------------------------
function Grant-Traverse {
    param([string]$Path, [string]$Sid)
    $acl = Get-Acl $Path
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier $Sid
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sidObj,
        [System.Security.AccessControl.FileSystemRights]::Traverse,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $Path -AclObject $acl
}
function Remove-Traverse {
    param([string]$Path, [string]$Sid)
    $acl = Get-Acl $Path
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier $Sid
    $acl.Access |
        Where-Object { $_.IdentityReference.Value -eq $sidObj.Value -and $_.InheritanceFlags -eq 'None' } |
        ForEach-Object { $acl.RemoveAccessRuleSpecific($_) | Out-Null }
    Set-Acl -Path $Path -AclObject $acl
}

$granted = @()
try {
    foreach ($a in $ancestors) {
        Write-Host "  granting Traverse to AppContainer SID on $a ..." -ForegroundColor Cyan
        Grant-Traverse -Path $a -Sid $acSid
        $granted += $a
    }

    # -------------------------------------------------------------------
    # Build config + run
    # -------------------------------------------------------------------
    $cfgPath = Join-Path $ScratchRoot 'config.json'
    $cfg = [ordered]@{
        version     = '0.5.0-dev'
        containerId = $ContainerId
        containment = 'appcontainer'
        process     = [ordered]@{
            commandLine = "cmd /c dir /b ""$rw"" 2>&1"
            timeout     = 30000
        }
        filesystem = [ordered]@{ readwritePaths = @($rw) }
        fallback   = [ordered]@{ allowDaclMutation = $true }
        ui         = [ordered]@{ disable = $false }
    }
    ($cfg | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $cfgPath -Encoding utf8 -Force

    Write-Host ""
    Write-Host "Running wxc-exec under MXC_FORCE_TIER=appcontainer-dacl..." -ForegroundColor Cyan
    $env:MXC_FORCE_TIER = 'appcontainer-dacl'
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $WxcDebug
        $psi.Arguments = "`"$cfgPath`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow  = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        $p.WaitForExit(30000) | Out-Null
        $exit = $p.ExitCode
    } finally {
        Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "  exit:   $exit"
    Write-Host "  stdout: $($stdout.Trim())"
    if ($stderr.Trim()) { Write-Host "  stderr: $($stderr.Trim())" }

    $combined = "$stdout`n$stderr"
    $result = if     ($combined -match 'Access is denied') { 'BLOCKED' }
              elseif ($combined -match 'a\.txt' -or $combined -match 'b\.txt') { 'ENUMERABLE' }
              else { 'UNKNOWN' }

    Write-Host ""
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "Result: $result" -ForegroundColor $(if ($result -eq 'ENUMERABLE') { 'Green' } else { 'Yellow' })
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host ""
    if ($result -eq 'ENUMERABLE') {
        Write-Host "HYPOTHESIS (1) CONFIRMED" -ForegroundColor Green
        Write-Host "  Full ancestor traverse chain enables FindFirstFile inside T3."
        Write-Host "  Missing FILE_TRAVERSE on system-owned ancestors was the root cause"
        Write-Host "  of the enumeration failure observed in microsoft/mxc#304."
        Write-Host ""
        Write-Host "  Implication for #304: option (1) — one-time admin grant of"
        Write-Host "  ALL APPLICATION PACKAGES (X) on C:\ and C:\Users\, plus per-run"
        Write-Host "  DaclManager extension to grant traverse on user-owned ancestors —"
        Write-Host "  is the viable path forward."
    } elseif ($result -eq 'BLOCKED') {
        Write-Host "HYPOTHESIS (1) NOT CONFIRMED" -ForegroundColor Yellow
        Write-Host "  Even with a full ancestor traverse chain (ALL APP PKGS on D:\,"
        Write-Host "  AppContainer SID on D:\TEMP\ and below), enumeration still fails."
        Write-Host "  The cause is not (just) missing ancestor traverse — it lies in"
        Write-Host "  AppContainer's enumeration access check itself."
        Write-Host ""
        Write-Host "  Implication for #304: option (1) is not viable. Path forward"
        Write-Host "  shrinks to option (2) bfs.sys direct drive, or option (3)"
        Write-Host "  document-and-accept the limitation."
    } else {
        Write-Host "INDETERMINATE — exit=$exit; stdout/stderr above" -ForegroundColor Yellow
    }
} finally {
    Write-Host ""
    Write-Host "Cleanup..." -ForegroundColor Cyan
    foreach ($a in $granted) {
        Write-Host "  removing per-run AppContainer SID grant from $a"
        try { Remove-Traverse -Path $a -Sid $acSid } catch {
            Write-Host "    cleanup failed: $_" -ForegroundColor Yellow
            Write-Host "    manual: (Get-Acl '$a').Access | Where IdentityReference.Value -eq '$acSid' | ForEach { ... }" -ForegroundColor Yellow
        }
    }
    Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue
}
