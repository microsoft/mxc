# Investigate-T3AppContainerSidAccess.ps1
#
# Does an Allow ACE for an AppContainer SID, alone, suffice to grant
# read access to an AppContainer-sandboxed process — or does the
# resource also need a separate user/group grant?
#
# The answer determines whether the cross-user attack on persistent
# ancestor ACEs is real:
#   - SID-alone-suffices  → User B's AppContainer can read User A's
#                           files that have only SID-of-X:(R) → attack
#                           is real → need per-user namespacing or
#                           per-run randomization.
#   - Both-needed         → Standard access check still requires a
#                           user/group grant → cross-user attack
#                           doesn't work → persistent design is safe
#                           from cross-user.
#
# Test:
#   1. Create a target file with a maximally-stripped DACL:
#      only NT AUTHORITY\SYSTEM:(F) + <AppContainer-SID>:(R).
#      No user, no group, no Administrators, no inherited ACEs.
#   2. Negative control: try to read from the calling shell (we're
#      the file's owner so we have RC/WD implicitly, but NO read-data
#      grant). Expect ACCESS DENIED.
#   3. Positive test: run a child in the matching AppContainer and
#      attempt `type target.txt`. Observe.
#
# Prerequisite: ALL APPLICATION PACKAGES:(X) must be present on the
# drive root we test under, so the AppContainer can traverse into the
# scratch directory. The script confirms this; if missing it tells
# you how to add it.

[CmdletBinding()]
param(
    [string]$DriveRoot   = 'E:\',
    [string]$WxcDebug    = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-exec.exe'),
    [string]$ContainerId = 'MxcAclSidAccessTest'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- SID derivation P/Invoke ---
$sig = @"
[DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int DeriveAppContainerSidFromAppContainerName(string n, out System.IntPtr sid);
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern bool ConvertSidToStringSidW(System.IntPtr sid, out System.IntPtr str);
[DllImport("kernel32.dll")]
public static extern System.IntPtr LocalFree(System.IntPtr p);
[DllImport("advapi32.dll")]
public static extern System.IntPtr FreeSid(System.IntPtr p);
"@
Add-Type -MemberDefinition $sig -Name H -Namespace MxcAclSidTest -ErrorAction SilentlyContinue
function Get-AcSid {
    param([string]$Name)
    $sid = [System.IntPtr]::Zero
    $hr = [MxcAclSidTest.H]::DeriveAppContainerSidFromAppContainerName($Name, [ref]$sid)
    if ($hr -ne 0) { throw "Derive failed: 0x$($hr.ToString('X8'))" }
    try {
        $str = [System.IntPtr]::Zero
        $ok = [MxcAclSidTest.H]::ConvertSidToStringSidW($sid, [ref]$str)
        if (-not $ok) { throw "Convert failed" }
        try { return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($str) }
        finally { [MxcAclSidTest.H]::LocalFree($str) | Out-Null }
    } finally { [MxcAclSidTest.H]::FreeSid($sid) | Out-Null }
}

# Pre-flight: confirm the drive root has ALL APP PKGS:(X).
$drvAcl = Get-Acl -LiteralPath $DriveRoot
$aapPresent = @($drvAcl.Access | Where-Object {
    $_.IdentityReference.Value -match 'ALL APPLICATION PACKAGES'
}).Count -gt 0
if (-not $aapPresent) {
    Write-Host "FAIL: $DriveRoot does not grant ALL APPLICATION PACKAGES traverse." -ForegroundColor Red
    Write-Host "Add it (elevated shell):" -ForegroundColor Yellow
    Write-Host '  $acl = Get-Acl ' "$DriveRoot"
    Write-Host '  $sid = New-Object System.Security.Principal.SecurityIdentifier ''S-1-15-2-1'''
    Write-Host '  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'
    Write-Host '      [System.Security.AccessControl.FileSystemRights]::Traverse,'
    Write-Host '      [System.Security.AccessControl.InheritanceFlags]::None,'
    Write-Host '      [System.Security.AccessControl.PropagationFlags]::None,'
    Write-Host '      [System.Security.AccessControl.AccessControlType]::Allow)'
    Write-Host '  $acl.AddAccessRule($rule)'
    Write-Host "  Set-Acl -Path $DriveRoot -AclObject `$acl"
    exit 1
}
Write-Host "$DriveRoot grants ALL APPLICATION PACKAGES (traverse) — good." -ForegroundColor Green

$acSidStr = Get-AcSid -Name $ContainerId
Write-Host "AppContainer SID for '$ContainerId': $acSidStr" -ForegroundColor Cyan

# Scratch + target file.
$randomTag = -join ((0..7) | ForEach-Object { [char][int]((97..122) | Get-Random) })
$scratch = Join-Path $DriveRoot "acl-sid-access-test-$randomTag"
$target  = Join-Path $scratch 'target.txt'

if (Test-Path $scratch) { Remove-Item -Recurse -Force -LiteralPath $scratch }
New-Item -ItemType Directory -Path $scratch | Out-Null
'secret-content-revealed-by-readers' | Out-File -LiteralPath $target -Encoding ascii -Force

# Grant ALL APP PKGS:(X) on the scratch dir (we own it; no elevation needed).
$dirAcl = Get-Acl -LiteralPath $scratch
$aapSidObj = New-Object System.Security.Principal.SecurityIdentifier 'S-1-15-2-1'
$dirRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $aapSidObj,
    [System.Security.AccessControl.FileSystemRights]::Traverse,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$dirAcl.AddAccessRule($dirRule)
Set-Acl -LiteralPath $scratch -AclObject $dirAcl
Write-Host "scratch dir $scratch granted ALL APP PKGS traverse" -ForegroundColor Cyan

# Strip the target file's DACL down to: SYSTEM:(F) + test SID:(R).
# We disable inheritance and clear inherited ACEs, then add only those
# two explicit grants. As owner we retain implicit READ_CONTROL +
# WRITE_DAC, which is enough to manage the ACL — but NOT to read the
# file's data.
$fileAcl = Get-Acl -LiteralPath $target
$fileAcl.SetAccessRuleProtection($true, $false)  # block inheritance, remove inherited
foreach ($r in @($fileAcl.Access)) {
    $fileAcl.RemoveAccessRule($r) | Out-Null
}
$systemSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'  # NT AUTHORITY\SYSTEM
$fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $systemSid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)))
$testSidObj = New-Object System.Security.Principal.SecurityIdentifier $acSidStr
$fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $testSidObj,
    [System.Security.AccessControl.FileSystemRights]::Read,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)))
Set-Acl -LiteralPath $target -AclObject $fileAcl

Write-Host ""
Write-Host "Target file ACL after stripping:" -ForegroundColor Cyan
icacls $target

# Negative control: read from the calling shell (we're the owner but
# have no read-data grant; should fail).
Write-Host ""
Write-Host "Negative control: reading from non-AppContainer process..." -ForegroundColor Cyan
$controlOk = $false
try {
    $content = Get-Content -LiteralPath $target -Raw -ErrorAction Stop
    Write-Host "  UNEXPECTED: read succeeded. Content: $($content.Trim())" -ForegroundColor Red
    Write-Host "  This invalidates the test — the calling user has some standard-token grant we didn't strip." -ForegroundColor Red
    $controlOk = $false
} catch {
    Write-Host "  EXPECTED: access denied. (Owner has RC/WD but no read-data.)" -ForegroundColor Green
    $controlOk = $true
}

if (-not $controlOk) {
    Write-Host "Test cannot proceed — negative control failed. Cleaning up." -ForegroundColor Red
    $a = Get-Acl -LiteralPath $target
    $a.SetAccessRuleProtection($false, $true) | Out-Null
    Set-Acl -LiteralPath $target -AclObject $a
    Remove-Item -Recurse -Force -LiteralPath $scratch -ErrorAction SilentlyContinue
    exit 1
}

# Positive test: run a child in the matching AppContainer.
Write-Host ""
Write-Host "Positive test: read via AppContainer process..." -ForegroundColor Cyan
$cfgPath = Join-Path $scratch 'config.json'
$cfg = [ordered]@{
    version     = '0.5.0-dev'
    containerId = $ContainerId
    containment = 'appcontainer'
    process     = [ordered]@{
        commandLine = "cmd /c type ""$target"" 2>&1"
        timeout     = 30000
    }
    fallback    = [ordered]@{ allowDaclMutation = $true }
    ui          = [ordered]@{ disable = $false }
}
($cfg | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $cfgPath -Encoding utf8 -Force

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
    Write-Host "  exit:   $($p.ExitCode)"
    Write-Host "  stdout: $($stdout.Trim())"
    if ($stderr.Trim()) { Write-Host "  stderr: $($stderr.Trim())" }

    $combined = "$stdout`n$stderr"
    if ($combined -match 'secret-content-revealed-by-readers') {
        Write-Host ""
        Write-Host "RESULT: SID-alone-suffices" -ForegroundColor Yellow
        Write-Host "  The AppContainer process read the file via the SID:(R) ACE alone." -ForegroundColor Yellow
        Write-Host "  → cross-user attack on persistent ancestor ACEs is REAL." -ForegroundColor Yellow
        Write-Host "  → mitigation needed (per-user namespacing or randomization)." -ForegroundColor Yellow
    } elseif ($combined -match 'Access is denied') {
        Write-Host ""
        Write-Host "RESULT: Both-needed" -ForegroundColor Green
        Write-Host "  The standard access check requires a user/group grant in addition to" -ForegroundColor Green
        Write-Host "  the AppContainer SID. The SID-alone scenario doesn't grant access." -ForegroundColor Green
        Write-Host "  → cross-user attack does NOT work." -ForegroundColor Green
        Write-Host "  → persistent ancestor ACEs are safe from cross-user escalation." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "RESULT: indeterminate — neither marker found." -ForegroundColor Yellow
        Write-Host "  Inspect stdout/stderr above." -ForegroundColor Yellow
    }
} finally {
    Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue

    # Cleanup: restore inheritance so the file picks up its parent ACL,
    # then nuke the scratch tree.
    try {
        $a = Get-Acl -LiteralPath $target
        $a.SetAccessRuleProtection($false, $true) | Out-Null
        Set-Acl -LiteralPath $target -AclObject $a
    } catch { }
    Remove-Item -Recurse -Force -LiteralPath $scratch -ErrorAction SilentlyContinue
}
