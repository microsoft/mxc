# Investigate-T3ManualAcl.ps1
#
# Bypasses DaclManager. Manually applies ACEs we choose, then runs
# wxc-exec with an EMPTY filesystem policy (so DaclManager doesn't
# touch anything). Lets us isolate "is the issue DaclManager's
# grant shape, or is it fundamental to AppContainer + Windows?"
#
# Two test runs:
#   A. Grant SID:(F) on rw leaf + traverse on every ancestor we can.
#      Try `dir /b rw`. If still BLOCKED → AppContainer fundamental.
#      If ENUMERABLE → DaclManager's grant shape is the issue.
#   B. Same as A, but also grant "ALL APPLICATION PACKAGES":(F) on rw.
#      Tests whether AppContainer requires the umbrella SID.

[CmdletBinding()]
param(
    # This script lives in `<repo>\tests\scripts\`; the repo root is two levels up.
    [string]$WxcDebug    = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-exec.exe'),
    [string]$ScratchRoot = (Join-Path $env:TEMP 'mxc-t3-manual-acl'),
    [string]$ContainerId = 'MxcT3ManualAcl'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- SID derivation P/Invoke ---
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
Add-Type -MemberDefinition $signature -Name H -Namespace MxcAcl -ErrorAction SilentlyContinue

function Get-AcSid {
    param([string]$Name)
    $sid = [System.IntPtr]::Zero
    $hr = [MxcAcl.H]::DeriveAppContainerSidFromAppContainerName($Name, [ref]$sid)
    if ($hr -ne 0) { throw "Derive failed: 0x$($hr.ToString('X8'))" }
    try {
        $str = [System.IntPtr]::Zero
        $ok = [MxcAcl.H]::ConvertSidToStringSidW($sid, [ref]$str)
        if (-not $ok) { throw "Convert failed" }
        try { return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($str) }
        finally { [MxcAcl.H]::LocalFree($str) | Out-Null }
    } finally { [MxcAcl.H]::FreeSid($sid) | Out-Null }
}

$acSid = Get-AcSid -Name $ContainerId
Write-Host "AppContainer SID: $acSid" -ForegroundColor Cyan

# --- Scratch ---
if (Test-Path $ScratchRoot) { Remove-Item -Recurse -Force -LiteralPath $ScratchRoot }
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$rw = Join-Path $ScratchRoot 'rw'
New-Item -ItemType Directory -Path $rw | Out-Null
'A' | Out-File -LiteralPath (Join-Path $rw 'a.txt') -Encoding ascii -Force
'B' | Out-File -LiteralPath (Join-Path $rw 'b.txt') -Encoding ascii -Force

function Get-Ancestors {
    param([string]$Path)
    $a = @()
    $cur = (Get-Item -LiteralPath $Path).Parent
    while ($cur -and $cur.FullName -ne $cur.Root.FullName) {
        $a += $cur.FullName
        $cur = $cur.Parent
    }
    return $a
}
$ancestors = Get-Ancestors -Path $rw

# --- Empty-FS config: DaclManager won't touch anything ---
$cfgPath = Join-Path $ScratchRoot 'config.json'
$cfg = [ordered]@{
    version     = '0.5.0-dev'
    containerId = $ContainerId
    containment = 'appcontainer'
    process     = [ordered]@{
        commandLine = "cmd /c dir /b ""$rw"" 2>&1"
        timeout     = 30000
    }
    fallback    = [ordered]@{ allowDaclMutation = $true }
    ui          = [ordered]@{ disable = $false }
}
($cfg | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $cfgPath -Encoding utf8 -Force

function Run-T3 {
    param([string]$Label)
    Write-Host ""
    Write-Host "[$Label] ..." -ForegroundColor Cyan
    $env:MXC_FORCE_TIER = 'appcontainer-dacl'
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName  = $WxcDebug
        $psi.Arguments = "`"$cfgPath`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow  = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        $p.WaitForExit(30000) | Out-Null
        Write-Host "  exit=$($p.ExitCode); stdout=$($stdout.Trim()); stderr=$($stderr.Trim())"
        $combined = "$stdout`n$stderr"
        if     ($combined -match 'Access is denied') { return 'BLOCKED' }
        elseif ($combined -match 'a\.txt' -or $combined -match 'b\.txt') { return 'ENUMERABLE' }
        else                                          { return 'UNKNOWN' }
    } finally {
        Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue
    }
}

function Grant-Sid {
    param([string]$Path, [string]$Sid, [string]$Rights)
    $r = & icacls.exe $Path /grant "*$($Sid):($Rights)" 2>&1
    return @{ ok = ($LASTEXITCODE -eq 0); output = ($r -join "`n") }
}

function Remove-SidGrants {
    param([string]$Path, [string]$Sid)
    & icacls.exe $Path /remove:g "*$Sid" 2>&1 | Out-Null
}

$cleanupTargets = @()  # @{ path; sid }
try {
    # --- TEST A: AppContainer SID full on leaf + traverse on ancestors ---
    Write-Host ""
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "TEST A: AppContainer SID full on rw + traverse on ancestors" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan

    $g = Grant-Sid -Path $rw -Sid $acSid -Rights 'F'
    Write-Host "  grant F on rw: $($g.ok)"
    if ($g.ok) { $cleanupTargets += @{ path=$rw; sid=$acSid } }

    foreach ($a in $ancestors) {
        $g = Grant-Sid -Path $a -Sid $acSid -Rights 'X'
        $tag = if ($g.ok) { 'ok' } else { 'FAIL' }
        Write-Host "  grant X on $a : $tag"
        if ($g.ok) { $cleanupTargets += @{ path=$a; sid=$acSid } }
    }

    $resultA = Run-T3 -Label 'TEST A'
    Write-Host "  -> $resultA" -ForegroundColor $(if ($resultA -eq 'ENUMERABLE') { 'Green' } else { 'Yellow' })

    # --- TEST B: add ALL APPLICATION PACKAGES SID grant ---
    Write-Host ""
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "TEST B: same as A + ALL APPLICATION PACKAGES (S-1-15-2-1) F on rw" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan

    $aapSid = 'S-1-15-2-1'
    $g = Grant-Sid -Path $rw -Sid $aapSid -Rights 'F'
    Write-Host "  grant F on rw for AAP: $($g.ok)"
    if ($g.ok) { $cleanupTargets += @{ path=$rw; sid=$aapSid } }
    foreach ($a in $ancestors) {
        $g = Grant-Sid -Path $a -Sid $aapSid -Rights 'X'
        $tag = if ($g.ok) { 'ok' } else { 'FAIL' }
        Write-Host "  grant X on $a for AAP: $tag"
        if ($g.ok) { $cleanupTargets += @{ path=$a; sid=$aapSid } }
    }

    $resultB = Run-T3 -Label 'TEST B'
    Write-Host "  -> $resultB" -ForegroundColor $(if ($resultB -eq 'ENUMERABLE') { 'Green' } else { 'Yellow' })

    # --- Summary ---
    Write-Host ""
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "Summary" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "  Test A (specific SID full + traverse): $resultA"
    Write-Host "  Test B (Test A + ALL APP PKGS):        $resultB"
    Write-Host ""
    if     ($resultA -eq 'ENUMERABLE') {
        Write-Host "Specific-SID approach alone is sufficient. DaclManager's grant" -ForegroundColor Green
        Write-Host "shape is probably correct; ancestor coverage is the only gap." -ForegroundColor Green
    } elseif ($resultB -eq 'ENUMERABLE') {
        Write-Host "ALL APPLICATION PACKAGES SID grant was needed in addition." -ForegroundColor Yellow
        Write-Host "DaclManager needs to grant both SIDs for enumeration to work." -ForegroundColor Yellow
    } else {
        Write-Host "Neither approach works. The cause is not (just) about which" -ForegroundColor Yellow
        Write-Host "SIDs appear in the DACL. Possible: enumeration vs. open uses" -ForegroundColor Yellow
        Write-Host "different access checks in newer Windows builds; LowBox policy" -ForegroundColor Yellow
        Write-Host "has additional constraints; or 'WRITE_DAC unavailable on C:\Users'" -ForegroundColor Yellow
        Write-Host "really is the chain-breaker even when AAP is present." -ForegroundColor Yellow
    }
} finally {
    Write-Host ""
    Write-Host "Cleanup..." -ForegroundColor Cyan
    foreach ($t in $cleanupTargets) {
        Remove-SidGrants -Path $t.path -Sid $t.sid
    }
    Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue
}
