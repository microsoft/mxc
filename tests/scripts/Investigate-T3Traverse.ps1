# Investigate-T3Traverse.ps1
#
# Investigates hypothesis (1) from microsoft/mxc#304: T3 directory
# enumeration fails because `FindFirstFile` requires FILE_TRAVERSE on
# every ancestor of the policy path, and DaclManager only grants ACEs
# on the leaf — not on ancestors.
#
# Procedure:
#   1. Compute the AppContainer SID that DaclManager will target
#      (derived from the container_id we use in the config).
#   2. Run wxc-exec under forced T3 with `dir /b <rw>` and confirm it
#      fails (baseline).
#   3. As the host user, manually grant FILE_TRAVERSE (icacls "(X)")
#      to that SID on each ancestor of the rw path.
#   4. Re-run wxc-exec under forced T3 with the same `dir /b <rw>`.
#   5. If dir now succeeds, hypothesis (1) is confirmed.
#   6. Always: remove the manual ancestor grants on exit.
#
# Run as a non-elevated user. The script will fail with a clean error
# if WRITE_DAC is missing on any ancestor it tries to modify.

[CmdletBinding()]
param(
    # This script lives in `<repo>\tests\scripts\`; the repo root is two levels up.
    [string]$RepoRoot    = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$WxcDebug    = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src\target\debug\wxc-exec.exe'),
    [string]$ScratchRoot = (Join-Path $env:TEMP 'mxc-t3-traverse-investigation'),
    [string]$ContainerId = 'MxcT3TraverseInvestigation'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -----------------------------------------------------------------------
# AppContainer SID derivation via P/Invoke
# -----------------------------------------------------------------------
$signature = @"
[DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int DeriveAppContainerSidFromAppContainerName(string pszAppContainerName, out System.IntPtr ppsidAppContainerSid);
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern bool ConvertSidToStringSidW(System.IntPtr Sid, out System.IntPtr StringSid);
[DllImport("kernel32.dll")]
public static extern System.IntPtr LocalFree(System.IntPtr hMem);
[DllImport("advapi32.dll")]
public static extern System.IntPtr FreeSid(System.IntPtr pSid);
"@
Add-Type -MemberDefinition $signature -Name AppContainerHelper -Namespace MxcInvestigation -ErrorAction SilentlyContinue

function Get-AppContainerSid {
    param([string]$ProfileName)
    $sidPtr = [System.IntPtr]::Zero
    $hr = [MxcInvestigation.AppContainerHelper]::DeriveAppContainerSidFromAppContainerName($ProfileName, [ref]$sidPtr)
    if ($hr -ne 0) { throw "DeriveAppContainerSidFromAppContainerName failed: HRESULT=0x$($hr.ToString('X8'))" }
    try {
        $strPtr = [System.IntPtr]::Zero
        $ok = [MxcInvestigation.AppContainerHelper]::ConvertSidToStringSidW($sidPtr, [ref]$strPtr)
        if (-not $ok) { throw "ConvertSidToStringSidW failed" }
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($strPtr)
        } finally {
            [MxcInvestigation.AppContainerHelper]::LocalFree($strPtr) | Out-Null
        }
    } finally {
        [MxcInvestigation.AppContainerHelper]::FreeSid($sidPtr) | Out-Null
    }
}

# -----------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------
$sid = Get-AppContainerSid -ProfileName $ContainerId
Write-Host "AppContainer SID for '$ContainerId': $sid" -ForegroundColor Cyan

if (-not (Test-Path $WxcDebug)) {
    throw "wxc-exec not found at $WxcDebug — build it first (cargo build -p wxc)"
}

if (Test-Path $ScratchRoot) { Remove-Item -Recurse -Force -LiteralPath $ScratchRoot }
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$rw = Join-Path $ScratchRoot 'rw'
New-Item -ItemType Directory -Path $rw | Out-Null
'A' | Out-File -LiteralPath (Join-Path $rw 'a.txt') -Encoding ascii -Force
'B' | Out-File -LiteralPath (Join-Path $rw 'b.txt') -Encoding ascii -Force

# Compute ancestor chain: every directory from $rw up to (but not
# including) the volume root.
function Get-Ancestors {
    param([string]$Path)
    $ancestors = @()
    $cur = (Get-Item -LiteralPath $Path).Parent
    while ($cur -and $cur.FullName -ne $cur.Root.FullName) {
        $ancestors += $cur.FullName
        $cur = $cur.Parent
    }
    return $ancestors
}
$ancestors = Get-Ancestors -Path $rw
Write-Host ""
Write-Host "rw path:    $rw" -ForegroundColor Cyan
Write-Host "Ancestors that would receive FILE_TRAVERSE:" -ForegroundColor Cyan
foreach ($a in $ancestors) { Write-Host "  $a" }

# -----------------------------------------------------------------------
# Config + run helper
# -----------------------------------------------------------------------
$cfgPath = Join-Path $ScratchRoot 'config.json'
$config = [ordered]@{
    version     = '0.5.0-dev'
    containerId = $ContainerId
    containment = 'appcontainer'
    process     = [ordered]@{
        commandLine = "cmd /c dir /b ""$rw"" 2>&1"
        timeout     = 30000
    }
    filesystem  = [ordered]@{ readwritePaths = @($rw) }
    fallback    = [ordered]@{ allowDaclMutation = $true }
    ui          = [ordered]@{ disable = $false }
}
($config | ConvertTo-Json -Depth 10) | Out-File -LiteralPath $cfgPath -Encoding utf8 -Force

function Run-T3 {
    param([string]$Label)
    Write-Host ""
    Write-Host ('-' * 72)
    Write-Host "[$Label] running wxc-exec under MXC_FORCE_TIER=appcontainer-dacl" -ForegroundColor Cyan
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
        Write-Host "  exit:    $($p.ExitCode)"
        Write-Host "  stdout:  $($stdout.Trim())"
        if ($stderr.Trim()) { Write-Host "  stderr:  $($stderr.Trim())" }
        return [pscustomobject]@{
            ExitCode = $p.ExitCode
            Stdout   = $stdout
            Stderr   = $stderr
        }
    } finally {
        Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue
    }
}

function Classify {
    param([string]$Stdout, [string]$Stderr)
    $combined = "$Stdout`n$Stderr"
    if ($combined -match 'Access is denied') { return 'BLOCKED' }
    if ($combined -match 'a\.txt' -or $combined -match 'b\.txt') { return 'ENUMERABLE' }
    return 'UNKNOWN'
}

# -----------------------------------------------------------------------
# Step 1: baseline (no ancestor grants)
# -----------------------------------------------------------------------
$baseline = Run-T3 -Label 'BASELINE (no ancestor grants)'
$baselineResult = Classify -Stdout $baseline.Stdout -Stderr $baseline.Stderr
Write-Host "  classified: $baselineResult" -ForegroundColor $(if ($baselineResult -eq 'BLOCKED') { 'Yellow' } else { 'Red' })

# -----------------------------------------------------------------------
# Step 2: manually grant FILE_TRAVERSE on each ancestor for the AppContainer SID
# -----------------------------------------------------------------------
$granted = @()
try {
    Write-Host ""
    Write-Host ('-' * 72)
    Write-Host "Granting FILE_TRAVERSE (icacls '(X)') to the AppContainer SID on each ancestor..." -ForegroundColor Cyan
    foreach ($a in $ancestors) {
        Write-Host "  $a ... " -NoNewline
        $r = & icacls.exe $a /grant "*$($sid):(X)" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED" -ForegroundColor Yellow
            Write-Host "    $($r -join "`n    ")" -ForegroundColor Yellow
            Write-Host "  (this typically means WRITE_DAC is unavailable for this user on $a)" -ForegroundColor Yellow
            break
        }
        Write-Host "ok" -ForegroundColor Green
        $granted += $a
    }

    if ($granted.Count -eq 0) {
        Write-Host ""
        Write-Host "Could not grant traverse on any ancestor; cannot complete the experiment." -ForegroundColor Yellow
        return
    }
    if ($granted.Count -lt $ancestors.Count) {
        Write-Host ""
        Write-Host "Granted on $($granted.Count) of $($ancestors.Count) ancestors. Re-running anyway; the unreachable ancestors may still block the traverse chain." -ForegroundColor Yellow
    }

    # -------------------------------------------------------------------
    # Step 3: re-run wxc-exec under T3 with ancestor traverse in place
    # -------------------------------------------------------------------
    $patched = Run-T3 -Label 'PATCHED (with manual ancestor traverse)'
    $patchedResult = Classify -Stdout $patched.Stdout -Stderr $patched.Stderr
    Write-Host "  classified: $patchedResult" -ForegroundColor $(if ($patchedResult -eq 'ENUMERABLE') { 'Green' } else { 'Yellow' })

    # -------------------------------------------------------------------
    # Conclusion
    # -------------------------------------------------------------------
    Write-Host ""
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "Result" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host "  Baseline: $baselineResult"
    Write-Host "  With ancestor traverse: $patchedResult"
    Write-Host ""
    if ($baselineResult -eq 'BLOCKED' -and $patchedResult -eq 'ENUMERABLE') {
        Write-Host "HYPOTHESIS (1) CONFIRMED" -ForegroundColor Green
        Write-Host "  Missing FILE_TRAVERSE on ancestor directories is the cause."
        Write-Host "  DaclManager would need to grant traverse on every ancestor of"
        Write-Host "  each policy path (and remove on cleanup) for dir/FindFirstFile"
        Write-Host "  to work inside T3."
    } elseif ($baselineResult -eq 'BLOCKED' -and $patchedResult -eq 'BLOCKED') {
        Write-Host "HYPOTHESIS (1) NOT CONFIRMED" -ForegroundColor Yellow
        Write-Host "  Granting traverse on every reachable ancestor did not change"
        Write-Host "  the outcome. Either the granted ancestors weren't enough (some"
        Write-Host "  unreachable ancestor still blocks the chain), or the cause is"
        Write-Host "  not traverse-related — fall back to hypotheses (2)-(4) in #304."
    } else {
        Write-Host "INDETERMINATE" -ForegroundColor Yellow
        Write-Host "  Baseline=$baselineResult, patched=$patchedResult."
    }
} finally {
    Write-Host ""
    Write-Host ('-' * 72)
    Write-Host "Cleanup: removing manual ancestor grants..." -ForegroundColor Cyan
    foreach ($a in $granted) {
        Write-Host "  $a ... " -NoNewline
        $r = & icacls.exe $a /remove:g "*$sid" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED — manual cleanup needed: icacls `"$a`" /remove:g `"*$sid`"" -ForegroundColor Red
            Write-Host "    $($r -join "`n    ")" -ForegroundColor Yellow
        } else {
            Write-Host "removed" -ForegroundColor Green
        }
    }

    Remove-Item -Recurse -Force -LiteralPath $ScratchRoot -ErrorAction SilentlyContinue
}
