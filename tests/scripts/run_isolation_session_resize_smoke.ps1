# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Manual TTY resize-event smoke for the IsolationSession backend.

.DESCRIPTION
    Launches an isolation session that runs a "ruler line" loop inside an
    agent powershell.exe: every 500 ms the agent prints a single line
    sized to the inner shell's perceived console width, with a trailing
    '|' marking the right edge.

    The user resizes the host cmd.exe window while the loop is running
    and observes:

      - The 'cols=' / 'rows=' header values printed each iteration.
      - Where the trailing '|' lands relative to the actual right edge.
      - Whether lines wrap cleanly at narrow widths.

    This is a MANUAL smoke -- there is no automated pass/fail oracle for
    a rendering bug. Must run on a real cmd.exe console on the test host;
    PSSession invocations are rejected with Access Denied.

    Healthy outcome:
      - 'cols=' / 'rows=' update within ~500 ms of every resize.
      - '|' stays at the actual right edge at every width.
      - Lines wrap cleanly when narrowing; no concatenation when widening.

    Regression outcome (resize event propagation broken):
      - 'cols=' / 'rows=' frozen at the initial values.
      - '|' drifts away from the actual right edge after resize.
      - Lines render with concatenation / wrap chaos at non-initial widths.

    Ctrl-C exits the loop and tears down the isolation session.

.PARAMETER WxcExePath
    Path to wxc-exec.exe (built with --features isolation_session). If
    omitted, the script probes the usual target directories under
    <repo>/src/target/.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File run_isolation_session_resize_smoke.ps1
#>

param(
    [string]$WxcExePath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# ---------------- Locate wxc-exec.exe ----------------

$HostTarget = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    'aarch64-pc-windows-msvc'
} else {
    'x86_64-pc-windows-msvc'
}
$OtherTarget = if ($HostTarget -eq 'aarch64-pc-windows-msvc') {
    'x86_64-pc-windows-msvc'
} else {
    'aarch64-pc-windows-msvc'
}

if ($WxcExePath) {
    $WxcExec = $WxcExePath
} else {
    $CandidatePaths = @(
        (Join-Path $RepoRoot "src\target\$HostTarget\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$OtherTarget\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$HostTarget\debug\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$OtherTarget\debug\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\debug\wxc-exec.exe")
    )
    $WxcExec = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found." -ForegroundColor Red
    Write-Host "Searched:" -ForegroundColor Yellow
    foreach ($p in $CandidatePaths) { Write-Host "  - $p" -ForegroundColor Yellow }
    Write-Host "Build with: cargo build --release --features isolation_session --target $HostTarget" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExePath explicitly." -ForegroundColor Yellow
    exit 1
}

# ---------------- Backend-availability probe ----------------

if (-not (Test-Path 'C:\Windows\System32\IsoSessionApp.dll')) {
    Write-Host "SKIPPED: IsoSessionApp.dll not present in System32" -ForegroundColor Yellow
    exit 0
}
$IsoSessionOpsKey = "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.AI.IsolationSession.IsoSessionOps"
if (-not (Test-Path $IsoSessionOpsKey)) {
    Write-Host "SKIPPED: Windows.AI.IsolationSession.IsoSessionOps WinRT class not registered" -ForegroundColor Yellow
    exit 0
}

# ---------------- Build the encoded inner loop ----------------
#
# powershell.exe -EncodedCommand expects UTF-16LE base64 of the script
# body. Encoding the body this way avoids quote-escaping headaches when
# it travels through JSON, then through cmd.exe /c.

$loopScript = @'
function Build-Ruler {
    param([int]$Width, [int]$Cols, [int]$Rows, [string]$Stamp)
    $header = "$Stamp cols=$Cols rows=$Rows "
    # Reserve 1 char for the right-edge '|'; rest is ruler.
    $rulerLen = [Math]::Max(0, $Width - $header.Length - 1)
    if ($rulerLen -le 0) {
        return $header.Substring(0, [Math]::Min($header.Length, $Width))
    }
    # Build a ruler like "....10....20....30....40...." up to $rulerLen chars.
    $sb = New-Object System.Text.StringBuilder
    for ($i = 1; $i -le $rulerLen; $i++) {
        if ($i % 10 -eq 0) {
            $tag = ($i).ToString()
            # Back up so the number overwrites the dots it replaces.
            $sb.Length = [Math]::Max(0, $sb.Length - $tag.Length + 1)
            [void]$sb.Append($tag)
        } else {
            [void]$sb.Append('.')
        }
    }
    $ruler = $sb.ToString()
    if ($ruler.Length -gt $rulerLen) { $ruler = $ruler.Substring(0, $rulerLen) }
    return $header + $ruler + '|'
}

while ($true) {
    $cols  = [Console]::WindowWidth
    $rows  = [Console]::WindowHeight
    $stamp = (Get-Date -f 'HH:mm:ss.fff')
    Write-Host (Build-Ruler -Width $cols -Cols $cols -Rows $rows -Stamp $stamp)
    Start-Sleep -Milliseconds 500
}
'@

$encodedLoop = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loopScript))

# ---------------- Build the wxc-exec config envelope ----------------
#
# Shape matches tests/configs/isolation_session_powershell_interactive.json:
# top-level version + containerId + containment + process. timeout=0 lets
# the loop run until Ctrl-C.

$config = [ordered]@{
    version     = '0.6.0-alpha'
    containerId = 'isolation-session-resize-smoke'
    containment = 'isolation_session'
    process     = [ordered]@{
        commandLine = "powershell.exe -NoProfile -EncodedCommand $encodedLoop"
        timeout     = 0
    }
}
$configJson   = $config | ConvertTo-Json -Compress -Depth 10
$configBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($configJson))

# ---------------- User-facing header ----------------

Write-Host ""
Write-Host "IsolationSession TTY resize smoke" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "Binary: $WxcExec" -ForegroundColor Gray
Write-Host ""
Write-Host "This launches an isolation session running a ruler-line loop." -ForegroundColor Gray
Write-Host "Every 500 ms the agent prints one line sized to its perceived" -ForegroundColor Gray
Write-Host "console width. The trailing '|' marks the right edge." -ForegroundColor Gray
Write-Host ""
Write-Host "WHAT TO DO:" -ForegroundColor Cyan
Write-Host "  1. Wait for the loop to start emitting ruler lines." -ForegroundColor Gray
Write-Host "  2. Drag-resize this cmd.exe window (try narrower AND wider)." -ForegroundColor Gray
Write-Host "  3. Watch the 'cols=' / 'rows=' header AND where '|' lands" -ForegroundColor Gray
Write-Host "     relative to the actual right edge." -ForegroundColor Gray
Write-Host "  4. Ctrl-C to exit." -ForegroundColor Gray
Write-Host ""
Write-Host "EXPECTED:" -ForegroundColor Cyan
Write-Host "  - cols= / rows= update within ~500 ms of every resize." -ForegroundColor Gray
Write-Host "  - '|' stays at the actual right edge at every width." -ForegroundColor Gray
Write-Host "  - Lines wrap cleanly when narrowing; no concatenation on widen." -ForegroundColor Gray
Write-Host ""

# ---------------- Run ----------------

& $WxcExec --experimental --config-base64 $configBase64
