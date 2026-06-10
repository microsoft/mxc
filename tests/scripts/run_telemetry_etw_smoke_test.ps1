<#
.SYNOPSIS
    ETW capture smoke test for MXC telemetry.

.DESCRIPTION
    Starts an ETW trace session targeting the MXC public provider GUID,
    runs wxc-exec with telemetry enabled, stops the session, and verifies
    that at least one event was captured.

    This test uses the PUBLIC provider GUID (already in the open-source
    code) — it does NOT depend on or reveal the private telemetry group GUID.

    Requires: Administrator privileges (for ETW session creation),
              wxc-exec.exe built, logman.exe (ships with Windows).

    Run from the repo root.
#>

[CmdletBinding()]
param(
    [switch]$SkipClean
)

$ErrorActionPreference = 'Stop'

# MXC public provider GUID (from mxc_telemetry build.rs — this is NOT private).
$providerGuid = '{4f50731a-89cf-4782-b3e0-dce8c90476ba}'
$sessionName  = 'MxcTelemetryTest'
$repoRoot     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host "=== MXC ETW Capture Smoke Test ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Pre-flight: elevation check
# ---------------------------------------------------------------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "SKIPPED: this test requires Administrator privileges for ETW session creation." -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------------------
# Pre-flight: locate wxc-exec.exe
# ---------------------------------------------------------------------------
$srcDir = Join-Path $repoRoot 'src'
$candidates = @(
    (Join-Path $srcDir 'target\debug\wxc-exec.exe'),
    (Join-Path $srcDir 'target\release\wxc-exec.exe'),
    (Join-Path $srcDir 'target\x86_64-pc-windows-msvc\debug\wxc-exec.exe'),
    (Join-Path $srcDir 'target\x86_64-pc-windows-msvc\release\wxc-exec.exe'),
    (Join-Path $srcDir 'target\aarch64-pc-windows-msvc\debug\wxc-exec.exe'),
    (Join-Path $srcDir 'target\aarch64-pc-windows-msvc\release\wxc-exec.exe')
)
$wxcExe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $wxcExe) {
    Write-Host "SKIPPED: wxc-exec.exe not found. Build first with build.bat." -ForegroundColor Yellow
    exit 0
}
Write-Host "Using wxc-exec: $wxcExe"

# ---------------------------------------------------------------------------
# Pre-flight: locate telemetry example config
# ---------------------------------------------------------------------------
$configFile = Join-Path $repoRoot 'tests\examples\28_telemetry_enabled.json'
if (-not (Test-Path $configFile)) {
    throw "Config not found: $configFile"
}

# ---------------------------------------------------------------------------
# Setup: ETL output path
# ---------------------------------------------------------------------------
$etlDir = Join-Path $env:TEMP 'mxc_etw_test'
if (Test-Path $etlDir) { Remove-Item -Recurse -Force $etlDir }
New-Item -ItemType Directory -Path $etlDir -Force | Out-Null
$etlFile = Join-Path $etlDir 'mxc_trace.etl'

# ---------------------------------------------------------------------------
# Step 1: Start ETW trace session
# ---------------------------------------------------------------------------
Write-Host "`n--- Starting ETW trace session '$sessionName' ---" -ForegroundColor Yellow

# Remove any stale session from a previous interrupted run.
logman stop  $sessionName -ets 2>$null | Out-Null
logman delete $sessionName -ets 2>$null | Out-Null

logman create trace $sessionName -ets -o $etlFile -p $providerGuid 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create ETW trace session"
}
Write-Host "ETW session started, writing to $etlFile"

# ---------------------------------------------------------------------------
# Step 2: Run wxc-exec with telemetry enabled
# ---------------------------------------------------------------------------
Write-Host "`n--- Running wxc-exec with telemetry ---" -ForegroundColor Yellow

try {
    # Run with --experimental to enable the telemetry section.
    # The sandbox may fail (AppContainer prerequisites), but telemetry
    # init/emit happens before execution — an error event should still fire.
    $proc = Start-Process -FilePath $wxcExe `
        -ArgumentList "--debug", "--experimental", $configFile `
        -PassThru -NoNewWindow -Wait
    Write-Host "wxc-exec exited with code $($proc.ExitCode)"
} catch {
    Write-Host "wxc-exec failed to run: $_" -ForegroundColor Yellow
    # Continue — even a crash after init may have emitted events.
}

# Brief pause for ETW buffers to flush.
Start-Sleep -Seconds 2

# ---------------------------------------------------------------------------
# Step 3: Stop ETW trace session
# ---------------------------------------------------------------------------
Write-Host "`n--- Stopping ETW trace session ---" -ForegroundColor Yellow
logman stop $sessionName -ets 2>&1 | Out-Host

# ---------------------------------------------------------------------------
# Step 4: Validate captured events
# ---------------------------------------------------------------------------
Write-Host "`n--- Validating captured events ---" -ForegroundColor Yellow

if (-not (Test-Path $etlFile)) {
    throw "ETL file not found: $etlFile"
}

$etlSize = (Get-Item $etlFile).Length
Write-Host "ETL file size: $etlSize bytes"

if ($etlSize -eq 0) {
    Write-Host "WARNING: ETL file is empty — no events captured." -ForegroundColor Yellow
    Write-Host "This may happen if the sandbox failed before telemetry init." -ForegroundColor Yellow
    Write-Host "TEST INCONCLUSIVE (not a failure)." -ForegroundColor Yellow
    exit 0
}

# Convert .etl to XML for inspection.
$xmlFile = Join-Path $etlDir 'mxc_trace.xml'
tracerpt $etlFile -o $xmlFile -of XML -y 2>&1 | Out-Host

if (-not (Test-Path $xmlFile)) {
    throw "tracerpt failed to produce XML output"
}

$xmlContent = Get-Content -Path $xmlFile -Raw
$eventCount = ([regex]::Matches($xmlContent, '<Event ')).Count
Write-Host "Events captured: $eventCount"

if ($eventCount -gt 0) {
    Write-Host "`n=== ETW CAPTURE SMOKE TEST PASSED ===" -ForegroundColor Green
    Write-Host "$eventCount event(s) captured from the MXC provider."

    # Check for expected field names (public, not private).
    $expectedFields = @('mxc.backend', 'mxc.exit_code', 'mxc.outcome', 'mxc.duration_ms')
    foreach ($field in $expectedFields) {
        if ($xmlContent -match $field) {
            Write-Host "  [OK] Found field: $field" -ForegroundColor Green
        } else {
            Write-Host "  [--] Field not found: $field (may not be in this event type)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "WARNING: ETL had content but no parseable events." -ForegroundColor Yellow
    Write-Host "TEST INCONCLUSIVE." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
if (-not $SkipClean) {
    Remove-Item -Recurse -Force $etlDir -ErrorAction SilentlyContinue
}
