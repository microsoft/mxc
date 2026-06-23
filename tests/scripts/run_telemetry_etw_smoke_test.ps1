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

# MXC public provider name. The provider GUID is derived deterministically from
# this name by `tracelogging::define_provider!` using the standard ETW name-hash
# algorithm (the same algorithm used by <TraceLoggingProvider.h>, WIL's
# IMPLEMENT_TRACELOGGING_CLASS, and .NET's EventSource). We compute the GUID from
# the name here rather than hard-coding a literal, so the test stays in lockstep
# with the provider name and never embeds a magic constant.
$providerName = 'Microsoft.MXC'

function Get-TraceLoggingProviderGuid {
    param([Parameter(Mandatory)][string]$Name)

    # EventSource/TraceLogging name->GUID: SHA1 over a fixed namespace seed
    # followed by the UTF-16BE bytes of the upper-cased name; first 16 bytes of
    # the digest become the GUID with the version nibble forced to 5.
    $seed = [byte[]]@(
        0x48, 0x2C, 0x2D, 0xB2, 0xC3, 0x90, 0x47, 0xC8,
        0x87, 0xF8, 0x1A, 0x15, 0xBF, 0xC1, 0x30, 0xFB
    )
    $nameBytes = [System.Text.Encoding]::BigEndianUnicode.GetBytes($Name.ToUpperInvariant())
    $buffer = New-Object byte[] ($seed.Length + $nameBytes.Length)
    [Array]::Copy($seed, 0, $buffer, 0, $seed.Length)
    [Array]::Copy($nameBytes, 0, $buffer, $seed.Length, $nameBytes.Length)

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hash = $sha1.ComputeHash($buffer)
    } finally {
        $sha1.Dispose()
    }

    $guidBytes = New-Object byte[] 16
    [Array]::Copy($hash, 0, $guidBytes, 0, 16)
    $guidBytes[7] = ($guidBytes[7] -band 0x0F) -bor 0x50
    return '{' + ([guid]::new($guidBytes)).ToString() + '}'
}

$providerGuid = Get-TraceLoggingProviderGuid -Name $providerName
$sessionName  = 'MxcTelemetryTest'
$repoRoot     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host "=== MXC ETW Capture Smoke Test ===" -ForegroundColor Cyan
Write-Host "Provider: $providerName  $providerGuid"

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

logman create trace $sessionName -ets -o "$etlFile" -p $providerGuid 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create ETW trace session"
}
Write-Host "ETW session started, writing to $etlFile"

# ---------------------------------------------------------------------------
# Step 2: Run wxc-exec with telemetry enabled
# ---------------------------------------------------------------------------
Write-Host "`n--- Running wxc-exec with telemetry ---" -ForegroundColor Yellow

try {
    # Run with --experimental to enable the telemetry section. The provider is
    # registered during init (before execution); the MXC.Execution / MXC.Error
    # events are emitted on completion, after the runner returns. The sandbox
    # itself may fail (e.g. AppContainer prerequisites), but completion
    # telemetry still fires for the failure, so events should be captured.
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
    Write-Host "FAILED: ETL file is empty — no events captured." -ForegroundColor Red
    Write-Host "All prerequisites were met (admin, wxc-exec present, ETW session created)," -ForegroundColor Red
    Write-Host "so the provider should have emitted at least one completion event." -ForegroundColor Red
    exit 1
}

# Convert .etl to XML for inspection.
$xmlFile = Join-Path $etlDir 'mxc_trace.xml'
tracerpt "$etlFile" -o "$xmlFile" -of XML -y 2>&1 | Out-Host

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
    Write-Host "`n=== ETW CAPTURE SMOKE TEST FAILED ===" -ForegroundColor Red
    Write-Host "ETL file had content ($etlSize bytes) but no parseable events were found." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
if (-not $SkipClean) {
    Remove-Item -Recurse -Force $etlDir -ErrorAction SilentlyContinue
}
