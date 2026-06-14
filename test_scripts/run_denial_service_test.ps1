# run_denial_service_test.ps1
# Tests the denied-resource detection pipeline end-to-end.
# Can run non-elevated (uses output parsing fallback).
# With elevation: start mxc-diagnostic-console first for ETW-based detection.

param(
    [switch]$WithService  # If set, attempts to start diag console for ETW capture
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

$RepoRoot = Split-Path -Parent $PSScriptRoot
$SdkDir = Join-Path $RepoRoot 'sdk'
$DiagBinary = [System.IO.Path]::Combine($RepoRoot, 'src', 'target', 'release', 'mxc-diagnostic-console.exe')
$DiagBinaryDebug = [System.IO.Path]::Combine($RepoRoot, 'src', 'target', 'debug', 'mxc-diagnostic-console.exe')

# Resolve the diagnostic binary path
if (Test-Path $DiagBinary) {
    $DiagExe = $DiagBinary
} elseif (Test-Path $DiagBinaryDebug) {
    $DiagExe = $DiagBinaryDebug
} else {
    $DiagExe = $null
}

Write-Host "=== MXC Denied-Resource Detection Pipeline Test ===" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Check prerequisites
# ---------------------------------------------------------------------------

Write-Host "[Step 1] Checking prerequisites..." -ForegroundColor Yellow

if ($DiagExe) {
    Write-Host "  Diagnostic binary found: $DiagExe" -ForegroundColor Green
} else {
    Write-Host "  Diagnostic binary NOT found (build with 'cargo build -p mxc_diagnostic_console')" -ForegroundColor DarkYellow
    Write-Host "  Will use output-parsing fallback only." -ForegroundColor DarkYellow
}

# Check SDK is built
$SdkDist = Join-Path $SdkDir 'dist'
if (-not (Test-Path (Join-Path $SdkDist 'index.js'))) {
    Write-Host "  SDK not built. Building..." -ForegroundColor DarkYellow
    Push-Location $SdkDir
    npm run build 2>&1 | Out-Null
    Pop-Location
}
Write-Host "  SDK built: OK" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# Step 2: Optionally start the diagnostic service in console mode
# ---------------------------------------------------------------------------

$DiagProcess = $null

if ($WithService -and $DiagExe) {
    Write-Host "[Step 2] Starting diagnostic console (ETW capture mode)..." -ForegroundColor Yellow

    # Check elevation — ETW requires admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "  WARNING: Not running as Administrator. ETW capture may fail." -ForegroundColor Red
        Write-Host "  Run this script elevated for full ETW-based detection." -ForegroundColor Red
    }

    try {
        # Interactive/console mode is the DEFAULT invocation -- there is no
        # --console flag (the binary rejects it with exit code 2 and dies
        # instantly, so no pipe is ever created). Start with no arguments.
        $DiagProcess = Start-Process -FilePath $DiagExe -PassThru -WindowStyle Hidden
        Write-Host "  Diagnostic console started (PID: $($DiagProcess.Id))" -ForegroundColor Green
        # Give it a moment to initialize the pipe
        Start-Sleep -Seconds 2
    } catch {
        Write-Host "  Failed to start diagnostic console: $_" -ForegroundColor Red
        $DiagProcess = $null
    }
} else {
    Write-Host "[Step 2] Skipping diagnostic service start (use -WithService to enable)" -ForegroundColor DarkYellow
}
Write-Host ""

# ---------------------------------------------------------------------------
# Step 3: Run a test that triggers PermissionError via output parsing
# ---------------------------------------------------------------------------

Write-Host "[Step 3] Running denial detection via output parsing..." -ForegroundColor Yellow

# Create a Node.js script that exercises the SDK's getDeniedResources()
$TestScript = @"
import { getDeniedResources } from '@microsoft/mxc-sdk';

const simulatedOutput = [
    "Traceback (most recent call last):",
    "  File \"test.py\", line 5, in <module>",
    "PermissionError: [WinError 5] Access is denied: 'C:\\\\Users\\\\test\\\\secret.txt'",
    "Error: connect ECONNREFUSED 127.0.0.1:8080",
].join('\n');

async function main() {
    const result = await getDeniedResources({
        containerName: 'test-denial-pipeline',
        output: simulatedOutput,
        runDaclProbe: false,
    });

    console.log(JSON.stringify({
        serviceAvailable: result.serviceAvailable,
        sourcesUsed: result.sourcesUsed,
        deniedCount: result.deniedResources.length,
        denials: result.deniedResources.map(d => ({
            path: d.path,
            resourceType: d.resourceType,
            source: d.source,
            accessType: d.accessType,
        })),
    }, null, 2));

    // Validate expected behavior
    if (result.deniedResources.length === 0) {
        console.error('FAIL: Expected at least one denied resource');
        process.exit(1);
    }
    if (!result.sourcesUsed.includes('output_parsing')) {
        console.error('FAIL: Expected output_parsing in sourcesUsed');
        process.exit(1);
    }

    const fileDenial = result.deniedResources.find(d => d.resourceType === 'file');
    if (!fileDenial) {
        console.error('FAIL: Expected at least one file denial');
        process.exit(1);
    }

    const networkDenial = result.deniedResources.find(d => d.resourceType === 'network');
    if (!networkDenial) {
        console.error('FAIL: Expected at least one network denial');
        process.exit(1);
    }

    console.log('\nPASS: Denied resource detection pipeline working correctly');
}

main().catch(err => {
    console.error('FAIL:', err.message);
    process.exit(1);
});
"@

$TempTestFile = Join-Path $SdkDir 'mxc_denial_test.mjs'
$TestScript | Out-File -FilePath $TempTestFile -Encoding utf8

Push-Location $SdkDir
try {
    $output = node $TempTestFile 2>&1
    $exitCode = $LASTEXITCODE
    Write-Host $output
    Write-Host ""

    if ($exitCode -eq 0) {
        Write-Host "  Output parsing detection: PASS" -ForegroundColor Green
    } else {
        Write-Host "  Output parsing detection: FAIL (exit code: $exitCode)" -ForegroundColor Red
    }
} catch {
    Write-Host "  Output parsing detection: ERROR - $_" -ForegroundColor Red
} finally {
    Pop-Location
}
Write-Host ""

# ---------------------------------------------------------------------------
# Step 4: Verify SDK can detect service availability
# ---------------------------------------------------------------------------

Write-Host "[Step 4] Checking denial service availability..." -ForegroundColor Yellow

$ServiceCheckScript = @"
import { isDenialServiceRunning } from '@microsoft/mxc-sdk';
const running = isDenialServiceRunning();
console.log('Service running: ' + running);
if (running) {
    console.log('  ETW-based detection is available');
} else {
    console.log('  Falling back to output-parsing only (expected without -WithService)');
}
"@

$TempServiceCheck = Join-Path $SdkDir 'mxc_service_check.mjs'
$ServiceCheckScript | Out-File -FilePath $TempServiceCheck -Encoding utf8

Push-Location $SdkDir
try {
    $output = node $TempServiceCheck 2>&1
    Write-Host "  $output" -ForegroundColor Green
} catch {
    Write-Host "  Service check: ERROR - $_" -ForegroundColor Red
} finally {
    Pop-Location
}
Write-Host ""

# ---------------------------------------------------------------------------
# Step 5: Cleanup
# ---------------------------------------------------------------------------

Write-Host "[Step 5] Cleaning up..." -ForegroundColor Yellow

if ($DiagProcess -and -not $DiagProcess.HasExited) {
    Write-Host "  Stopping diagnostic console (PID: $($DiagProcess.Id))..."
    Stop-Process -Id $DiagProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Host "  Diagnostic console stopped." -ForegroundColor Green
}

# Remove temp files
Remove-Item -Path $TempTestFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $TempServiceCheck -Force -ErrorAction SilentlyContinue
Write-Host "  Temp files cleaned up." -ForegroundColor Green

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
