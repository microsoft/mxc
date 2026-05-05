# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs IsolationSession state-aware lifecycle E2E tests. Companion to
    run_isolation_session_tests.ps1 — that script asserts the one-shot path;
    this script asserts the state-aware path (`phase` / `sandboxId` envelope
    style, multi-invocation lifecycle).

.DESCRIPTION
    Each test invokes wxc-exec.exe with a base64-encoded state-aware request
    envelope, parses the JSON response on stdout, and asserts on the
    envelope's `result` or `error` fields. Subsequent commits extend the
    skeleton with start, exec, stop, and deprovision tests; this revision
    asserts only the provision phase.

    This script must run INTERACTIVELY on the test host. The OS-side service
    cohort check rejects network-logon tokens, so PSSession-driven
    invocations fail with Access Denied. Copy wxc-exec.exe and this script
    to the host, then run it directly in cmd.exe or PowerShell on that host.

    Prerequisite probes (skip if missing — not a failure):
      - IsoSessionApp.dll present in System32
      - WinRT activatable class IsoSessionOps registered
      - wxc-exec.exe responds to a state-aware request without
        backend_unavailable (catches feature-flag-off builds)

.PARAMETER WxcExePath
    Path to wxc-exec.exe. Default probes the host-arch target dir, then
    other-arch target dir, then the default release/debug dirs.

.EXAMPLE
    .\run_isolation_session_state_aware_tests.ps1
    .\run_isolation_session_state_aware_tests.ps1 -WxcExePath C:\test\wxc-exec.exe
#>

param(
    [string]$WxcExePath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

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
    Write-Host "Build with: cargo build --release --features isolation_session --target $HostTarget" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExePath explicitly." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nIsolationSession State-Aware E2E Tests" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "Binary: $WxcExec`n" -ForegroundColor Gray

# ---------------- Prerequisite probes ----------------

if (-not (Test-Path 'C:\Windows\System32\IsoSessionApp.dll')) {
    Write-Host "SKIPPED: IsoSessionApp.dll not present in System32" -ForegroundColor Yellow
    exit 0
}

$IsoSessionOpsKey = "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.AI.IsolationSession.IsoSessionOps"
if (-not (Test-Path $IsoSessionOpsKey)) {
    Write-Host "SKIPPED: Windows.AI.IsolationSession.IsoSessionOps WinRT class not registered" -ForegroundColor Yellow
    exit 0
}

# ---------------- Helpers ----------------

# Encode a state-aware request envelope and run wxc-exec against it. Returns
# a hashtable with stdout / stderr / exitCode for the caller to assert on.
function Invoke-StateAware {
    param(
        [Parameter(Mandatory = $true)] [hashtable]$Request,
        [switch]$Experimental
    )
    $json = $Request | ConvertTo-Json -Compress -Depth 12
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))

    $argList = @()
    if ($Experimental.IsPresent) { $argList += '--experimental' }
    $argList += @('--config-base64', $b64)

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        # Start-Process redirects to file so we can capture both streams without
        # ConPTY interleaving — wxc-exec's stdout must be a single envelope.
        $proc = Start-Process -FilePath $WxcExec -ArgumentList $argList `
            -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile `
            -NoNewWindow -PassThru -Wait
        @{
            ExitCode = $proc.ExitCode
            Stdout   = (Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue)
            Stderr   = (Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue)
        }
    } finally {
        Remove-Item $stdoutFile -ErrorAction SilentlyContinue
        Remove-Item $stderrFile -ErrorAction SilentlyContinue
    }
}

# Parses the wxc-exec stdout envelope and returns the parsed object, or
# $null if the stdout is not valid JSON.
function Parse-Envelope {
    param([string]$Stdout)
    if ([string]::IsNullOrWhiteSpace($Stdout)) { return $null }
    try { $Stdout | ConvertFrom-Json } catch { $null }
}

# Returns "result" / "error" / "<empty>" describing which arm of the envelope
# is present. Useful for failure messages.
function Envelope-Arm {
    param($Envelope)
    if ($null -eq $Envelope) { return '<empty>' }
    if ($Envelope.PSObject.Properties.Name -contains 'result') { return 'result' }
    if ($Envelope.PSObject.Properties.Name -contains 'error') { return 'error' }
    '<unknown>'
}

# ---------------- Backend-availability probe ----------------

# Sends a state-aware provision request and surfaces a `backend_unavailable`
# envelope as a SKIP. This catches feature-flag-off builds without raising
# false test failures.
$probeRequest = @{
    phase       = 'provision'
    containment = 'isolation_session'
}
$probe = Invoke-StateAware -Request $probeRequest -Experimental
$probeEnv = Parse-Envelope -Stdout $probe.Stdout
if ($null -ne $probeEnv -and $probeEnv.error.code -eq 'backend_unavailable') {
    Write-Host "SKIPPED: wxc-exec reports backend_unavailable (likely built without --features isolation_session)" -ForegroundColor Yellow
    exit 0
}

# ---------------- Tests ----------------

$TestsRun = 0
$TestsFailed = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:TestsRun++
    if ($Condition) {
        Write-Host "  PASS: $Message" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: $Message" -ForegroundColor Red
        $script:TestsFailed++
    }
}

# Test 1: provision returns iso:wxc-<8-hex> and a backend_unavailable-free
# envelope.
Write-Host "[provision] sandbox_id format" -ForegroundColor Cyan
$provisionResult = Invoke-StateAware -Request $probeRequest -Experimental
$provisionEnv = Parse-Envelope -Stdout $provisionResult.Stdout
$arm = Envelope-Arm $provisionEnv

$sandboxId = $null

if ($arm -ne 'result') {
    Write-Host "  Envelope arm: $arm" -ForegroundColor Red
    Write-Host "  Stdout: $($provisionResult.Stdout)" -ForegroundColor Gray
    Write-Host "  Stderr: $($provisionResult.Stderr)" -ForegroundColor Gray
    Assert-True $false "provision returned a result envelope"
} else {
    Assert-True ($provisionResult.ExitCode -eq 0) "exit code = 0 on success"
    $sandboxId = $provisionEnv.result.sandboxId
    $agentUserName = $provisionEnv.result.metadata.agentUserName
    Assert-True ($sandboxId -match '^iso:wxc-[0-9a-f]{8}$') "sandbox_id matches iso:wxc-<8-hex> ($sandboxId)"
    Assert-True ($null -ne $agentUserName) "metadata.agentUserName is present ($agentUserName)"
    # TODO(I5): once deprovision lands, wrap this test body in try-finally and
    # call deprovision on $sandboxId to avoid leaking the agent user across
    # test runs. Until then, the OS-side service retains the registration —
    # acceptable while we are validating early phases only.
}

# Test 2: start succeeds against the provisioned sandbox. Exercises the
# multi-invocation pattern — provision was a separate wxc-exec process; this
# is a fresh wxc-exec process consuming the same sandbox_id. Skipped if
# provision did not return a usable id.
if ($null -ne $sandboxId) {
    Write-Host "[start] provision + start sequence" -ForegroundColor Cyan
    $startRequest = @{
        phase     = 'start'
        sandboxId = $sandboxId
    }
    $startResult = Invoke-StateAware -Request $startRequest -Experimental
    $startEnv = Parse-Envelope -Stdout $startResult.Stdout
    $startArm = Envelope-Arm $startEnv

    if ($startArm -ne 'result') {
        Write-Host "  Envelope arm: $startArm" -ForegroundColor Red
        Write-Host "  Stdout: $($startResult.Stdout)" -ForegroundColor Gray
        Write-Host "  Stderr: $($startResult.Stderr)" -ForegroundColor Gray
        Assert-True $false "start returned a result envelope"
    } else {
        Assert-True ($startResult.ExitCode -eq 0) "exit code = 0 on success"
        # Start has no metadata in v1 — `result` should be an empty object.
        Assert-True ($null -eq $startEnv.result.metadata) "result.metadata is absent (no start metadata in v1)"
    }
}

# ---------------- Summary ----------------

Write-Host ""
if ($TestsFailed -eq 0) {
    Write-Host "ALL $TestsRun TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$TestsFailed of $TestsRun TESTS FAILED" -ForegroundColor Red
    exit 1
}
