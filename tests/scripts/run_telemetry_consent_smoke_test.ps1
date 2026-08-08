# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Telemetry consent CLI smoke test.
#
# Exercises `wxc-exec.exe --telemetry-consent-{status,grant,revoke,source}`
# end to end against an isolated consent store, so it never touches the real
# developer/CI-machine one. See docs/telemetry/telemetry-consent-design.md.
#
# Debug builds only, by design: isolation relies on
# MXC_TEST_LOCALAPPDATA_OVERRIDE, which wxc_common::telemetry::consent
# compiles out of release builds (a release binary always resolves the real
# per-user known-folder path). There is no safe way to run this against a
# release binary without mutating the real store, so -Release is refused
# rather than silently doing that.
#
# Usage:
#   .\run_telemetry_consent_smoke_test.ps1
#   .\run_telemetry_consent_smoke_test.ps1 -BinDir <dir-with-a-debug-wxc-exec>

param(
    [string]$BinDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $BinDir) {
    $BinDir = Join-Path $RepoRoot "src\target\debug"
}

$WxcExec = Join-Path $BinDir "wxc-exec.exe"

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build -p wxc' first (debug; see the note above about release builds)." -ForegroundColor Yellow
    exit 1
}

function Assert-Consent {
    param([string]$Actual, [string]$Expected, [string]$NeedsPrompt, [string]$Step, [string]$Policy = "unrestricted")

    try {
        $parsed = $Actual | ConvertFrom-Json
    } catch {
        Write-Host "FAILED: $Step emitted output that is not valid JSON: '$Actual'" -ForegroundColor Red
        exit 1
    }

    $expectedPrompt = [bool]::Parse($NeedsPrompt)
    $failures = @()
    if ($parsed.consent -ne $Expected) { $failures += "consent: expected '$Expected', got '$($parsed.consent)'" }
    if ($parsed.needsPrompt -ne $expectedPrompt) { $failures += "needsPrompt: expected '$expectedPrompt', got '$($parsed.needsPrompt)'" }
    if ($parsed.policy -ne $Policy) { $failures += "policy: expected '$Policy', got '$($parsed.policy)'" }

    if ($failures.Count -gt 0) {
        Write-Host "FAILED: $Step" -ForegroundColor Red
        foreach ($failure in $failures) { Write-Host "  $failure" -ForegroundColor Red }
        Write-Host "  raw output: '$Actual'" -ForegroundColor Red
        exit 1
    }

    Write-Host "  OK: $Step -> $Actual" -ForegroundColor DarkGray
}

# Redirect the consent store to an isolated temp directory for the duration
# of this script so it never reads or writes the real per-user consent file.
# This is the same debug-only override the Rust and C# tests use; production
# code path resolves the known folder directly and ignores LOCALAPPDATA.
$OverrideEnvVar = "MXC_TEST_LOCALAPPDATA_OVERRIDE"
$OriginalOverride = [Environment]::GetEnvironmentVariable($OverrideEnvVar)
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "mxc_telemetry_consent_smoke_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $TempDir | Out-Null
Set-Item -Path "Env:$OverrideEnvVar" -Value $TempDir

# Likewise redirect the administrative policy read to a throwaway HKCU key, so
# the assertions below hold on a machine that genuinely has the MXC telemetry
# policy configured, and so this script can exercise the policy path without
# needing elevation. Also debug-build-only.
$PolicyEnvVar = "MXC_TEST_POLICY_KEY_OVERRIDE"
$OriginalPolicyOverride = [Environment]::GetEnvironmentVariable($PolicyEnvVar)
$PolicySubkey = "Software\MxcTelemetryPolicySmoke\$([guid]::NewGuid().ToString('N'))"
$PolicyPath = "HKCU:\$PolicySubkey"
New-Item -Path $PolicyPath -Force | Out-Null
Set-Item -Path "Env:$PolicyEnvVar" -Value $PolicySubkey

$ConsentFile = Join-Path $TempDir "mxc\telemetry-consent.json"

try {
    Write-Host "Running telemetry consent CLI smoke test..." -ForegroundColor Cyan

    # Prove the store override is actually honored *before* issuing any command
    # that writes. A release build compiles $OverrideEnvVar out, and every write
    # below would then land in the developer's real per-user consent store and
    # silently overwrite their genuine decision.
    #
    # The proof is read-only: seed two different records directly and require
    # the CLI to report each one back. A binary ignoring the override reads a
    # single fixed store, so it cannot match both.
    New-Item -ItemType Directory -Path (Split-Path -Parent $ConsentFile) -Force | Out-Null
    foreach ($seeded in @("granted", "denied")) {
        $record = [pscustomobject]@{
            schemaVersion      = 1
            consent            = $seeded
            source             = "smoke-test-seed"
            promptedMxcVersion = "0.0.0-smoke"
            updatedAtEpoch     = 0
        }
        # Must be BOM-free: Windows PowerShell's `-Encoding UTF8` emits a BOM,
        # which the JSON parser rejects, making a correctly isolated store look
        # unreadable.
        [System.IO.File]::WriteAllText(
            $ConsentFile,
            ($record | ConvertTo-Json),
            (New-Object System.Text.UTF8Encoding $false))

        $probe = & $WxcExec --telemetry-consent-status
        if (($probe | ConvertFrom-Json).consent -ne $seeded) {
            Write-Host "FAILED: consent store is NOT isolated - seeded '$seeded' at $ConsentFile" -ForegroundColor Red
            Write-Host "        but the CLI reported '$(($probe | ConvertFrom-Json).consent)'." -ForegroundColor Red
            Write-Host "        The wxc-exec.exe under test is most likely a release build, which compiles out" -ForegroundColor Yellow
            Write-Host "        $OverrideEnvVar. Rebuild with 'cargo build -p wxc' (debug) and re-run." -ForegroundColor Yellow
            Write-Host "        Refusing to continue: the remaining steps would write to your real consent store." -ForegroundColor Yellow
            exit 1
        }
    }
    Remove-Item -Path $ConsentFile -Force
    Write-Host "  OK: consent store is isolated at $ConsentFile" -ForegroundColor DarkGray

    $status0 = & $WxcExec --telemetry-consent-status
    Assert-Consent $status0 "undetermined" "true" "fresh store status"

    $grant = & $WxcExec --telemetry-consent-grant --telemetry-consent-source prompt
    Assert-Consent $grant "granted" "false" "grant"

    if (-not (Test-Path $ConsentFile)) {
        Write-Host "FAILED: grant did not persist a record to $ConsentFile." -ForegroundColor Red
        exit 1
    }
    Write-Host "  OK: consent file persisted under the isolated store at $ConsentFile" -ForegroundColor DarkGray

    $status1 = & $WxcExec --telemetry-consent-status
    Assert-Consent $status1 "granted" "false" "status after grant"

    $revoke = & $WxcExec --telemetry-consent-revoke --telemetry-consent-source settings-toggle
    Assert-Consent $revoke "denied" "false" "revoke"

    $status2 = & $WxcExec --telemetry-consent-status
    Assert-Consent $status2 "denied" "false" "status after revoke"

    & $WxcExec --telemetry-consent-grant --telemetry-consent-revoke | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "FAILED: --telemetry-consent-grant + --telemetry-consent-revoke should be rejected as mutually exclusive" -ForegroundColor Red
        exit 1
    }
    Write-Host "  OK: grant+revoke rejected as mutually exclusive (exit $LASTEXITCODE)" -ForegroundColor DarkGray

    # Administrative (MDM / Group Policy) ceiling. Only the value 3 (Optional)
    # permits the product-and-service-usage data MXC emits; everything else,
    # including an unrecognised value, must fail closed.
    & $WxcExec --telemetry-consent-grant --telemetry-consent-source cli | Out-Null

    foreach ($blocking in @(0, 1, 42)) {
        Set-ItemProperty -Path $PolicyPath -Name "AllowTelemetry" -Value $blocking -Type DWord
        $blocked = & $WxcExec --telemetry-consent-status
        # The user's own grant is preserved verbatim; only the ceiling changes,
        # and the prompt is suppressed so no host asks a moot question.
        Assert-Consent $blocked "granted" "false" "policy AllowTelemetry=$blocking blocks" "blocked"
    }

    Set-ItemProperty -Path $PolicyPath -Name "AllowTelemetry" -Value 3 -Type DWord
    $allowed = & $WxcExec --telemetry-consent-status
    Assert-Consent $allowed "granted" "false" "policy AllowTelemetry=3 allows" "allowed"

    # A value of the wrong registry type is unreadable, not absent. It must fail
    # closed rather than degrade to "no policy configured" and re-enable
    # collection an administrator was trying to turn off.
    Remove-ItemProperty -Path $PolicyPath -Name "AllowTelemetry"
    Set-ItemProperty -Path $PolicyPath -Name "AllowTelemetry" -Value "3" -Type String
    $wrongType = & $WxcExec --telemetry-consent-status
    Assert-Consent $wrongType "granted" "false" "REG_SZ AllowTelemetry blocks" "blocked"

    Remove-ItemProperty -Path $PolicyPath -Name "AllowTelemetry"
    $unmanaged = & $WxcExec --telemetry-consent-status
    Assert-Consent $unmanaged "granted" "false" "policy removed is unrestricted"

    # A blocking policy must also suppress the first-run prompt for a user who
    # has *not* decided yet, not just for one who already has.
    & $WxcExec --telemetry-consent-status | Out-Null
    Remove-Item -Path $ConsentFile -Force
    Set-ItemProperty -Path $PolicyPath -Name "AllowTelemetry" -Value 0 -Type DWord
    $blockedFresh = & $WxcExec --telemetry-consent-status
    Assert-Consent $blockedFresh "undetermined" "false" "blocked policy suppresses the first-run prompt" "blocked"

    Write-Host "PASSED: telemetry consent CLI smoke test" -ForegroundColor Green
} finally {
    Set-Item -Path "Env:$OverrideEnvVar" -Value $OriginalOverride
    Set-Item -Path "Env:$PolicyEnvVar" -Value $OriginalPolicyOverride
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $PolicyPath -ErrorAction SilentlyContinue
}

