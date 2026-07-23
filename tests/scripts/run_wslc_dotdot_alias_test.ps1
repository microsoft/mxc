# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# WSLC denied-path `..`-through-junction pre-flight validation test (comment 1).
#
# Guards the Tier-2 canonicalization fix for `canonicalize_allowing_absent_tail`:
# a deniedPaths entry that reaches inside a mounted tree only AFTER (a) following
# a junction and (b) folding `..` across several not-yet-created components must
# still be rejected by the pre-flight overlap check. The absent components force
# the `..` into the tail-replay path (the exact spot the old `file_name()`-based
# reconstruction dropped it), so this exercises the fixed push/pop folding
# end-to-end through wxc-exec.
#
# Fixture (owned here so the config is never run without its on-disk aliasing):
#   C:\ddttest\real            real directory, mounted readwrite
#   C:\ddttest\link -> real    junction; deny is spelled through it
# Denied `C:\ddttest\link\ghost\sub\..\secret` resolves to `C:\ddttest\real\ghost\secret`,
# which is nested under the mounted `C:\ddttest\real`, so validation must FAIL
# (exit -1) with the "cannot be enforced" overlap error BEFORE any container run.
#
# Usage:
#   .\run_wslc_dotdot_alias_test.ps1                       # auto-discovers wxc-exec.exe
#   .\run_wslc_dotdot_alias_test.ps1 -WxcExecPath <path>   # explicit binary
#   .\run_wslc_dotdot_alias_test.ps1 -Debug                # debug build + --debug

param(
    [switch]$Debug,
    [string]$WxcExecPath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ConfigPath = Join-Path $RepoRoot "tests\configs\wslc_denied_dotdot_alias.json"

# Resolve the binary: explicit path, then target-specific and default dirs.
$Target = "x86_64-pc-windows-msvc"
$Profile = if ($Debug) { "debug" } else { "release" }
if ($WxcExecPath) {
    $WxcExec = $WxcExecPath
} else {
    $Candidates = @(
        (Join-Path $RepoRoot "src\target\$Target\$Profile\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$Profile\wxc-exec.exe")
    )
    $WxcExec = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found. Build with: cargo build --features wslc --release --target $Target" -ForegroundColor Red
    exit 1
}

# Fixed paths must match tests\configs\wslc_denied_dotdot_alias.json.
$Base = "C:\ddttest"
$RealDir = Join-Path $Base "real"
$LinkDir = Join-Path $Base "link"

function Remove-Fixture {
    Remove-Item -Recurse -Force $Base -ErrorAction SilentlyContinue
}

Remove-Fixture
try {
    # Real directory (the mount) plus a junction alias. `ghost`, `sub` and
    # `secret` are deliberately NOT created so the `..` lands in the tail replay.
    # mklink /J does NOT require administrator.
    New-Item -ItemType Directory -Path $RealDir -Force | Out-Null
    $null = cmd /c mklink /J "$LinkDir" "$RealDir"
    if (-not (Test-Path $LinkDir)) {
        Write-Host "FAIL: fixture setup -- junction not created at $LinkDir" -ForegroundColor Red
        exit 1
    }

    Write-Host "Running WSLC denied `..`-through-junction test (expect pre-flight rejection)..."
    $wxcArgs = @("--experimental")
    if ($Debug) { $wxcArgs += "--debug" }
    $wxcArgs += $ConfigPath

    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $WxcExec @wxcArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $prev
    Write-Host $output

    # The container must never start; validation must reject the config with the
    # overlap error and must not print the process output.
    if (($output -match "cannot be enforced") -and ($output -notmatch "SHOULD_NOT_RUN")) {
        Write-Host "PASS: `..`-through-junction deny rejected at pre-flight (tail replay folded `..` into the mount)." -ForegroundColor Green
        $exit = 0
    } else {
        Write-Host "FAIL: `..`-through-junction deny was NOT rejected (exit $exitCode)." -ForegroundColor Red
        $exit = 1
    }
} finally {
    Remove-Fixture
}

Write-Host "WSLC denied `..`-through-junction validation test complete."
exit $exit
