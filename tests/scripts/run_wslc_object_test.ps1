# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# WSLC object-based filesystem-policy validation test (roadmap D6).
#
# When two different policy paths resolve to the SAME host object (a directory
# and a Windows junction to it) but carry conflicting intents, the runner
# tightens every alias to the most-restrictive intent (deny > ro > rw) BEFORE
# mapping volume mounts. WSLC masks a denied path by simply NOT mounting it
# (see policy_mapping.rs), so the directory -- though listed under
# readwritePaths -- is not mounted and its secret is invisible in the container.
#
# This script owns the fixture (directory + junction) so the config is never
# run without its on-disk aliasing -- running the config alone would otherwise
# pass for the wrong reason (the path simply wouldn't exist).
#
# Usage:
#   .\run_wslc_object_test.ps1                       # auto-discovers wxc-exec.exe
#   .\run_wslc_object_test.ps1 -WxcExecPath <path>   # explicit binary
#   .\run_wslc_object_test.ps1 -Debug                # debug build + --debug

param(
    [switch]$Debug,
    [string]$WxcExecPath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ConfigPath = Join-Path $RepoRoot "tests\configs\wslc_filesystem_object.json"

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

# Fixed path must match tests\configs\wslc_filesystem_object.json.
$ObjBase = "C:\objtest"
$DataDir = Join-Path $ObjBase "data"
$LinkDir = Join-Path $ObjBase "data_link"

function Remove-Fixture {
    Remove-Item -Recurse -Force $ObjBase -ErrorAction SilentlyContinue
}

Remove-Fixture
try {
    # Real directory with a secret, plus a junction alias pointing at the same
    # directory object. mklink /J does NOT require administrator.
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Set-Content (Join-Path $DataDir "secret.txt") "OBJECT_SECRET"
    $null = cmd /c mklink /J "$LinkDir" "$DataDir"
    if (-not (Test-Path $LinkDir)) {
        Write-Host "FAIL: fixture setup -- junction not created at $LinkDir" -ForegroundColor Red
        exit 1
    }

    Write-Host "Running WSLC object-validation test (RW + denied junction alias, expect masked)..."
    $wxcArgs = @("--experimental")
    if ($Debug) { $wxcArgs += "--debug" }
    $wxcArgs += $ConfigPath

    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $WxcExec @wxcArgs 2>&1 | Out-String
    $ErrorActionPreference = $prev
    Write-Host $output

    if (($output -match "OBJECT_MASKED_OK") -and ($output -notmatch "OBJECT_LEAK")) {
        Write-Host "PASS: denied junction alias tightened the read-write path; object masked (bypass closed)." -ForegroundColor Green
        $exit = 0
    } else {
        Write-Host "FAIL: object reachable via read-write alias of a denied path (bypass NOT closed)." -ForegroundColor Red
        $exit = 1
    }
} finally {
    Remove-Fixture
}

Write-Host "WSLC object-based validation test complete."
exit $exit
