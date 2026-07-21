# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# WSLC denied-path masking test.
#
# WSLC masks a denied path by simply NOT mounting it (see policy_mapping.rs:
# `build_volume_mounts` maps only readwrite/readonly paths; denied paths are
# omitted, and `normalize_object_conflicts` tightens same-object aliases to
# deny). Unlike the Linux LXC/Bubblewrap backends, WSLC does not carve a denied
# child out of a mounted parent, so this test uses the sibling model: a
# read-write subdir (`visible`) is mounted as a positive control, while a denied
# sibling file and a denied sibling directory are left unmounted and must be
# invisible inside the container.
#
# This script owns the on-disk fixture so the config is never run without it
# (running the config alone would pass for the wrong reason -- the paths simply
# would not exist).
#
# Usage:
#   .\run_wslc_denied_masking_test.ps1                       # auto-discovers wxc-exec.exe
#   .\run_wslc_denied_masking_test.ps1 -WxcExecPath <path>   # explicit binary
#   .\run_wslc_denied_masking_test.ps1 -Debug                # debug build + --debug

param(
    [switch]$Debug,
    [string]$WxcExecPath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ConfigPath = Join-Path $RepoRoot "tests\configs\wslc_denied_masking.json"

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

# Fixed paths must match tests\configs\wslc_denied_masking.json.
$Base = "C:\wslcmask"
$VisibleDir = Join-Path $Base "visible"
$SecretFile = Join-Path $Base "secret_file.txt"
$SecretDir = Join-Path $Base "secret_dir"

function Remove-Fixture {
    Remove-Item -Recurse -Force $Base -ErrorAction SilentlyContinue
}

Remove-Fixture
try {
    # Positive control (mounted read-write), plus a denied sibling file and a
    # denied sibling directory, each holding secret content readable on the host.
    New-Item -ItemType Directory -Path $VisibleDir -Force | Out-Null
    New-Item -ItemType Directory -Path $SecretDir -Force | Out-Null
    Set-Content (Join-Path $VisibleDir "control.txt") "VISIBLE_SECRET"
    Set-Content $SecretFile "FILE_SECRET"
    Set-Content (Join-Path $SecretDir "inner.txt") "DIR_SECRET"

    Write-Host "Running WSLC denied-path masking test (denied sibling file + dir left unmounted)..."
    $wxcArgs = @("--experimental")
    if ($Debug) { $wxcArgs += "--debug" }
    $wxcArgs += $ConfigPath

    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $WxcExec @wxcArgs 2>&1 | Out-String
    $ErrorActionPreference = $prev
    Write-Host $output

    $fail = 0

    # Positive control: the mounted sibling must be readable, proving the mount
    # is present (so masking below is attributable to the deny, not absence).
    if (($output -match "VISIBLE_OK") -and ($output -notmatch "VISIBLE_MISSING")) {
        Write-Host "PASS: non-denied sibling readable (mount present)." -ForegroundColor Green
    } else {
        Write-Host "FAIL: non-denied sibling not readable - mount missing, test inconclusive." -ForegroundColor Red
        $fail = 1
    }

    if (($output -match "FILE_MASKED_OK") -and ($output -notmatch "FILE_LEAK")) {
        Write-Host "PASS: denied file not mounted (masked)." -ForegroundColor Green
    } else {
        Write-Host "FAIL: denied file content leaked." -ForegroundColor Red
        $fail = 1
    }

    if (($output -match "DIR_MASKED_OK") -and ($output -notmatch "DIR_LEAK")) {
        Write-Host "PASS: denied directory not mounted (masked)." -ForegroundColor Green
    } else {
        Write-Host "FAIL: denied directory content leaked." -ForegroundColor Red
        $fail = 1
    }

    if ($fail -ne 0) { $exit = 1 } else { $exit = 0 }
} finally {
    Remove-Fixture
}

Write-Host "WSLC denied-path masking test complete."
exit $exit
