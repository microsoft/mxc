# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# WSLC most-specific-path-wins test (denied parent, read-write child).
#
# The Linux LXC/Bubblewrap backends realise most-specific-wins via ordered bind
# mounts. WSLC reaches the SAME observable outcome by a different mechanism: it
# mounts each read-write path as its own volume and leaves denied paths
# unmounted (see policy_mapping.rs `build_volume_mounts`). Mounting the specific
# read-write child (`data\secret_child`) while denying its parent (`data`) means
# the child is present and writable inside the container, while a sibling under
# the (unmounted) denied parent is invisible.
#
# This script owns the on-disk fixture so the config is never run without it.
#
# Usage:
#   .\run_wslc_most_specific_test.ps1                       # auto-discovers wxc-exec.exe
#   .\run_wslc_most_specific_test.ps1 -WxcExecPath <path>   # explicit binary
#   .\run_wslc_most_specific_test.ps1 -Debug                # debug build + --debug

param(
    [switch]$Debug,
    [string]$WxcExecPath
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ConfigPath = Join-Path $RepoRoot "tests\configs\wslc_most_specific_denied_parent.json"

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

# Fixed paths must match tests\configs\wslc_most_specific_denied_parent.json.
$Base = "C:\wslcmsp"
$DataDir = Join-Path $Base "data"
$ChildDir = Join-Path $DataDir "secret_child"

function Remove-Fixture {
    Remove-Item -Recurse -Force $Base -ErrorAction SilentlyContinue
}

Remove-Fixture
try {
    # Read-write child (mounted) with a keeper secret, plus a sibling secret
    # under the denied parent (left unmounted, must be masked).
    New-Item -ItemType Directory -Path $ChildDir -Force | Out-Null
    Set-Content (Join-Path $ChildDir "keep.txt") "CHILD_KEPT"
    Set-Content (Join-Path $DataDir "sibling.txt") "PARENT_SECRET"

    Write-Host "Running WSLC most-specific test (denied parent, rw child)..."
    $wxcArgs = @("--experimental")
    if ($Debug) { $wxcArgs += "--debug" }
    $wxcArgs += $ConfigPath

    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $WxcExec @wxcArgs 2>&1 | Out-String
    $ErrorActionPreference = $prev
    Write-Host $output

    if (($output -match "CHILD_OK") -and ($output -match "CHILD_WRITE_OK") `
            -and ($output -match "PARENT_MASKED_OK") `
            -and ($output -notmatch "CHILD_MISSING") -and ($output -notmatch "CHILD_WRITE_FAIL") `
            -and ($output -notmatch "PARENT_LEAK")) {
        Write-Host "PASS: rw child mounted and writable; denied parent sibling masked." -ForegroundColor Green
        $exit = 0
    } else {
        Write-Host "FAIL: most-specific rw child did not win over denied parent." -ForegroundColor Red
        $exit = 1
    }
} finally {
    Remove-Fixture
}

Write-Host "WSLC most-specific-path-wins test complete."
exit $exit
