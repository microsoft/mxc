# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Pre-pull WSLC container images into the local cache.

.DESCRIPTION
    MXC is an execution layer and does not pull container images at run time.
    Instead, operators populate the WSLC SDK image cache out of band — this
    script is the canonical entry point. Each image is pulled via
    `wxc-exec.exe --setup-wslc --image <name>`, which opens a minimal WSLC
    session against the configured `storage_path` and invokes
    `WslcPullSessionImage`. The pulled images persist in that storage path
    and become visible to subsequent runtime executions.

    The storage path you pass here MUST match the value used at run time
    (the `experimental.wslc.storagePath` field of the config, or the
    runner's default of `%TEMP%\mxc-wslc-sessions` when omitted).

.PARAMETER Image
    One or more image references to pre-pull. Defaults to a small
    starter set (alpine:latest, python:3.12-alpine) suitable for a quick
    smoke test. To populate the cache for the full WSLC test suite, run
    tests\scripts\run_wslc_all_tests.ps1, which invokes this script with
    the complete image list.

.PARAMETER WxcExecPath
    Explicit path to wxc-exec.exe. When omitted, the script probes the
    standard cargo target directories.

.PARAMETER StoragePath
    WSLC storage path to populate. When omitted, the runner default
    (`%TEMP%\mxc-wslc-sessions`) is used. Set this if your runtime configs
    override `experimental.wslc.storagePath`.

.PARAMETER DebugLogs
    Enable verbose logging from wxc-exec (passes `--debug`).

.PARAMETER Force
    Continue pulling subsequent images even if one fails.

.EXAMPLE
    .\setup-wslc.ps1
    Pulls the default image set (alpine:latest, python:3.12-alpine).

.EXAMPLE
    .\setup-wslc.ps1 -Image alpine:latest, ghcr.io/owner/image:tag
    Pulls specific images.

.EXAMPLE
    .\setup-wslc.ps1 -StoragePath C:\wslc-cache
    Pulls into a non-default cache directory.
#>

[CmdletBinding()]
param(
    [string[]]$Image = @("alpine:latest", "python:3.12-alpine"),
    [string]$WxcExecPath,
    [string]$StoragePath,
    [switch]$DebugLogs,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

# Discover wxc-exec.exe -- prefer explicit path, then probe target dirs.
$Target = "x86_64-pc-windows-msvc"
if ($WxcExecPath) {
    $WxcExec = $WxcExecPath
} else {
    $CandidatePaths = @(
        (Join-Path $RepoRoot "src\target\$Target\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$Target\debug\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\debug\wxc-exec.exe")
    )
    $WxcExec = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found." -ForegroundColor Red
    Write-Host "Build with: cargo build --release --features wslc --target $Target" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExecPath explicitly." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nWSLC image setup" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
Write-Host "Binary       : $WxcExec" -ForegroundColor Gray
if ($StoragePath) {
    Write-Host "Storage path : $StoragePath" -ForegroundColor Gray
} else {
    Write-Host "Storage path : (default) %TEMP%\mxc-wslc-sessions" -ForegroundColor Gray
}
Write-Host "Images       : $($Image -join ', ')`n" -ForegroundColor Gray

$failed = @()
foreach ($img in $Image) {
    Write-Host "  $img ... " -NoNewline
    $wxcArgs = @("--setup-wslc", "--image", $img)
    if ($StoragePath) {
        $wxcArgs += @("--storage-path", $StoragePath)
    }
    if ($DebugLogs) {
        $wxcArgs += "--debug"
    }

    $prevPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $WxcExec @wxcArgs 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevPref

    if ($exitCode -eq 0) {
        Write-Host "OK" -ForegroundColor Green
    } else {
        Write-Host "FAIL (exit $exitCode)" -ForegroundColor Red
        $output -split "`n" | Where-Object { $_.Trim() -ne "" } | ForEach-Object {
            Write-Host "    > $($_.TrimEnd())" -ForegroundColor Gray
        }
        $failed += $img
        if (-not $Force) {
            break
        }
    }
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "All images pulled successfully." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Failed images: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
