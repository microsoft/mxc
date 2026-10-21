# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Pre-pull WSLC container images into the local cache.

.DESCRIPTION
    Warms the WSLC SDK image cache ahead of time. A run pulls on a cache miss
    by itself, so this is an optimisation rather than a prerequisite — it moves
    the download off the critical path of a later run, and it is how you
    populate a cache for a host that cannot reach a registry. All images are
    pulled via a single `wxc-exec.exe --setup-wslc --image <name> ...`
    invocation per store, which opens one WSLC session against that store and
    invokes `WslcPullSessionImage` for each image. The pulled images persist in
    that storage path and become visible to subsequent runtime executions.

    The storage path you pass here MUST match the value used at run time
    (the `wslc.storagePath` field of the config, or the
    runner's default of `%TEMP%\mxc-wslc-sessions` when omitted).

    Container lifecycle operations do not read that store. The lifecycle
    daemon leases its store from a pool under
    %LOCALAPPDATA%\mxc\wslc-store-slots, so -DaemonSlots warms those slots
    separately.

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
    override `wslc.storagePath`. This reaches create-and-run execution only;
    use -DaemonSlots for the container-lifecycle store.
.PARAMETER DaemonSlots
    How many container-lifecycle store slots to warm as well, from slot 0 up.
    The lifecycle daemon leases its store from a separate pool under
    %LOCALAPPDATA%\mxc\wslc-store-slots, which -StoragePath does not reach, and
    a slot that has never been leased holds no images. Defaults to 0, matching
    `wxc-exec.exe --wslc-daemon-slots`, so warming a create-and-run cache stays
    one pull per image. Pass 1 before running container lifecycle operations
    against an isolated posture, and one slot per session you expect to run at
    once beyond that — a session that leases a cold slot cannot resolve an
    uncached image under that posture. Each slot costs another pull and another
    multi-GiB store.

.PARAMETER DebugLogs
    Enable verbose logging from wxc-exec (passes `--debug`).

.PARAMETER Force
    Retained for compatibility. Every image is now pulled in one `wxc-exec`
    invocation per store, which always attempts them all and reports each
    failure, so there is no longer a run to continue past.

.EXAMPLE
    .\setup-wslc.ps1
    Pulls the default image set (alpine:latest, python:3.12-alpine).

.EXAMPLE
    .\setup-wslc.ps1 -Image alpine:latest, ghcr.io/owner/image:tag
    Pulls specific images.

.EXAMPLE
    .\setup-wslc.ps1 -StoragePath C:\wslc-cache
    Pulls into a non-default cache directory.

.EXAMPLE
    .\setup-wslc.ps1 -DaemonSlots 1
    Also warms the store slot the container-lifecycle daemon leases.
#>

[CmdletBinding()]
param(
    [string[]]$Image = @("alpine:latest", "python:3.12-alpine"),
    [string]$WxcExecPath,
    [string]$StoragePath,
    [ValidateRange(0, 64)]
    [int]$DaemonSlots = 0,
    [switch]$DebugLogs,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

# Discover wxc-exec.exe -- prefer explicit path, then probe target dirs.
$Target = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    'aarch64-pc-windows-msvc'
} else {
    'x86_64-pc-windows-msvc'
}
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
if ($DaemonSlots -gt 0) {
    Write-Host "Daemon slots : $DaemonSlots (%LOCALAPPDATA%\mxc\wslc-store-slots)" -ForegroundColor Gray
} else {
    Write-Host "Daemon slots : none" -ForegroundColor Gray
}
Write-Host "Images       : $($Image -join ', ')`n" -ForegroundColor Gray

$failed = @()
Write-Host "  pulling $($Image.Count) image(s) ... " -NoNewline

$wxcArgs = @("--setup-wslc")
foreach ($img in $Image) {
    $wxcArgs += @("--image", $img)
}
if ($StoragePath) {
    $wxcArgs += @("--storage-path", $StoragePath)
}
if ($DaemonSlots -gt 0) {
    $wxcArgs += @("--wslc-daemon-slots", "$DaemonSlots")
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
    $failed += $Image
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "All images pulled successfully." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Failed images: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
