# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Runs BaseContainer denied-path tests using portable C:\Users\Public fixtures.
# Missing denied targets are created by the contained commands. The existing
# target case is host-seeded because its denied file must exist before launch.

param(
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$WxcExec = if ($BinDir) {
    Join-Path $BinDir "wxc-exec.exe"
} else {
    $profile = if ($Release) { "release" } else { "debug" }
    Join-Path $RepoRoot "src\target\$profile\wxc-exec.exe"
}

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

$ExistingRoot = "C:\Users\Public\mxc_git_denied_existing"
$CleanupRoots = @(
    "C:\Users\Public\mxc_git_denied_missing",
    "C:\Users\Public\mxc_git_denied_case",
    $ExistingRoot
)

$Tests = @(
    @{
        Name = "missing denied child"
        Config = "processcontainer_git_denied_missing.json"
        Marker = "OK:git_create_denied"
    },
    @{
        Name = "case-insensitive denied child"
        Config = "processcontainer_git_denied_casevariation.json"
        Marker = "OK:GiT_create_denied"
    },
    @{
        Name = "existing denied child"
        Config = "processcontainer_git_denied_existing.json"
        Marker = "OK:config_write_denied"
    }
)

try {
    foreach ($root in $CleanupRoots) {
        if (Test-Path $root) {
            Remove-Item -Recurse -Force $root
        }
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }

    New-Item -ItemType Directory -Path (Join-Path $ExistingRoot ".git") -Force | Out-Null
    Set-Content -Path (Join-Path $ExistingRoot ".git\config") -Value "ORIGINAL"

    $probeConfig = Join-Path $RepoRoot "tests\configs\processcontainer_git_denied_missing.json"
    $probe = & $WxcExec --probe --config $probeConfig 2>$null | ConvertFrom-Json
    if ($probe.tier -ne "base-container") {
        Write-Host "SKIPPED: BaseContainer is not selected on this host (tier: $($probe.tier))" -ForegroundColor Yellow
        exit 0
    }
    if (-not $probe.probes.baseContainerSupportsDenyPaths) {
        Write-Host "SKIPPED: BaseContainer denied paths are not supported on this host" -ForegroundColor Yellow
        exit 0
    }

    foreach ($test in $Tests) {
        $config = Join-Path $RepoRoot "tests\configs\$($test.Config)"
        Write-Host "Running $($test.Name)..." -ForegroundColor Cyan
        $output = & $WxcExec --debug $config 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        Write-Host $output

        if ($exitCode -ne 0) {
            Write-Host "FAILED: $($test.Name) exited with code $exitCode" -ForegroundColor Red
            exit $exitCode
        }
        if ($output -notmatch "(?im)selected isolation tier:\s*base-container") {
            Write-Host "FAILED: $($test.Name) did not run on BaseContainer" -ForegroundColor Red
            exit 1
        }
        if ($output -notmatch [regex]::Escape($test.Marker)) {
            Write-Host "FAILED: expected marker '$($test.Marker)'" -ForegroundColor Red
            exit 1
        }

        Write-Host "PASSED: $($test.Name)" -ForegroundColor Green
    }

    Write-Host "PASSED: all BaseContainer denied-path tests" -ForegroundColor Green
} finally {
    foreach ($root in $CleanupRoots) {
        if (Test-Path $root) {
            Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
        }
    }
}
