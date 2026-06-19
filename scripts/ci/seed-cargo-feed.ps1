# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Seed the public MxcDependencies cargo feed with every crates.io package
    pinned in src/Cargo.lock.

.DESCRIPTION
    The fork/PR ("Unofficial") ADO build redirects crates.io to the public,
    anonymous-read MxcDependencies feed (see .azure-pipelines/.cargo/config.public.toml).
    That feed is an upstream-caching proxy: anonymous clients can only READ
    crate versions that have already been saved to the feed — pulling a new
    version from the crates.io upstream requires authentication, otherwise the
    feed returns HTTP 401.

    A crate version is persisted into the feed only when its `.crate` FILE is
    downloaded by an authenticated client (reading the sparse index alone is
    not enough). This script walks src/Cargo.lock and authenticated-downloads
    every crates.io `.crate` file, which permanently saves each version so the
    anonymous CI lane never 401s on a not-yet-cached crate.

    Why this is needed: fork PRs lose System.AccessToken and therefore only run
    the GitHub Actions gates, which build against real crates.io. They never
    exercise the network-isolated feed, so a fork-PR lockfile bump can merge a
    brand-new transitive crate that was never cached in the public feed — and
    the next in-repo PR or `main` push then fails `cargo fetch` with a 401.

    Authenticated downloads of already-persisted crates simply return the cached
    file, so this script is idempotent and safe to re-run.

.PARAMETER LockFile
    Path to Cargo.lock. Defaults to src/Cargo.lock relative to this script.

.PARAMETER ConfigToml
    Path to the cargo config that declares the public feed's sparse index.
    The index URL is read from here so there is a single source of truth.
    Defaults to .azure-pipelines/.cargo/config.public.toml.

.PARAMETER IndexUrl
    Override for the sparse-index URL. When omitted it is parsed from ConfigToml.

.PARAMETER Pat
    A Personal Access Token with Packaging (Read) scope on the Azure DevOps
    org that backs the public feed. Defaults to the CARGO_FEED_PAT environment
    variable so the token never has to appear on the command line.

.PARAMETER ThrottleLimit
    Maximum number of concurrent downloads. Defaults to 12.

.EXAMPLE
    $env:CARGO_FEED_PAT = '<pat>'
    pwsh ./scripts/ci/seed-cargo-feed.ps1
#>
[CmdletBinding()]
param(
    [string]$LockFile = (Join-Path $PSScriptRoot '..\..\src\Cargo.lock'),
    [string]$ConfigToml = (Join-Path $PSScriptRoot '..\..\.azure-pipelines\.cargo\config.public.toml'),
    [string]$IndexUrl,
    [string]$Pat = $env:CARGO_FEED_PAT,
    [int]$ThrottleLimit = 12
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Pat)) {
    Write-Host '##[error]No PAT supplied. Set the CARGO_FEED_PAT environment variable or pass -Pat.'
    exit 1
}

# Azure DevOps accepts a PAT as the password of HTTP Basic auth (any username).
$auth = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("pat:$Pat"))

# Resolve the sparse-index URL from config.public.toml unless one was passed.
if ([string]::IsNullOrWhiteSpace($IndexUrl)) {
    $tomlText = Get-Content -Raw -LiteralPath $ConfigToml
    if ($tomlText -match 'index\s*=\s*"sparse\+([^"]+)"') {
        $IndexUrl = $Matches[1]
    } else {
        Write-Host "##[error]Could not find a sparse index URL in $ConfigToml"
        exit 1
    }
}
$IndexUrl = $IndexUrl.TrimEnd('/')
Write-Host "Public feed index: $IndexUrl"

# The crate-download URL template lives in the feed's sparse-index config.json
# (the `dl` field), e.g. https://.../cargo/api/v1/crates/{crate}/{version}/download.
# Reading it (rather than hardcoding org GUIDs) keeps the script robust to feed
# re-provisioning.
$config = Invoke-RestMethod -Uri "$IndexUrl/config.json" -Headers @{ Authorization = $auth }
$dlTemplate = $config.dl
if ([string]::IsNullOrWhiteSpace($dlTemplate)) {
    Write-Host "##[error]Feed config.json did not return a 'dl' download template."
    exit 1
}

# Parse Cargo.lock for crates.io packages (skip workspace/git/path members).
$pkgs = [System.Collections.Generic.List[object]]::new()
$name = $null; $ver = $null; $src = $null
foreach ($line in Get-Content -LiteralPath $LockFile) {
    if ($line -eq '[[package]]') {
        if ($name -and $src -like 'registry+*crates.io-index') {
            $pkgs.Add([pscustomobject]@{ name = $name; version = $ver })
        }
        $name = $null; $ver = $null; $src = $null
        continue
    }
    if ($line -match '^name = "(.+)"$') { $name = $Matches[1] }
    elseif ($line -match '^version = "(.+)"$') { $ver = $Matches[1] }
    elseif ($line -match '^source = "(.+)"$') { $src = $Matches[1] }
}
if ($name -and $src -like 'registry+*crates.io-index') {
    $pkgs.Add([pscustomobject]@{ name = $name; version = $ver })
}

Write-Host "##[section]Seeding $($pkgs.Count) crates.io packages from $LockFile"

# Download each `.crate` file authenticated. The download is what persists the
# version into the feed; already-persisted crates just return the cache.
$failures = $pkgs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $ProgressPreference = 'SilentlyContinue'
    $pkg = $_
    $url = $using:dlTemplate
    $url = $url.Replace('{crate}', $pkg.name).Replace('{version}', $pkg.version)
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $url -Headers @{ Authorization = $using:auth } `
            -UseBasicParsing -OutFile $tmp -ErrorAction Stop | Out-Null
        $null
    } catch {
        "$($pkg.name) $($pkg.version) :: $($_.Exception.Message)"
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
}

$failures = @($failures | Where-Object { $_ })
if ($failures.Count -gt 0) {
    Write-Host "##[error]Failed to seed $($failures.Count) crate(s):"
    $failures | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "Successfully seeded all $($pkgs.Count) crates into the public feed."
