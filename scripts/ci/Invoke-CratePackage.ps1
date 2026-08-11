# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Packages the crates.io release closure into .crate files and copies them
# where the artifact task expects them.
#
# Called by Package.Crates.Job.yml.  Runnable by hand from the repo root to
# reproduce exactly what the packaging leg does:
#
#   pwsh scripts/ci/Invoke-CratePackage.ps1 -OutDir out/crates

[CmdletBinding()]
param
(
    [Parameter(Mandatory)]
    [string] $OutDir,

    # The feed that replaced crates-io on this agent.  Omit to package against
    # whatever the ambient cargo config resolves, which is what a local run
    # without source replacement wants.
    [string] $Registry,

    [string] $ManifestPath = 'src/Cargo.toml'
)

$ErrorActionPreference = 'Stop'

$crates = & (Join-Path $PSScriptRoot 'Get-CrateOrder.ps1') -ManifestPath $ManifestPath

# Without -p flags cargo packages every workspace member and still exits 0, so
# an empty closure has to stop the run here rather than reach cargo.
if ($crates.Count -eq 0) { throw "Get-CrateOrder.ps1 returned no crates" }

$packageArgs = @()
foreach ($crate in $crates)
{
    $packageArgs += '-p'
    $packageArgs += $crate
}

if ($Registry)
{
    $packageArgs += '--registry'
    $packageArgs += $Registry
}

Write-Host "packaging $($crates.Count) crates"

# One cargo call for the whole closure: cargo resolves the crates against each
# other inside a temporary overlay, which is the only way to package a crate
# whose path dependencies are not on a registry yet.
$cargoArgs = @('package', '--manifest-path', $ManifestPath) + $packageArgs
Write-Host "cargo $($cargoArgs -join ' ')"
cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { throw "cargo package failed with exit $LASTEXITCODE" }

$metadata = cargo metadata --format-version 1 --no-deps --manifest-path $ManifestPath | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed with exit $LASTEXITCODE" }

$packageDir = Join-Path $metadata.target_directory 'package'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# target/package accumulates across runs, so a bare *.crate glob also matches
# files left by earlier runs -- including crates that have since been renamed.
# Counting those is both fragile and unsafe: a coincidental match would copy a
# stale crate into the artifact.  Collect by the exact file name cargo produces
# for each crate in this closure instead.
$versions = @{}
foreach ($package in $metadata.packages)
{
    $versions[$package.name] = $package.version
}

$found = @()
foreach ($crate in $crates)
{
    if (-not $versions.ContainsKey($crate)) { throw "cargo metadata has no package named $crate" }

    $cratePath = Join-Path $packageDir "$crate-$($versions[$crate]).crate"
    if (-not (Test-Path -LiteralPath $cratePath)) { throw "cargo package did not produce $cratePath" }

    $found += $cratePath
}

Copy-Item $found -Destination $OutDir
Write-Host "collected $($found.Count) crates into $OutDir"
