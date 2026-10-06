# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Validates and packages the single Rust release crate, mxc-sdk.
#
# Package:
#   pwsh scripts/ci/Invoke-CratePackage.ps1 -OutDir out/crates
#
# Validate release metadata and the pipeline's crate list:
#   pwsh scripts/ci/Invoke-CratePackage.ps1 -ValidateOnly

[CmdletBinding(DefaultParameterSetName = 'Package')]
param
(
    [Parameter(Mandatory, ParameterSetName = 'Package')]
    [string] $OutDir,

    [Parameter(Mandatory, ParameterSetName = 'Validate')]
    [switch] $ValidateOnly,

    [string] $ManifestPath = 'src/Cargo.toml',
    [string] $RootCrate = 'mxc-sdk',
    [string] $PackageRegistry = 'crates-io',
    [string] $ReleasePipelinePath = '.azure-pipelines/1ES.Release.Crates.yml',
    [string] $PublishTemplatePath = '.azure-pipelines/templates/Publish.CratesIo.Job.yml'
)

$ErrorActionPreference = 'Stop'

$metadata = cargo metadata --locked --format-version 1 --no-deps --manifest-path $ManifestPath | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed with exit $LASTEXITCODE" }

$packages = @($metadata.packages)
$package = $packages | Where-Object { $_.name -ceq $RootCrate }
if ($null -eq $package) { throw "root crate '$RootCrate' is not a member of $ManifestPath" }
if (@($package).Count -ne 1) { throw "workspace contains multiple packages named '$RootCrate'" }

if ($null -ne $package.publish -and @($package.publish).Count -eq 0)
{
    throw "crate '$RootCrate' has publish = false"
}
if ($package.name -cne 'mxc-sdk')
{
    throw "the Rust release crate must be named 'mxc-sdk'"
}
if ([string]::IsNullOrWhiteSpace($package.description))
{
    throw "crate '$RootCrate' has no package description"
}
if ([string]::IsNullOrWhiteSpace($package.repository))
{
    throw "crate '$RootCrate' has no package repository"
}
if ([string]::IsNullOrWhiteSpace($package.license) -and [string]::IsNullOrWhiteSpace($package.license_file))
{
    throw "crate '$RootCrate' has neither package license nor license-file metadata"
}

$firstPartyDependencies = @(
    $package.dependencies |
        Where-Object { $_.path -and $_.kind -ne 'dev' }
)
if ($firstPartyDependencies.Count -ne 0)
{
    $dependencyNames = ($firstPartyDependencies.name | Sort-Object -Unique) -join ', '
    throw "crate '$RootCrate' must be the only Rust release crate, but it depends on workspace packages: $dependencyNames"
}

if ($ValidateOnly)
{
    $releasePipelineText = [System.IO.File]::ReadAllText($ReleasePipelinePath)
    if ($releasePipelineText -cmatch '\bpublishCrates\b')
    {
        throw "$ReleasePipelinePath must not expose publishCrates as a queue-time parameter"
    }

    $pipelineLines = [System.IO.File]::ReadAllLines($PublishTemplatePath)
    $startMarker = '# BEGIN MXC-SDK PUBLISH CRATES'
    $endMarker = '# END MXC-SDK PUBLISH CRATES'
    $start = [Array]::FindIndex($pipelineLines, [Predicate[string]] { param($line) $line.Trim() -ceq $startMarker })
    $end = [Array]::FindIndex($pipelineLines, [Predicate[string]] { param($line) $line.Trim() -ceq $endMarker })
    if ($start -lt 0 -or $end -le $start)
    {
        throw "$PublishTemplatePath must contain ordered $startMarker and $endMarker markers"
    }

    $pipelineCrates = [System.Collections.Generic.List[string]]::new()
    for ($index = $start + 1; $index -lt $end; $index++)
    {
        if ($pipelineLines[$index] -notmatch '^\s*-\s+(mxc-[a-z0-9]+(?:-[a-z0-9]+)*)\s*$')
        {
            throw "$PublishTemplatePath has an invalid publishCrates entry at line $($index + 1)"
        }
        $pipelineCrates.Add($Matches[1])
    }
    if ($pipelineCrates.Count -ne 1 -or $pipelineCrates[0] -cne $RootCrate)
    {
        throw "$PublishTemplatePath must publish only '$RootCrate'"
    }

    Write-Host "validated the $RootCrate release package at version $($package.version)"
    return
}

Write-Host "fetching locked $RootCrate dependencies"
cargo fetch --locked --manifest-path $package.manifest_path
if ($LASTEXITCODE -ne 0) { throw "cargo fetch failed with exit $LASTEXITCODE" }

Write-Host "packaging $RootCrate at version $($package.version)"
cargo package --offline --locked --no-verify --registry $PackageRegistry --manifest-path $ManifestPath -p $RootCrate
if ($LASTEXITCODE -ne 0) { throw "cargo package failed with exit $LASTEXITCODE" }

$archive = Join-Path $metadata.target_directory "package/$RootCrate-$($package.version).crate"
if (-not (Test-Path -LiteralPath $archive))
{
    throw "cargo package did not produce $archive"
}
if (Test-Path -LiteralPath $OutDir)
{
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}
$crateDirectory = Join-Path $OutDir $RootCrate
New-Item -ItemType Directory -Force -Path $crateDirectory | Out-Null
Copy-Item -LiteralPath $archive -Destination $crateDirectory

Write-Host "collected the $RootCrate archive into $crateDirectory"
