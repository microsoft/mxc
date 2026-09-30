# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Discovers, validates, orders, and packages mxc-sdk and every internal crate
# it depends on into the pipeline artifact.
#
# Package:
#   pwsh scripts/ci/Invoke-CratePackage.ps1 -OutDir out/crates
#
# Validate release metadata and the pipeline's ordered crate list:
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

$members = @{}
foreach ($package in $metadata.packages) { $members[$package.name] = $package }
if (-not $members.ContainsKey($RootCrate)) { throw "root crate '$RootCrate' is not a member of $ManifestPath" }

$releaseVersion = $members[$RootCrate].version
$rootManifestPath = $members[$RootCrate].manifest_path
$releaseRequirement = "^$releaseVersion"
$visited = [System.Collections.Generic.HashSet[string]]::new()
$visiting = [System.Collections.Generic.HashSet[string]]::new()
$order = [System.Collections.Generic.List[string]]::new()

function Get-ReleaseDependencies([string] $Name)
{
    $dependencies = [System.Collections.Generic.List[string]]::new()
    foreach ($dependency in $members[$Name].dependencies)
    {
        if (-not $dependency.path -or $dependency.kind -eq 'dev' -or -not $members.ContainsKey($dependency.name))
        {
            continue
        }
        if (-not $dependency.req -or $dependency.req -eq '*')
        {
            throw "$Name has an unversioned first-party dependency on $($dependency.name)"
        }
        if ($dependency.req -cne $releaseRequirement)
        {
            throw "$Name requires $($dependency.name) at $($dependency.req), expected $releaseRequirement from the workspace version"
        }
        $dependencies.Add($dependency.name)
    }

    $result = [string[]] @($dependencies | Select-Object -Unique)
    [Array]::Sort($result, [System.StringComparer]::Ordinal)
    return $result
}

function Assert-ReleasePackage([string] $Name)
{
    $package = $members[$Name]
    if ($null -ne $package.publish -and @($package.publish).Count -eq 0)
    {
        throw "crate '$Name' is required by mxc-sdk but has publish = false"
    }
    if ($package.name -cnotmatch '^mxc-[a-z0-9]+(?:-[a-z0-9]+)*$')
    {
        throw "crate '$Name' must use a lowercase, hyphen-separated mxc- package name"
    }
    if ($package.version -ne $releaseVersion)
    {
        throw "crate '$Name' has version $($package.version), expected $releaseVersion"
    }
    if ([string]::IsNullOrWhiteSpace($package.description))
    {
        throw "crate '$Name' has no package description"
    }
    if ([string]::IsNullOrWhiteSpace($package.repository))
    {
        throw "crate '$Name' has no package repository"
    }
    if ([string]::IsNullOrWhiteSpace($package.license) -and [string]::IsNullOrWhiteSpace($package.license_file))
    {
        throw "crate '$Name' has neither package license nor license-file metadata"
    }
}

function Add-ReleasePackage([string] $Name)
{
    if ($visited.Contains($Name)) { return }
    if (-not $visiting.Add($Name))
    {
        throw "dependency cycle among crates required by mxc-sdk at '$Name'"
    }

    Assert-ReleasePackage $Name
    foreach ($dependency in Get-ReleaseDependencies $Name)
    {
        Add-ReleasePackage $dependency
    }

    $visiting.Remove($Name) | Out-Null
    $visited.Add($Name) | Out-Null
    $order.Add($Name)
}

Add-ReleasePackage $RootCrate

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

    $pipelineOrder = [System.Collections.Generic.List[string]]::new()
    for ($index = $start + 1; $index -lt $end; $index++)
    {
        if ($pipelineLines[$index] -notmatch '^\s*-\s+(mxc-[a-z0-9]+(?:-[a-z0-9]+)*)\s*$')
        {
            throw "$PublishTemplatePath has an invalid publishCrates entry at line $($index + 1)"
        }
        $pipelineOrder.Add($Matches[1])
    }
    if ($pipelineOrder.Count -ne $order.Count)
    {
        throw "$PublishTemplatePath contains $($pipelineOrder.Count) publish crates, but Cargo computed $($order.Count)"
    }
    for ($index = 0; $index -lt $order.Count; $index++)
    {
        if ($pipelineOrder[$index] -cne $order[$index])
        {
            throw "$PublishTemplatePath publishCrates[$index] is '$($pipelineOrder[$index])', but Cargo computed '$($order[$index])'"
        }
    }

    Write-Host "validated $($order.Count) release crates and pipeline order at version $releaseVersion"
    return
}

Write-Host "fetching locked $RootCrate dependencies"
cargo fetch --locked --manifest-path $rootManifestPath
if ($LASTEXITCODE -ne 0) { throw "cargo fetch failed with exit $LASTEXITCODE" }

$packageArgs = [System.Collections.Generic.List[string]]::new()
foreach ($crate in $order)
{
    $packageArgs.Add('-p')
    $packageArgs.Add($crate)
}
Write-Host "packaging $($order.Count) crates at version $releaseVersion"
$cargoArgs = @('package', '--offline', '--locked', '--no-verify', '--registry', $PackageRegistry, '--manifest-path', $ManifestPath) + [string[]] $packageArgs
cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { throw "cargo package failed with exit $LASTEXITCODE" }

$packageDirectory = Join-Path $metadata.target_directory 'package'
if (Test-Path -LiteralPath $OutDir)
{
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

foreach ($crate in $order)
{
    $archive = Join-Path $packageDirectory "$crate-$releaseVersion.crate"
    if (-not (Test-Path -LiteralPath $archive))
    {
        throw "cargo package did not produce $archive"
    }
    $crateDirectory = Join-Path $OutDir $crate
    New-Item -ItemType Directory -Force -Path $crateDirectory | Out-Null
    Copy-Item -LiteralPath $archive -Destination $crateDirectory
}

Write-Host "collected $($order.Count) crate archives into $OutDir"
