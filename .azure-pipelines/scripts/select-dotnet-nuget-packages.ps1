# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PayloadDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseDirectory,

    [AllowEmptyString()]
    [string]$PackageSelection = $env:MXC_NUGET_PACKAGES
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

if ([string]::IsNullOrWhiteSpace($PackageSelection)) {
    throw 'Select at least one NuGet package to publish.'
}
$requested = @($PackageSelection.Split(',') | ForEach-Object { $_.Trim() })
foreach ($name in $requested) {
    if ($name -cnotin @('publish-sdk', 'publish-nvx-runtime')) {
        throw "Unknown package selection: $name"
    }
}
if (@($requested | Select-Object -Unique).Count -ne $requested.Count) {
    throw 'Duplicate package selection.'
}

$packages = @(
    if ($requested -ccontains 'publish-sdk') {
        @{ Name = 'sdk'; Id = 'Microsoft.Mxc.Sdk'; Directory = $PayloadDirectory }
    }
    if ($requested -ccontains 'publish-nvx-runtime') {
        @{ Name = 'nvx'; Id = 'Microsoft.Mxc.Sdk.Nvx.Runtime'; Directory = (Join-Path $PayloadDirectory 'nvx') }
    }
)
foreach ($package in $packages) {
    if (-not (Test-Path -LiteralPath $package.Directory -PathType Container)) {
        throw "Missing package directory: $($package.Directory)"
    }
    $files = @(Get-ChildItem -LiteralPath $package.Directory -Filter "$($package.Id).*.nupkg" -File -ErrorAction Stop)
    if ($files.Count -ne 1) {
        throw "Expected exactly one $($package.Id) package in $($package.Directory), found $($files.Count)"
    }
    $package.File = $files[0]
    $archive = [System.IO.Compression.ZipFile]::OpenRead($package.File.FullName)
    try {
        $nuspecs = @($archive.Entries | Where-Object { $_.FullName -match '^[^/\\]+\.nuspec$' })
        if ($nuspecs.Count -ne 1) { throw "Expected exactly one root nuspec in $($package.File.Name)" }
        $reader = [System.IO.StreamReader]::new($nuspecs[0].Open())
        try { [xml]$nuspec = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $ids = @($nuspec.SelectNodes("/*[local-name()='package']/*[local-name()='metadata']/*[local-name()='id']"))
        $versions = @($nuspec.SelectNodes("/*[local-name()='package']/*[local-name()='metadata']/*[local-name()='version']"))
        if ($ids.Count -ne 1 -or $versions.Count -ne 1 -or $ids[0].InnerText -cne $package.Id) {
            throw "Invalid package identity in $($package.File.Name)"
        }
        $package.Version = $versions[0].InnerText
        if ($package.Version -cnotmatch '^[0-9][0-9A-Za-z.+-]*$' -or
            $package.File.Name -cne "$($package.Id).$($package.Version).nupkg") {
            throw "Invalid package version or filename in $($package.File.Name)"
        }
    } finally {
        $archive.Dispose()
    }
}
if ($packages.Count -eq 2 -and $packages[0].Version -cne $packages[1].Version) {
    throw 'SDK and NVX runtime package versions do not match.'
}
foreach ($package in $packages) {
    $directory = Join-Path $ReleaseDirectory $package.Name
    New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
    $releasePath = Join-Path $directory $package.File.Name
    Copy-Item -LiteralPath $package.File.FullName -Destination $releasePath -ErrorAction Stop
    Write-Host "##vso[task.setvariable variable=NuGetPackagePath_$($package.Name)]$releasePath"
}
