# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PayloadDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseDirectory,

    [AllowEmptyString()]
    [string]$PackageSelection = $env:MXC_NPM_PACKAGES
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($PackageSelection)) {
    throw 'Select at least one npm package to publish.'
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
        @{ Name = 'sdk'; Id = '@microsoft/mxc-sdk'; Directory = $PayloadDirectory }
    }
    if ($requested -ccontains 'publish-nvx-runtime') {
        @{ Name = 'nvx'; Id = '@microsoft/mxc-sdk-nvx-runtime-win32-x64'; Directory = (Join-Path $PayloadDirectory 'nvx') }
    }
)
foreach ($package in $packages) {
    if (-not (Test-Path -LiteralPath $package.Directory -PathType Container)) {
        throw "Missing package directory: $($package.Directory)"
    }
    $files = @(Get-ChildItem -LiteralPath $package.Directory -Filter '*.tgz' -File -ErrorAction Stop)
    if ($files.Count -ne 1) {
        throw "Expected exactly one $($package.Id) package in $($package.Directory), found $($files.Count)"
    }
    $package.File = $files[0]
    $manifestJson = @(& tar -xOf $package.File.FullName package/package.json)
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot read package/package.json from $($package.File.Name)"
    }
    $manifest = ($manifestJson -join "`n") | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.name -cne $package.Id) {
        throw "Invalid package identity in $($package.File.Name)"
    }
    $package.Version = $manifest.version
    $filePrefix = $package.Id.TrimStart('@').Replace('/', '-')
    if ($package.Version -isnot [string] -or $package.Version -cnotmatch '^[0-9][0-9A-Za-z.+-]*$' -or
        $package.File.Name -cne "$filePrefix-$($package.Version).tgz") {
        throw "Invalid package version or filename in $($package.File.Name)"
    }
}
if ($packages.Count -eq 2 -and $packages[0].Version -cne $packages[1].Version) {
    throw 'SDK and NVX runtime package versions do not match.'
}
foreach ($package in $packages) {
    $directory = Join-Path $ReleaseDirectory $package.Name
    New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath $package.File.FullName -Destination $directory -ErrorAction Stop
}
