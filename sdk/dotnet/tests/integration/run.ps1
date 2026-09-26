# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackagePath,

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [switch]$SkipBackendTests,

    [switch]$RunWithSudo
)

$ErrorActionPreference = 'Stop'

$packages = @(Get-Item -Path $PackagePath -ErrorAction Stop)
if ($packages.Count -ne 1) {
    throw "Expected exactly one Microsoft.Mxc.Sdk package, found $($packages.Count)."
}

$package = $packages[0]
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "mxc-dotnet-integration-$([Guid]::NewGuid())"
$packageSource = Join-Path $temporaryRoot 'packages'
$packageCache = Join-Path $temporaryRoot 'cache'
$project = Join-Path $PSScriptRoot 'Microsoft.Mxc.Sdk.IntegrationTests.csproj'

$previousPackageVersion = $env:MXC_TEST_PACKAGE_VERSION
$previousSkipBackends = $env:MXC_SKIP_BACKEND_INTEGRATION_TESTS
$previousNuGetPackages = $env:NUGET_PACKAGES

try {
    New-Item -ItemType Directory -Path $packageSource -Force | Out-Null

    $destinationName = if ($package.Name.EndsWith('.public-unsigned-package', [StringComparison]::Ordinal)) {
        $package.Name.Substring(
            0,
            $package.Name.Length - '.public-unsigned-package'.Length
        ) + '.nupkg'
    } elseif ($package.Extension -eq '.nupkg') {
        $package.Name
    } else {
        throw "Unsupported package filename: $($package.Name)"
    }

    $stagedPackage = Join-Path $packageSource $destinationName
    Copy-Item -LiteralPath $package.FullName -Destination $stagedPackage

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($stagedPackage)
    try {
        $nuspecEntries = @($archive.Entries | Where-Object { $_.FullName -like '*.nuspec' })
        if ($nuspecEntries.Count -ne 1) {
            throw "Expected exactly one nuspec in $destinationName, found $($nuspecEntries.Count)."
        }

        $reader = [IO.StreamReader]::new($nuspecEntries[0].Open())
        try {
            [xml]$nuspec = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $archive.Dispose()
    }

    $packageId = [string]$nuspec.package.metadata.id
    $packageVersion = ([string]$nuspec.package.metadata.version).Trim()
    if ($packageId -ne 'Microsoft.Mxc.Sdk' -or [string]::IsNullOrWhiteSpace($packageVersion)) {
        throw "Unexpected package identity: '$packageId' '$packageVersion'."
    }

    $env:MXC_TEST_PACKAGE_VERSION = $packageVersion
    $env:MXC_SKIP_BACKEND_INTEGRATION_TESTS = if ($SkipBackendTests) { '1' } else { '0' }
    $env:NUGET_PACKAGES = $packageCache

    Write-Host "Testing $packageId $packageVersion from $($package.FullName)"

    foreach ($directory in @('bin', 'obj')) {
        $buildDirectory = Join-Path $PSScriptRoot $directory
        if (Test-Path -LiteralPath $buildDirectory) {
            Remove-Item -LiteralPath $buildDirectory -Recurse -Force
        }
    }

    & dotnet restore $project `
        "-p:MxcPackageVersion=$packageVersion" `
        --source $packageSource `
        --nologo
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet restore failed with exit code $LASTEXITCODE."
    }

    & dotnet build $project `
        --configuration $Configuration `
        --no-restore `
        --nologo `
        "-p:MxcPackageVersion=$packageVersion"
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet build failed with exit code $LASTEXITCODE."
    }

    $testAssembly = Join-Path $PSScriptRoot "bin/$Configuration/net8.0/Microsoft.Mxc.Sdk.IntegrationTests.dll"
    $dotnet = (Get-Command dotnet -ErrorAction Stop).Source
    if ($RunWithSudo) {
        & sudo --preserve-env=MXC_TEST_PACKAGE_VERSION,MXC_SKIP_BACKEND_INTEGRATION_TESTS $dotnet $testAssembly
    } else {
        & $dotnet $testAssembly
    }
    if ($LASTEXITCODE -ne 0) {
        throw "The package integration tests failed with exit code $LASTEXITCODE."
    }
} finally {
    $env:MXC_TEST_PACKAGE_VERSION = $previousPackageVersion
    $env:MXC_SKIP_BACKEND_INTEGRATION_TESTS = $previousSkipBackends
    $env:NUGET_PACKAGES = $previousNuGetPackages

    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
