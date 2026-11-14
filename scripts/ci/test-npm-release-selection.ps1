# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$selector = Join-Path $PSScriptRoot '..\..\.azure-pipelines\scripts\select-npm-packages.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) "mxc-npm-release-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $root | Out-Null

function New-TestPackage {
    param([string]$Directory, [string]$FileName, [string]$Id, [string]$Version)
    $source = Join-Path $root ([guid]::NewGuid().ToString())
    $package = Join-Path $source 'package'
    New-Item -ItemType Directory -Path $package | Out-Null
    @{ name = $Id; version = $Version } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $package 'package.json') -Encoding Ascii
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    & tar -czf (Join-Path $Directory $FileName) -C $source package
    if ($LASTEXITCODE -ne 0) { throw 'Could not create npm package fixture.' }
}

function Assert-Failure {
    param([string]$Payload, [string]$Release, [string]$Selection, [string]$Expected)
    try {
        & $selector -PayloadDirectory $Payload -ReleaseDirectory $Release -PackageSelection $Selection
    } catch {
        if ($_.Exception.Message -notmatch $Expected) {
            throw "Expected error matching '$Expected', got: $_"
        }
        if (Test-Path -LiteralPath $Release) {
            throw 'Invalid package selection must not stage any files.'
        }
        return
    }
    throw "Expected package selection to fail: $Expected"
}

try {
    $sdkFile = 'microsoft-mxc-sdk-1.2.3.tgz'
    $nvxFile = 'microsoft-mxc-sdk-nvx-runtime-win32-x64-1.2.3.tgz'
    $sdkId = '@microsoft/mxc-sdk'
    $nvxId = '@microsoft/mxc-sdk-nvx-runtime-win32-x64'
    $payload = Join-Path $root 'both'
    New-TestPackage $payload $sdkFile $sdkId '1.2.3'
    New-TestPackage (Join-Path $payload 'nvx') $nvxFile $nvxId '1.2.3'
    Copy-Item -LiteralPath $selector -Destination $payload
    $selector = Join-Path $payload 'select-npm-packages.ps1'
    $release = Join-Path $root 'both-release'
    & $selector -PayloadDirectory $payload -ReleaseDirectory $release `
        -PackageSelection 'publish-nvx-runtime,publish-sdk'
    foreach ($package in @(
        @{ Name = 'sdk'; File = $sdkFile; Source = $payload }
        @{ Name = 'nvx'; File = $nvxFile; Source = (Join-Path $payload 'nvx') }
    )) {
        $staged = Join-Path (Join-Path $release $package.Name) $package.File
        if ((Get-FileHash -LiteralPath $staged).Hash -ne
            (Get-FileHash -LiteralPath (Join-Path $package.Source $package.File)).Hash) {
            throw "Staged package differs from input: $staged"
        }
    }

    $sdkOnly = Join-Path $root 'sdk-only'
    New-TestPackage $sdkOnly $sdkFile $sdkId '1.2.3'
    $sdkRelease = Join-Path $root 'sdk-release'
    & $selector -PayloadDirectory $sdkOnly -ReleaseDirectory $sdkRelease -PackageSelection 'publish-sdk'
    if (-not (Test-Path -LiteralPath (Join-Path $sdkRelease "sdk\$sdkFile")) -or
        (Test-Path -LiteralPath (Join-Path $sdkRelease 'nvx'))) {
        throw 'SDK-only selection staged the wrong packages.'
    }

    $nvxOnly = Join-Path $root 'nvx-only'
    New-TestPackage (Join-Path $nvxOnly 'nvx') $nvxFile $nvxId '1.2.3'
    $nvxRelease = Join-Path $root 'nvx-release'
    & $selector -PayloadDirectory $nvxOnly -ReleaseDirectory $nvxRelease -PackageSelection 'publish-nvx-runtime'
    if (-not (Test-Path -LiteralPath (Join-Path $nvxRelease "nvx\$nvxFile")) -or
        (Test-Path -LiteralPath (Join-Path $nvxRelease 'sdk'))) {
        throw 'NVX-only selection staged the wrong packages.'
    }

    $previousSelection = $env:MXC_NPM_PACKAGES
    try {
        $env:MXC_NPM_PACKAGES = 'publish-nvx-runtime'
        $envRelease = Join-Path $root 'environment-release'
        & $selector -PayloadDirectory $nvxOnly -ReleaseDirectory $envRelease
        if (-not (Test-Path -LiteralPath (Join-Path $envRelease "nvx\$nvxFile")) -or
            (Test-Path -LiteralPath (Join-Path $envRelease 'sdk'))) {
            throw 'Pipeline environment selection staged the wrong packages.'
        }
    } finally {
        $env:MXC_NPM_PACKAGES = $previousSelection
    }

    $mismatch = Join-Path $root 'mismatch'
    New-TestPackage $mismatch $sdkFile $sdkId '1.2.3'
    New-TestPackage (Join-Path $mismatch 'nvx') 'microsoft-mxc-sdk-nvx-runtime-win32-x64-1.2.4.tgz' $nvxId '1.2.4'
    Assert-Failure $mismatch (Join-Path $root 'mismatch-release') 'publish-sdk,publish-nvx-runtime' 'versions do not match'

    $badIdentity = Join-Path $root 'bad-identity'
    New-TestPackage $badIdentity $sdkFile $nvxId '1.2.3'
    Assert-Failure $badIdentity (Join-Path $root 'bad-identity-release') 'publish-sdk' 'Invalid package identity'

    $badFilename = Join-Path $root 'bad-filename'
    New-TestPackage $badFilename $sdkFile $sdkId '1.2.4'
    Assert-Failure $badFilename (Join-Path $root 'bad-filename-release') 'publish-sdk' 'Invalid package version or filename'

    $multiple = Join-Path $root 'multiple'
    New-TestPackage $multiple $sdkFile $sdkId '1.2.3'
    New-TestPackage $multiple 'microsoft-mxc-sdk-1.2.4.tgz' $sdkId '1.2.4'
    Assert-Failure $multiple (Join-Path $root 'multiple-release') 'publish-sdk' 'Expected exactly one'
    Assert-Failure $sdkOnly (Join-Path $root 'missing-release') 'publish-sdk,publish-nvx-runtime' 'Missing package directory'
    Assert-Failure $payload (Join-Path $root 'empty-release') '' 'Select at least one'
    Assert-Failure $payload (Join-Path $root 'unknown-release') 'publish-other' 'Unknown package selection'
    Assert-Failure $payload (Join-Path $root 'duplicate-release') 'publish-sdk,publish-sdk' 'Duplicate package selection'
    Write-Host 'npm release package selection tests passed.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
