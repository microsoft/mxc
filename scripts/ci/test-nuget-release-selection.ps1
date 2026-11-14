# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$selector = Join-Path $PSScriptRoot '..\..\.azure-pipelines\scripts\select-dotnet-nuget-packages.ps1'
$pipelinePath = Join-Path $PSScriptRoot '..\..\.azure-pipelines\1ES.Release.Nuget.yml'
$root = Join-Path ([IO.Path]::GetTempPath()) "mxc-nuget-release-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $root | Out-Null
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function New-TestPackage {
    param(
        [string]$Directory,
        [string]$FileName,
        [string]$Id,
        [string]$Version
    )
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $archive = [IO.Compression.ZipFile]::Open(
        (Join-Path $Directory $FileName),
        [IO.Compression.ZipArchiveMode]::Create
    )
    try {
        $entry = $archive.CreateEntry("$Id.nuspec")
        $writer = [IO.StreamWriter]::new($entry.Open())
        try {
            $writer.Write("<package xmlns='http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'><metadata><id>$Id</id><version>$Version</version></metadata></package>")
        } finally {
            $writer.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
}

function Assert-Failure {
    param([string]$Payload, [string]$Release, [string]$Selection, [string]$Expected)
    try {
        & $selector -PayloadDirectory $Payload -ReleaseDirectory $Release -PackageSelection $Selection 6>&1 | Out-Null
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
    $payload = Join-Path $root 'both'
    $nvx = Join-Path $payload 'nvx'
    New-TestPackage $payload 'Microsoft.Mxc.Sdk.1.2.3.nupkg' 'Microsoft.Mxc.Sdk' '1.2.3'
    New-TestPackage $nvx 'Microsoft.Mxc.Sdk.Nvx.Runtime.1.2.3.nupkg' 'Microsoft.Mxc.Sdk.Nvx.Runtime' '1.2.3'
    Copy-Item -LiteralPath $selector -Destination $payload
    $selector = Join-Path $payload 'select-dotnet-nuget-packages.ps1'
    $release = Join-Path $root 'both-release'
    $output = @(& $selector -PayloadDirectory $payload -ReleaseDirectory $release `
        -PackageSelection 'publish-nvx-runtime,publish-sdk' 6>&1 | ForEach-Object { "$_" })
    foreach ($package in @(
        @{ Name = 'sdk'; File = 'Microsoft.Mxc.Sdk.1.2.3.nupkg'; Source = $payload }
        @{ Name = 'nvx'; File = 'Microsoft.Mxc.Sdk.Nvx.Runtime.1.2.3.nupkg'; Source = $nvx }
    )) {
        $staged = Join-Path (Join-Path $release $package.Name) $package.File
        if (-not (Test-Path -LiteralPath $staged -PathType Leaf)) { throw "Missing $staged" }
        if ((Get-FileHash -LiteralPath $staged).Hash -ne
            (Get-FileHash -LiteralPath (Join-Path $package.Source $package.File)).Hash) {
            throw "Staged package differs from input: $staged"
        }
        if (-not ($output -contains "##vso[task.setvariable variable=NuGetPackagePath_$($package.Name)]$staged")) {
            throw "Missing pipeline variable for $($package.Name): $output"
        }
    }

    $sdkOnly = Join-Path $root 'sdk-only'
    New-TestPackage $sdkOnly 'Microsoft.Mxc.Sdk.1.2.3.nupkg' 'Microsoft.Mxc.Sdk' '1.2.3'
    $sdkRelease = Join-Path $root 'sdk-release'
    & $selector -PayloadDirectory $sdkOnly -ReleaseDirectory $sdkRelease -PackageSelection 'publish-sdk'
    if (-not (Test-Path -LiteralPath (Join-Path $sdkRelease 'sdk\Microsoft.Mxc.Sdk.1.2.3.nupkg')) -or
        (Test-Path -LiteralPath (Join-Path $sdkRelease 'nvx'))) {
        throw 'SDK-only selection staged the wrong packages.'
    }

    $nvxOnly = Join-Path $root 'nvx-only'
    New-TestPackage (Join-Path $nvxOnly 'nvx') 'Microsoft.Mxc.Sdk.Nvx.Runtime.1.2.3.nupkg' 'Microsoft.Mxc.Sdk.Nvx.Runtime' '1.2.3'
    $nvxRelease = Join-Path $root 'nvx-release'
    & $selector -PayloadDirectory $nvxOnly -ReleaseDirectory $nvxRelease -PackageSelection 'publish-nvx-runtime'
    if (-not (Test-Path -LiteralPath (Join-Path $nvxRelease 'nvx\Microsoft.Mxc.Sdk.Nvx.Runtime.1.2.3.nupkg')) -or
        (Test-Path -LiteralPath (Join-Path $nvxRelease 'sdk'))) {
        throw 'NVX-only selection staged the wrong packages.'
    }

    $previousSelection = $env:MXC_NUGET_PACKAGES
    try {
        $env:MXC_NUGET_PACKAGES = 'publish-nvx-runtime'
        $envRelease = Join-Path $root 'environment-release'
        & $selector -PayloadDirectory $nvxOnly -ReleaseDirectory $envRelease
        if (-not (Test-Path -LiteralPath (Join-Path $envRelease 'nvx\Microsoft.Mxc.Sdk.Nvx.Runtime.1.2.3.nupkg')) -or
            (Test-Path -LiteralPath (Join-Path $envRelease 'sdk'))) {
            throw 'Pipeline environment selection staged the wrong packages.'
        }
    } finally {
        $env:MXC_NUGET_PACKAGES = $previousSelection
    }

    $mismatch = Join-Path $root 'mismatch'
    New-TestPackage $mismatch 'Microsoft.Mxc.Sdk.1.2.3.nupkg' 'Microsoft.Mxc.Sdk' '1.2.3'
    New-TestPackage (Join-Path $mismatch 'nvx') 'Microsoft.Mxc.Sdk.Nvx.Runtime.1.2.4.nupkg' 'Microsoft.Mxc.Sdk.Nvx.Runtime' '1.2.4'
    Assert-Failure $mismatch (Join-Path $root 'mismatch-release') 'publish-sdk,publish-nvx-runtime' 'versions do not match'

    $badIdentity = Join-Path $root 'bad-identity'
    New-TestPackage $badIdentity 'Microsoft.Mxc.Sdk.1.2.3.nupkg' 'Wrong.Package' '1.2.3'
    Assert-Failure $badIdentity (Join-Path $root 'bad-identity-release') 'publish-sdk' 'Invalid package identity'

    $badFilename = Join-Path $root 'bad-filename'
    New-TestPackage $badFilename 'Microsoft.Mxc.Sdk.1.2.3.nupkg' 'Microsoft.Mxc.Sdk' '1.2.4'
    Assert-Failure $badFilename (Join-Path $root 'bad-filename-release') 'publish-sdk' 'Invalid package version or filename'

    $multiple = Join-Path $root 'multiple'
    New-TestPackage $multiple 'Microsoft.Mxc.Sdk.1.2.3.nupkg' 'Microsoft.Mxc.Sdk' '1.2.3'
    New-TestPackage $multiple 'Microsoft.Mxc.Sdk.1.2.4.nupkg' 'Microsoft.Mxc.Sdk' '1.2.4'
    Assert-Failure $multiple (Join-Path $root 'multiple-release') 'publish-sdk' 'Expected exactly one'
    Assert-Failure $sdkOnly (Join-Path $root 'missing-release') 'publish-nvx-runtime' 'Missing package directory'
    Assert-Failure $payload (Join-Path $root 'empty-release') '' 'Select at least one'
    Assert-Failure $payload (Join-Path $root 'unknown-release') 'publish-other' 'Unknown package selection'
    Assert-Failure $payload (Join-Path $root 'duplicate-release') 'publish-sdk,publish-sdk' 'Duplicate package selection'

    $pipeline = Get-Content -LiteralPath $pipelinePath -Raw
    foreach ($required in @(
        'name: nugetPackages',
        'type: stringList',
        'select-dotnet-nuget-packages.ps1',
        "MXC_NUGET_PACKAGES: `${{ join(',', parameters.nugetPackages) }}"
    )) {
        if (-not $pipeline.Contains($required)) { throw "NuGet pipeline is missing: $required" }
    }
    if ($pipeline -notmatch '(?ms)name: nugetPackages\s+displayName: [^\r\n]+\s+type: stringList\s+default:\s+- publish-sdk\s+- publish-nvx-runtime\s+values:\s+- publish-sdk\s+- publish-nvx-runtime') {
        throw 'NuGet pipeline must default to both selectable packages.'
    }
    $publicStart = $pipeline.IndexOf("        - `${{ if eq(parameters.publishTarget, 'NuGet.org') }}:")
    $internalStart = $pipeline.IndexOf('        - ${{ else }}:', $publicStart)
    if ($publicStart -lt 0 -or $internalStart -lt 0) { throw 'NuGet publish targets are missing.' }
    $public = $pipeline.Substring($publicStart, $internalStart - $publicStart)
    $internal = $pipeline.Substring($internalStart)
    foreach ($target in @(
        @{ Text = $public; Task = 'EsrpRelease@14'; Sdk = 'nuget-release/sdk'; Nvx = 'nuget-release/nvx' }
        @{ Text = $internal; Task = '1ES.PublishNuget@1'; Sdk = 'NuGetPackagePath_sdk'; Nvx = 'NuGetPackagePath_nvx' }
    )) {
        $sdkCondition = $target.Text.IndexOf("`${{ if containsValue(parameters.nugetPackages, 'publish-sdk') }}")
        $nvxCondition = $target.Text.IndexOf("`${{ if containsValue(parameters.nugetPackages, 'publish-nvx-runtime') }}")
        if ($sdkCondition -lt 0 -or $nvxCondition -le $sdkCondition) {
            throw 'Both packages must be independently selectable, with the SDK first.'
        }
        $sdkStep = $target.Text.Substring($sdkCondition, $nvxCondition - $sdkCondition)
        $nvxStep = $target.Text.Substring($nvxCondition)
        if (-not $sdkStep.Contains($target.Task) -or -not $sdkStep.Contains($target.Sdk) -or
            -not $nvxStep.Contains($target.Task) -or -not $nvxStep.Contains($target.Nvx)) {
            throw "Incorrect package task or input for $($target.Task)."
        }
    }
    Write-Host 'NuGet release package selection tests passed.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
}
