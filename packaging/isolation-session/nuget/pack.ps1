#Requires -Version 5.1
<#
.SYNOPSIS
    Build the pipeline-owned multi-architecture IsoSession SDK NuGet.

.DESCRIPTION
    Copyright (c) Microsoft Corporation. All rights reserved.

    Creates Microsoft.Windows.AI.IsolationSession.SDK from source inputs owned
    by this repository's pipeline:

      - metadata/windows.ai.isolationsession.winmd
      - metadata/windows.ai.isolationsession.preview.winmd
      - metadata/GENERATION_INFO.toml
      - metadata/RELEASE_INFO.json
      - runtimes/win-x64/native/IsoSessionApp.dll
      - runtimes/win-x64/native/IsoSession.manifest
      - runtimes/win-arm64/native/IsoSessionApp.dll
      - runtimes/win-arm64/native/IsoSession.manifest

    The package version is derived from the canonical release contract:
    MonthId (runtime instance) stays YYYY.MM, while the NuGet version carries
    the in-month patch as 0.YYYYMM.<patch>.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$X64BinDir,

    [Parameter(Mandatory = $true)]
    [string]$Arm64BinDir,

    [Parameter(Mandatory = $true)]
    [string]$MetadataDir,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseMetadataPath,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}\.\d{2}$')]
    [string]$MonthId,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 65535)]
    [int]$Patch,

    [string]$ManifestTemplate = (Join-Path $PSScriptRoot 'IsoSession.manifest.template')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$releaseInfoScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'common\Get-IsoSessionReleaseInfo.ps1'
$sdkGenerationInfoPath = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path `
    'external\windows-sdk\isolation-session\GENERATION_INFO.toml'

if (-not (Test-Path -LiteralPath $releaseInfoScript -PathType Leaf)) {
    throw "Release helper not found: '$releaseInfoScript'."
}
if (-not (Test-Path -LiteralPath $sdkGenerationInfoPath -PathType Leaf)) {
    throw "SDK generation provenance file not found: '$sdkGenerationInfoPath'."
}
if (-not (Test-Path -LiteralPath $ManifestTemplate -PathType Leaf)) {
    throw "Manifest template not found: '$ManifestTemplate'."
}
if (-not (Test-Path -LiteralPath $ReleaseMetadataPath -PathType Leaf)) {
    throw "Release metadata file not found: '$ReleaseMetadataPath'."
}

$releaseInfo = & $releaseInfoScript -MonthId $MonthId -Patch $Patch
$releaseMetadataRaw = Get-Content -LiteralPath $ReleaseMetadataPath -Raw
$releaseMetadata = $releaseMetadataRaw | ConvertFrom-Json

function Test-RequiredDirectory {
    param(
        [string]$Path,
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Label directory not found: '$Path'."
    }
}

function Get-RequiredFileBytes {
    param(
        [string]$Path,
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label file not found: '$Path'."
    }
    [System.IO.File]::ReadAllBytes($Path)
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        [System.BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Add-TextEntry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName,
        [string]$Text
    )

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $entry = $Archive.CreateEntry($EntryName)
    $stream = $entry.Open()
    try {
        $bytes = $utf8NoBom.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
}

function Add-BytesEntry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName,
        [byte[]]$Bytes
    )

    $entry = $Archive.CreateEntry($EntryName)
    $stream = $entry.Open()
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
}

function Get-ZipEntryText {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName
    )

    $entry = $Archive.GetEntry($EntryName)
    if (-not $entry) {
        return $null
    }

    $reader = [System.IO.StreamReader]::new($entry.Open())
    try {
        $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }
}

function Get-GenerationInfoValue {
    param(
        [string]$Content,
        [string]$Name
    )

    $match = [regex]::Match($Content, "(?m)^\s*$([regex]::Escape($Name))\s*=\s*`"([^`"]+)`"")
    if (-not $match.Success) {
        throw "GENERATION_INFO.toml is missing '$Name'."
    }
    $match.Groups[1].Value.Trim()
}

function Get-ReleaseWinmdRecord {
    param(
        [object]$Metadata,
        [string]$WinmdName
    )

    $record = @($Metadata.source.winmds | Where-Object { $_.name -eq $WinmdName })
    if ($record.Count -ne 1) {
        throw "Release metadata must contain exactly one winmd record for '$WinmdName'."
    }
    $record[0]
}

Test-RequiredDirectory -Path $X64BinDir -Label 'x64 runtime'
Test-RequiredDirectory -Path $Arm64BinDir -Label 'arm64 runtime'
Test-RequiredDirectory -Path $MetadataDir -Label 'metadata'

$x64AppDllPath = Join-Path $X64BinDir 'IsoSessionApp.dll'
$arm64AppDllPath = Join-Path $Arm64BinDir 'IsoSessionApp.dll'
$winmdPath = Join-Path $MetadataDir 'windows.ai.isolationsession.winmd'
$previewWinmdPath = Join-Path $MetadataDir 'windows.ai.isolationsession.preview.winmd'

$x64AppDllBytes = Get-RequiredFileBytes -Path $x64AppDllPath -Label 'x64 runtime'
$arm64AppDllBytes = Get-RequiredFileBytes -Path $arm64AppDllPath -Label 'arm64 runtime'
$winmdBytes = Get-RequiredFileBytes -Path $winmdPath -Label 'primary WinMD'
$previewWinmdBytes = Get-RequiredFileBytes -Path $previewWinmdPath -Label 'preview WinMD'

if ($releaseMetadata.release.canonicalRelease -ne $releaseInfo.canonicalRelease) {
    throw "Release metadata canonical release '$($releaseMetadata.release.canonicalRelease)' does not match '$($releaseInfo.canonicalRelease)'."
}
if ($releaseMetadata.release.monthId -ne $releaseInfo.monthId -or
    [int]$releaseMetadata.release.patch -ne $releaseInfo.patch) {
    throw 'Release metadata monthId/patch do not match the requested release contract.'
}
if ($releaseMetadata.package.id -ne $releaseInfo.packageId) {
    throw "Release metadata package id '$($releaseMetadata.package.id)' does not match '$($releaseInfo.packageId)'."
}
if ($releaseMetadata.package.version -ne $releaseInfo.nugetVersion) {
    throw "Release metadata package version '$($releaseMetadata.package.version)' does not match '$($releaseInfo.nugetVersion)'."
}
if ($releaseMetadata.package.fileName -ne $releaseInfo.nugetPackageFileName) {
    throw "Release metadata package file name '$($releaseMetadata.package.fileName)' does not match '$($releaseInfo.nugetPackageFileName)'."
}

$primaryWinmdMetadata = Get-ReleaseWinmdRecord -Metadata $releaseMetadata -WinmdName 'windows.ai.isolationsession.winmd'
$previewWinmdMetadata = Get-ReleaseWinmdRecord -Metadata $releaseMetadata -WinmdName 'windows.ai.isolationsession.preview.winmd'
if ($primaryWinmdMetadata.sha256 -ne (Get-Sha256Hex -Bytes $winmdBytes)) {
    throw 'Release metadata primary WinMD hash does not match the staged WinMD bytes.'
}
if ($previewWinmdMetadata.sha256 -ne (Get-Sha256Hex -Bytes $previewWinmdBytes)) {
    throw 'Release metadata preview WinMD hash does not match the staged WinMD bytes.'
}

$sdkGenerationInfo = Get-Content -LiteralPath $sdkGenerationInfoPath -Raw
$windowsBindgenVersion = Get-GenerationInfoValue -Content $sdkGenerationInfo -Name 'windows_bindgen_version'
$targetWindowsCrate = Get-GenerationInfoValue -Content $sdkGenerationInfo -Name 'target_windows_crate'
$sourceGeneratedDate = Get-GenerationInfoValue -Content $sdkGenerationInfo -Name 'generated_date'

$manifestText = [System.IO.File]::ReadAllText($ManifestTemplate).Replace('$(MonthId)', $MonthId)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$manifestBytes = $utf8NoBom.GetBytes($manifestText)
$generationInfo = @"
# Generated by the MXC IsoSession pipeline. Do not edit by hand.

[tool]
windows_bindgen_version = "$windowsBindgenVersion"
target_windows_crate = "$targetWindowsCrate"
generated_date = "$sourceGeneratedDate"

[metadata]
winmd = "windows.ai.isolationsession.winmd"
winmd_preview = "windows.ai.isolationsession.preview.winmd"
instance = "$($releaseInfo.runtimeInstance)"
canonical_release = "$($releaseInfo.canonicalRelease)"
nuget_version = "$($releaseInfo.nugetVersion)"
runtime_dir = "%ProgramFiles%\\Microsoft\\Agentic Runtime\\$MonthId"
build_guid = "$($releaseMetadata.source.buildGuid)"
os_branch = "$($releaseMetadata.source.osBranch)"
x64_drop_name = "$($releaseMetadata.source.payloads.x64.dropName)"
x64_flavor = "$($releaseMetadata.source.payloads.x64.flavor)"
arm64_drop_name = "$($releaseMetadata.source.payloads.arm64.dropName)"
arm64_flavor = "$($releaseMetadata.source.payloads.arm64.flavor)"
winmd_sha256 = "$($primaryWinmdMetadata.sha256)"
winmd_preview_sha256 = "$($previewWinmdMetadata.sha256)"
generated_utc = "$(Get-Date).ToUniversalTime().ToString('o')"
"@

$nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>$($releaseInfo.packageId)</id>
    <version>$($releaseInfo.nugetVersion)</version>
    <title>Windows AI Isolation Session SDK</title>
    <authors>Microsoft</authors>
    <owners>Microsoft</owners>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>Pipeline-generated SDK for Windows.AI.IsolationSession. Contains both WinMD metadata files plus signed win-x64 and win-arm64 IsoSessionApp runtime shims.</description>
    <summary>Windows.AI.IsolationSession SDK: metadata for Windows.AI.IsolationSession and Windows.AI.IsolationSession.Preview plus win-x64 and win-arm64 runtime assets.</summary>
    <tags>Windows IsolationSession WinRT WinMD MXC AgenticRuntime sdk</tags>
    <readme>README.md</readme>
  </metadata>
</package>
"@

$contentTypes = @"
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/octet" />
  <Default Extension="winmd" ContentType="application/octet" />
  <Default Extension="toml" ContentType="application/octet" />
  <Default Extension="json" ContentType="application/json" />
  <Default Extension="dll" ContentType="application/octet" />
  <Default Extension="manifest" ContentType="application/octet" />
  <Default Extension="md" ContentType="text/markdown" />
</Types>
"@

$rels = @"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/$($releaseInfo.packageId).nuspec" Id="R0" />
</Relationships>
"@

$readme = @"
# IsolationSession SDK

This package is generated by the MXC IsoSession artifact pipeline.

- Release: $($releaseInfo.canonicalRelease)
- MonthId: $MonthId
- NuGet version: $($releaseInfo.nugetVersion)
- MSI version: $($releaseInfo.msiVersion)
"@

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$outNupkg = Join-Path $OutDir $releaseInfo.nugetPackageFileName
if (Test-Path -LiteralPath $outNupkg -PathType Leaf) {
    Remove-Item -LiteralPath $outNupkg -Force
}

$zip = [System.IO.Compression.ZipFile]::Open($outNupkg, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Add-TextEntry -Archive $zip -EntryName 'README.md' -Text $readme
    Add-BytesEntry -Archive $zip -EntryName 'metadata/windows.ai.isolationsession.winmd' -Bytes $winmdBytes
    Add-BytesEntry -Archive $zip -EntryName 'metadata/windows.ai.isolationsession.preview.winmd' -Bytes $previewWinmdBytes
    Add-TextEntry -Archive $zip -EntryName 'metadata/GENERATION_INFO.toml' -Text $generationInfo
    Add-BytesEntry -Archive $zip -EntryName 'metadata/RELEASE_INFO.json' -Bytes ([System.IO.File]::ReadAllBytes($ReleaseMetadataPath))
    Add-BytesEntry -Archive $zip -EntryName 'runtimes/win-x64/native/IsoSessionApp.dll' -Bytes $x64AppDllBytes
    Add-BytesEntry -Archive $zip -EntryName 'runtimes/win-x64/native/IsoSession.manifest' -Bytes $manifestBytes
    Add-BytesEntry -Archive $zip -EntryName 'runtimes/win-arm64/native/IsoSessionApp.dll' -Bytes $arm64AppDllBytes
    Add-BytesEntry -Archive $zip -EntryName 'runtimes/win-arm64/native/IsoSession.manifest' -Bytes $manifestBytes
    Add-TextEntry -Archive $zip -EntryName '_rels/.rels' -Text $rels
    Add-TextEntry -Archive $zip -EntryName '[Content_Types].xml' -Text $contentTypes
    Add-TextEntry -Archive $zip -EntryName "$($releaseInfo.packageId).nuspec" -Text $nuspec
}
finally {
    $zip.Dispose()
}

$verify = [System.IO.Compression.ZipFile]::OpenRead($outNupkg)
try {
    $expectedEntries = @(
        'metadata/windows.ai.isolationsession.winmd',
        'metadata/windows.ai.isolationsession.preview.winmd',
        'metadata/GENERATION_INFO.toml',
        'metadata/RELEASE_INFO.json',
        'runtimes/win-x64/native/IsoSessionApp.dll',
        'runtimes/win-x64/native/IsoSession.manifest',
        'runtimes/win-arm64/native/IsoSessionApp.dll',
        'runtimes/win-arm64/native/IsoSession.manifest',
        'README.md',
        '_rels/.rels',
        '[Content_Types].xml',
        "$($releaseInfo.packageId).nuspec"
    )
    $missingEntries = @($expectedEntries | Where-Object { -not $verify.GetEntry($_) })
    if ($missingEntries.Count -gt 0) {
        throw "Generated package is missing expected entries: $($missingEntries -join ', ')."
    }

    $nuspecText = Get-ZipEntryText -Archive $verify -EntryName "$($releaseInfo.packageId).nuspec"
    if ($nuspecText -notmatch '<id>Microsoft\.Windows\.AI\.IsolationSession\.SDK</id>') {
        throw 'Generated nuspec id does not match the canonical package id.'
    }
    if ($nuspecText -notmatch [regex]::Escape("<version>$($releaseInfo.nugetVersion)</version>")) {
        throw 'Generated nuspec version does not match the canonical NuGet version.'
    }

    foreach ($rid in @('win-x64', 'win-arm64')) {
        $runtimeManifest = Get-ZipEntryText -Archive $verify -EntryName "runtimes/$rid/native/IsoSession.manifest"
        if ($runtimeManifest -notmatch [regex]::Escape("name=`"$MonthId`"")) {
            throw "Runtime manifest for $rid was not stamped with MonthId '$MonthId'."
        }
    }

    $packageReleaseMetadata = Get-ZipEntryText -Archive $verify -EntryName 'metadata/RELEASE_INFO.json' |
        ConvertFrom-Json
    if ($packageReleaseMetadata.package.version -ne $releaseInfo.nugetVersion) {
        throw 'Embedded release metadata does not match the canonical NuGet version.'
    }

    Write-Host "Created IsoSession SDK NuGet: $outNupkg" -ForegroundColor Cyan
    Write-Host "Release: $($releaseInfo.canonicalRelease)" -ForegroundColor Cyan
}
finally {
    $verify.Dispose()
}

Write-Output $outNupkg
