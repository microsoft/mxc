#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$InstallerDirectory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReleaseDetailsJson,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}\.\d{2}$')]
    [string]$MonthId,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 65535)]
    [int]$Patch,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+$')]
    [string]$PackageIdentifier,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PackageName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Publisher,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PackageUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$License,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LicenseUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ShortDescription,

    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string]$MinimumOSVersion = '10.0.26100.0',

    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$ManifestVersion = '1.10.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$releaseInfoScript = Join-Path $PSScriptRoot 'Get-IsoSessionReleaseInfo.ps1'
if (-not (Test-Path -LiteralPath $releaseInfoScript -PathType Leaf)) {
    $releaseInfoScript = Join-Path $PSScriptRoot '..\..\..\packaging\isolation-session\common\Get-IsoSessionReleaseInfo.ps1'
    $releaseInfoScript = [System.IO.Path]::GetFullPath($releaseInfoScript)
}
if (-not (Test-Path -LiteralPath $releaseInfoScript -PathType Leaf)) {
    throw "Release helper not found: '$releaseInfoScript'."
}

function ConvertTo-YamlSingleQuoted {
    param([Parameter(Mandatory = $true)][string]$Value)

    return "'" + $Value.Replace("'", "''") + "'"
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Lines
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($Path, $Lines, $encoding)
}

function New-DeterministicGuid {
    param([Parameter(Mandatory = $true)][string]$Name)

    $namespaceBytes = [guid]'6ba7b810-9dad-11d1-80b4-00c04fd430c8'
    $namespaceBytes = $namespaceBytes.ToByteArray()
    [array]::Reverse($namespaceBytes, 0, 4)
    [array]::Reverse($namespaceBytes, 4, 2)
    [array]::Reverse($namespaceBytes, 6, 2)

    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($Name)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hash = $sha1.ComputeHash($namespaceBytes + $nameBytes)
    }
    finally {
        $sha1.Dispose()
    }

    $guidBytes = [byte[]]$hash[0..15]
    $guidBytes[6] = ($guidBytes[6] -band 0x0F) -bor 0x50
    $guidBytes[8] = ($guidBytes[8] -band 0x3F) -bor 0x80
    [array]::Reverse($guidBytes, 0, 4)
    [array]::Reverse($guidBytes, 4, 2)
    [array]::Reverse($guidBytes, 6, 2)

    return ([guid]::new($guidBytes)).ToString('B').ToUpperInvariant()
}

try {
    $releaseDetails = $ReleaseDetailsJson | ConvertFrom-Json
}
catch {
    throw "ReleaseDetailsJson is not valid JSON: $($_.Exception.Message)"
}

if ($releaseDetails.status -ne 'pass') {
    throw "ESRP CDN release did not pass. Reported status: '$($releaseDetails.status)'."
}

$downloadLinks = @{}
foreach ($file in @($releaseDetails.files)) {
    $fileName = if ($file.PSObject.Properties.Name -contains 'name') {
        $file.name
    } else {
        $null
    }
    if ([string]::IsNullOrWhiteSpace($fileName)) {
        $fileName = if ($file.PSObject.Properties.Name -contains 'distributionRelativePath') {
            $file.distributionRelativePath
        } else {
            $null
        }
    }

    $fileDownloadDetails = if ($file.PSObject.Properties.Name -contains 'fileDownloadDetails') {
        @($file.fileDownloadDetails)
    } else {
        @()
    }
    $downloadUrl = @(
        $fileDownloadDetails |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.downloadUrl) } |
            Select-Object -First 1
    ).downloadUrl

    if (-not [string]::IsNullOrWhiteSpace($fileName) -and
        -not [string]::IsNullOrWhiteSpace($downloadUrl)) {
        $downloadLinks[[System.IO.Path]::GetFileName($fileName)] = $downloadUrl
    }
}

$releaseInfo = & $releaseInfoScript -MonthId $MonthId -Patch $Patch
$installers = foreach ($arch in @('x64', 'arm64')) {
    $fileName = "IsoSession_$($releaseInfo.monthUnderscore)_$arch.msi"
    $path = Join-Path $InstallerDirectory $fileName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Installer not found: '$path'."
    }

    $downloadUrl = $downloadLinks[$fileName]
    if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
        throw "No ESRP CDN link was returned for '$fileName'."
    }

    [pscustomobject][ordered]@{
        architecture = $arch
        fileName = $fileName
        url = $downloadUrl
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
    }
}

$packagePathSegments = $PackageIdentifier.Split('.')
$manifestDirectory = Join-Path $OutDir (
    'manifests\{0}\{1}\{2}' -f
        $packagePathSegments[0].Substring(0, 1).ToLowerInvariant(),
        ($packagePathSegments -join '\'),
        $releaseInfo.canonicalRelease)
New-Item -ItemType Directory -Path $manifestDirectory -Force | Out-Null

$quotedPackageIdentifier = ConvertTo-YamlSingleQuoted $PackageIdentifier
$quotedPackageVersion = ConvertTo-YamlSingleQuoted $releaseInfo.canonicalRelease

$versionManifest = @(
    "# yaml-language-server: `$schema=https://aka.ms/winget-manifest.version.$ManifestVersion.schema.json"
    "PackageIdentifier: $quotedPackageIdentifier"
    "PackageVersion: $quotedPackageVersion"
    "DefaultLocale: en-US"
    "ManifestType: version"
    "ManifestVersion: $ManifestVersion"
)
Write-Utf8NoBom `
    -Path (Join-Path $manifestDirectory "$PackageIdentifier.yaml") `
    -Lines $versionManifest

$localeManifest = @(
    "# yaml-language-server: `$schema=https://aka.ms/winget-manifest.defaultLocale.$ManifestVersion.schema.json"
    "PackageIdentifier: $quotedPackageIdentifier"
    "PackageVersion: $quotedPackageVersion"
    "PackageLocale: en-US"
    "Publisher: $(ConvertTo-YamlSingleQuoted $Publisher)"
    "PublisherUrl: $(ConvertTo-YamlSingleQuoted $PackageUrl)"
    "PublisherSupportUrl: $(ConvertTo-YamlSingleQuoted $PackageUrl)"
    "PackageName: $(ConvertTo-YamlSingleQuoted $PackageName)"
    "PackageUrl: $(ConvertTo-YamlSingleQuoted $PackageUrl)"
    "License: $(ConvertTo-YamlSingleQuoted $License)"
    "LicenseUrl: $(ConvertTo-YamlSingleQuoted $LicenseUrl)"
    "Copyright: $(ConvertTo-YamlSingleQuoted 'Copyright (c) Microsoft Corporation')"
    "ShortDescription: $(ConvertTo-YamlSingleQuoted $ShortDescription)"
    "Tags:"
    "- isolation"
    "- sandbox"
    "- windows-ai"
    "ManifestType: defaultLocale"
    "ManifestVersion: $ManifestVersion"
)
Write-Utf8NoBom `
    -Path (Join-Path $manifestDirectory "$PackageIdentifier.locale.en-US.yaml") `
    -Lines $localeManifest

$upgradeCode = New-DeterministicGuid "IsoSession:$MonthId"
$installerManifest = [System.Collections.Generic.List[string]]::new()
$installerManifest.Add("# yaml-language-server: `$schema=https://aka.ms/winget-manifest.installer.$ManifestVersion.schema.json")
$installerManifest.Add("PackageIdentifier: $quotedPackageIdentifier")
$installerManifest.Add("PackageVersion: $quotedPackageVersion")
$installerManifest.Add("InstallerLocale: en-US")
$installerManifest.Add("Platform:")
$installerManifest.Add("- Windows.Desktop")
$installerManifest.Add("MinimumOSVersion: $MinimumOSVersion")
$installerManifest.Add("InstallerType: msi")
$installerManifest.Add("Scope: machine")
$installerManifest.Add("InstallModes:")
$installerManifest.Add("- silent")
$installerManifest.Add("- silentWithProgress")
$installerManifest.Add("UpgradeBehavior: install")
$installerManifest.Add("AppsAndFeaturesEntries:")
$installerManifest.Add("- DisplayName: $(ConvertTo-YamlSingleQuoted "IsolationSession Service $MonthId")")
$installerManifest.Add("  Publisher: $(ConvertTo-YamlSingleQuoted $Publisher)")
$installerManifest.Add("  DisplayVersion: $(ConvertTo-YamlSingleQuoted $releaseInfo.msiVersion)")
$installerManifest.Add("  UpgradeCode: $(ConvertTo-YamlSingleQuoted $upgradeCode)")
$installerManifest.Add("Installers:")
foreach ($installer in $installers) {
    $installerManifest.Add("  - Architecture: $($installer.architecture)")
    $installerManifest.Add("    InstallerUrl: $(ConvertTo-YamlSingleQuoted $installer.url)")
    $installerManifest.Add("    InstallerSha256: $($installer.sha256)")
}
$installerManifest.Add("ManifestType: installer")
$installerManifest.Add("ManifestVersion: $ManifestVersion")
Write-Utf8NoBom `
    -Path (Join-Path $manifestDirectory "$PackageIdentifier.installer.yaml") `
    -Lines $installerManifest.ToArray()

$releaseSummary = [pscustomobject][ordered]@{
    schema = 'mxc.isosession-winget-release/1'
    packageIdentifier = $PackageIdentifier
    packageVersion = $releaseInfo.canonicalRelease
    manifestDirectory = $manifestDirectory
    upgradeCode = $upgradeCode
    installers = @($installers)
}
$releaseSummaryJson = $releaseSummary | ConvertTo-Json -Depth 10
Write-Utf8NoBom `
    -Path (Join-Path $OutDir 'winget-release.json') `
    -Lines @($releaseSummaryJson)

Write-Host "Generated WinGet manifests for $PackageIdentifier $($releaseInfo.canonicalRelease)."
Write-Host "Manifest directory: $manifestDirectory"
foreach ($installer in $installers) {
    Write-Host "$($installer.architecture): $($installer.url) ($($installer.sha256))"
}
