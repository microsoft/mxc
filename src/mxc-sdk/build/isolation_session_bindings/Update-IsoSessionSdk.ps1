#Requires -Version 5.1

<#
.SYNOPSIS
    Replaces MXC's pinned IsolationSession SDK package.

.DESCRIPTION
    Validates the package payload and release identity, replaces the single
    checked-in package, and regenerates GENERATION_INFO.toml from the package.
    The script fails before modifying the destination when the package is
    incomplete or internally inconsistent.

.PARAMETER PackagePath
    Path to Microsoft.Windows.AI.IsolationSession.SDK.<version>.nupkg.

.PARAMETER DestinationDirectory
    MXC's external\windows-sdk\isolation-session directory. Defaults to the
    directory containing this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $PackagePath,

    [string] $DestinationDirectory = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$package = Get-Item -LiteralPath $PackagePath -ErrorAction Stop
if ($package.Extension -ine '.nupkg') {
    throw "PackagePath must identify a .nupkg file: '$PackagePath'."
}

if (-not (Test-Path -LiteralPath $DestinationDirectory -PathType Container)) {
    throw "DestinationDirectory does not exist: '$DestinationDirectory'."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

function Get-ZipEntryBytes {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchive] $Archive,

        [Parameter(Mandatory = $true)]
        [string] $EntryName
    )

    $entry = $Archive.Entries |
        Where-Object { $_.FullName.Replace('\', '/') -ieq $EntryName } |
        Select-Object -First 1
    if (-not $entry) {
        throw "Package is missing required entry '$EntryName'."
    }

    $stream = $entry.Open()
    try {
        $memory = [System.IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            return $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Convert-BytesToText {
    param([byte[]] $Bytes)

    return [System.Text.UTF8Encoding]::new($true).GetString($Bytes).TrimStart([char]0xFEFF)
}

function Get-TomlString {
    param(
        [string] $Content,
        [string[]] $Names,
        [switch] $Optional
    )

    foreach ($name in $Names) {
        $match = [regex]::Match(
            $Content,
            "(?m)^\s*$([regex]::Escape($name))\s*=\s*`"([^`"]*)`"\s*$")
        if ($match.Success) {
            return $match.Groups[1].Value
        }
    }

    if ($Optional) {
        return ''
    }

    throw "Package GENERATION_INFO.toml is missing '$($Names -join "' or '")'."
}

function Get-Sha256 {
    param([byte[]] $Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
}

$archive = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
try {
    $nuspecEntry = $archive.Entries |
        Where-Object { $_.FullName -like '*.nuspec' } |
        Select-Object -First 1
    if (-not $nuspecEntry) {
        throw 'Package is missing its .nuspec metadata.'
    }

    $nuspecBytes = Get-ZipEntryBytes -Archive $archive -EntryName $nuspecEntry.FullName
    [xml] $nuspec = Convert-BytesToText -Bytes $nuspecBytes
    $packageId = [string] $nuspec.package.metadata.id
    $packageVersion = [string] $nuspec.package.metadata.version
    if ($packageId -ne 'Microsoft.Windows.AI.IsolationSession.SDK') {
        throw "Unexpected package id '$packageId'."
    }
    if ($packageVersion -notmatch '^0\.(\d{2}|20\d{2})(0[1-9]|1[0-2])\.(\d+)$') {
        throw "Unexpected package version '$packageVersion'; expected 0.YYMM.patch or 0.YYYYMM.patch."
    }

    $year = $Matches[1]
    $yearShort = $year.Substring($year.Length - 2)
    $month = $Matches[2]
    $runtimeVersionExpected = "20${yearShort}_$month"
    $canonicalFileName = "$packageId.$packageVersion.nupkg"

    $requiredEntries = @(
        'metadata/windows.ai.isolationsession.winmd',
        'metadata/windows.ai.isolationsession.preview.winmd',
        'metadata/GENERATION_INFO.toml',
        'runtime/IsoSessionApp.dll',
        'runtime/IsoSessionApp.runtimeversion'
    )
    foreach ($entryName in $requiredEntries) {
        [void] (Get-ZipEntryBytes -Archive $archive -EntryName $entryName)
    }

    $runtimeVersion = Convert-BytesToText (
        Get-ZipEntryBytes -Archive $archive -EntryName 'runtime/IsoSessionApp.runtimeversion')
    $runtimeVersion = $runtimeVersion.Trim()
    if ($runtimeVersion -ne $runtimeVersionExpected) {
        throw "Runtime sidecar '$runtimeVersion' does not match package version '$packageVersion' (expected '$runtimeVersionExpected')."
    }

    $packageGenerationInfo = Convert-BytesToText (
        Get-ZipEntryBytes -Archive $archive -EntryName 'metadata/GENERATION_INFO.toml')
    $targetWindowsCrate = Get-TomlString `
        -Content $packageGenerationInfo `
        -Names 'target_windows_crate'
    $windowsBindgen = Get-TomlString `
        -Content $packageGenerationInfo `
        -Names @('windows_bindgen', 'windows_bindgen_version')
    $instance = Get-TomlString -Content $packageGenerationInfo -Names 'instance'
    $osBuild = Get-TomlString `
        -Content $packageGenerationInfo `
        -Names 'os_build' `
        -Optional
    $buildGuid = Get-TomlString `
        -Content $packageGenerationInfo `
        -Names 'build_guid' `
        -Optional
    $generatedTimestamp = Get-TomlString `
        -Content $packageGenerationInfo `
        -Names 'generated_utc' `
        -Optional
    $generatedDateValue = Get-TomlString `
        -Content $packageGenerationInfo `
        -Names 'generated_date' `
        -Optional
    $releaseGeneratedTimestamp = ''
    $releaseInfoEntry = $archive.Entries |
        Where-Object { $_.FullName.Replace('\', '/') -ieq 'metadata/RELEASE_INFO.json' } |
        Select-Object -First 1
    if ($releaseInfoEntry) {
        $releaseInfoBytes = Get-ZipEntryBytes `
            -Archive $archive `
            -EntryName $releaseInfoEntry.FullName
        $releaseInfoText = Convert-BytesToText -Bytes $releaseInfoBytes
        $releaseTimestampMatch = [regex]::Match(
            $releaseInfoText,
            '"generatedUtc"\s*:\s*"([^"]+)"')
        if ($releaseTimestampMatch.Success) {
            $releaseGeneratedTimestamp = $releaseTimestampMatch.Groups[1].Value
        }
    }
    $validInstances = @(
        "$yearShort$month",
        "20$yearShort.$month"
    )
    if ($instance -notin $validInstances) {
        throw "Package instance '$instance' does not match package version '$packageVersion'."
    }

    $previewBytes = Get-ZipEntryBytes `
        -Archive $archive `
        -EntryName 'metadata/windows.ai.isolationsession.preview.winmd'
    $previewHash = Get-Sha256 -Bytes $previewBytes
}
finally {
    $archive.Dispose()
}

$destinationPackage = Join-Path $DestinationDirectory $canonicalFileName
$sourceResolved = $package.FullName
$destinationResolved = [System.IO.Path]::GetFullPath($destinationPackage)
if ($sourceResolved -ine $destinationResolved) {
    $temporaryPackage = "$destinationPackage.new"
    try {
        Copy-Item -LiteralPath $sourceResolved -Destination $temporaryPackage -Force
        Get-ChildItem -LiteralPath $DestinationDirectory -Filter '*.nupkg' -File |
            Where-Object { $_.FullName -ine $temporaryPackage } |
            Remove-Item -Force
        Move-Item -LiteralPath $temporaryPackage -Destination $destinationPackage -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPackage) {
            Remove-Item -LiteralPath $temporaryPackage -Force
        }
    }
}
else {
    Get-ChildItem -LiteralPath $DestinationDirectory -Filter '*.nupkg' -File |
        Where-Object { $_.FullName -ine $destinationResolved } |
        Remove-Item -Force
}

# Cargo build scripts track this package by timestamp. Refresh it even when a
# corrected package reuses the same version and canonical file name.
(Get-Item -LiteralPath $destinationPackage).LastWriteTimeUtc = [DateTime]::UtcNow

$parsedGeneratedDate = [DateTimeOffset]::MinValue
if ($releaseGeneratedTimestamp -and
    [DateTimeOffset]::TryParse($releaseGeneratedTimestamp, [ref] $parsedGeneratedDate)) {
    $generatedDate = $parsedGeneratedDate.UtcDateTime.ToString('yyyy-MM-dd')
}
elseif ($generatedTimestamp -and
    [DateTimeOffset]::TryParse($generatedTimestamp, [ref] $parsedGeneratedDate)) {
    $generatedDate = $parsedGeneratedDate.UtcDateTime.ToString('yyyy-MM-dd')
}
elseif ($generatedDateValue -and
    [DateTimeOffset]::TryParse($generatedDateValue, [ref] $parsedGeneratedDate)) {
    $generatedDate = $parsedGeneratedDate.UtcDateTime.ToString('yyyy-MM-dd')
}
else {
    throw 'Package GENERATION_INFO.toml has no valid generated_utc or generated_date value.'
}
$generationInfo = @"
# Provenance for the isolation_session_bindings crate.
#
# Bindings are regenerated at build time from the Preview WinMD in the pinned
# SDK package. Run Update-IsoSessionSdk.ps1 rather than editing this file.

[tool]
windows_bindgen_version = "$windowsBindgen"
target_windows_crate = "$targetWindowsCrate"
generated_date = "$generatedDate"

[source]
nupkg = "$canonicalFileName"
winmd = "metadata/windows.ai.isolationsession.preview.winmd"
winmd_sha256 = "$previewHash"
namespace = "Windows.AI.IsolationSession.Preview"
runtime_version = "$runtimeVersion"
"@
if ($osBuild) {
    $generationInfo += "`nos_build = `"$osBuild`""
}
if ($buildGuid) {
    $generationInfo += "`nbuild_guid = `"$buildGuid`""
}

$generationInfoPath = Join-Path $DestinationDirectory 'GENERATION_INFO.toml'
Set-Content -LiteralPath $generationInfoPath -Value $generationInfo -Encoding UTF8

[pscustomobject][ordered]@{
    Package = $destinationPackage
    PackageSha256 = (Get-FileHash -LiteralPath $destinationPackage -Algorithm SHA256).Hash
    PreviewWinmdSha256 = $previewHash
    OsBuild = $osBuild
    BuildGuid = $buildGuid
    RuntimeVersion = $runtimeVersion
}
