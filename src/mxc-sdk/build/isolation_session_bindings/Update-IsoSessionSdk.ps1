#Requires -Version 5.1

<#
.SYNOPSIS
    Updates MXC's pinned IsolationSession SDK package metadata.

.DESCRIPTION
    Validates the package payload and release identity, updates MXC's package
    version and SHA-256 pin, and regenerates GENERATION_INFO.toml. The package
    itself is not copied into the repository. The script fails before modifying
    tracked files when the package is incomplete or internally inconsistent.

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
    if ($packageVersion -notmatch '^0\.(20\d{2})(0[1-9]|1[0-2])\.(\d+)$') {
        throw "Unexpected package version '$packageVersion'; expected 0.YYYYMM.patch."
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
        'runtime/IsoSession.manifest'
    )
    foreach ($entryName in $requiredEntries) {
        [void] (Get-ZipEntryBytes -Archive $archive -EntryName $entryName)
    }

    $runtimeVersion = $runtimeVersionExpected
    $runtimeInstance = $runtimeVersion.Replace('_', '.')
    $runtimeManifest = Convert-BytesToText (
        Get-ZipEntryBytes -Archive $archive -EntryName 'runtime/IsoSession.manifest')
    if ($runtimeManifest -match '\$\(MonthId\)' -or
        $runtimeManifest -notmatch [regex]::Escape("name=`"$runtimeInstance`"")) {
        throw "Runtime manifest does not match package version '$packageVersion' (expected instance '$runtimeInstance')."
    }
    foreach ($requiredFragment in @(
            '<assemblyIdentity name="IsoSession.Runtime"',
            '<file name="IsoSessionApp.dll"')) {
        if ($runtimeManifest -notmatch [regex]::Escape($requiredFragment)) {
            throw "Runtime manifest is missing '$requiredFragment'."
        }
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

$packageHash = (Get-FileHash -LiteralPath $package.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $DestinationDirectory '..\..\..'))
$pinPath = Join-Path $repositoryRoot 'src\core\mxc_build_common\src\lib.rs'
if (-not (Test-Path -LiteralPath $pinPath -PathType Leaf)) {
    throw "IsolationSession SDK pin file does not exist: '$pinPath'."
}

$pinContent = [System.IO.File]::ReadAllText($pinPath)
$versionPattern = 'pub const PACKAGE_VERSION: &str = "[^"]+";'
$hashPattern = 'pub const PACKAGE_SHA256: &str =\s*"[^"]+";'
if ([regex]::Matches($pinContent, $versionPattern).Count -ne 1) {
    throw "Expected exactly one PACKAGE_VERSION pin in '$pinPath'."
}
if ([regex]::Matches($pinContent, $hashPattern).Count -ne 1) {
    throw "Expected exactly one PACKAGE_SHA256 pin in '$pinPath'."
}

$pinContent = [regex]::Replace(
    $pinContent,
    $versionPattern,
    "pub const PACKAGE_VERSION: &str = `"$packageVersion`";")
$pinContent = [regex]::Replace(
    $pinContent,
    $hashPattern,
    "pub const PACKAGE_SHA256: &str =`n        `"$packageHash`";")

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
$utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($pinPath, $pinContent, $utf8WithoutBom)
[System.IO.File]::WriteAllText(
    $generationInfoPath,
    "$generationInfo`n",
    $utf8WithoutBom)

[pscustomobject][ordered]@{
    Package = $package.FullName
    PackageSha256 = $packageHash
    PackageVersion = $packageVersion
    PreviewWinmdSha256 = $previewHash
    OsBuild = $osBuild
    BuildGuid = $buildGuid
    RuntimeVersion = $runtimeVersion
}
