#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}\.\d{2}$')]
    [string]$MonthId,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 65535)]
    [int]$Patch,

    [ValidateSet('test', 'production', 'unsigned')]
    [string]$SigningMode = 'test',

    [switch]$RedistributionApproved
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ArtifactDirectory -PathType Container)) {
    throw "Artifact directory not found: '$ArtifactDirectory'."
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
$releaseInfoScript = Join-Path $repoRoot 'packaging\isolation-session\common\Get-IsoSessionReleaseInfo.ps1'
if (-not (Test-Path -LiteralPath $releaseInfoScript -PathType Leaf)) {
    throw "Release helper not found: '$releaseInfoScript'."
}

$releaseInfo = & $releaseInfoScript -MonthId $MonthId -Patch $Patch
$releaseMetadataPath = Join-Path $ArtifactDirectory 'release-metadata.json'
if (-not (Test-Path -LiteralPath $releaseMetadataPath -PathType Leaf)) {
    throw "Release metadata not found: '$releaseMetadataPath'."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

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

function Get-ZipEntryBytes {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$EntryName
    )

    $entry = $Archive.GetEntry($EntryName)
    if (-not $entry) {
        return $null
    }
    $stream = $entry.Open()
    try {
        $memory = [System.IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-BytesEqual {
    param(
        [byte[]]$Expected,
        [byte[]]$Actual,
        [string]$Label
    )

    if ($Expected.Length -ne $Actual.Length -or (Compare-Object $Expected $Actual -SyncWindow 0)) {
        throw "$Label bytes differ."
    }
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

function Get-InstallerRecord {
    param(
        [object]$Metadata,
        [string]$Arch,
        [string]$Kind
    )

    $archRecord = $Metadata.installers.$Arch
    if (-not $archRecord) {
        throw "Release metadata is missing installer data for '$Arch'."
    }
    $record = $archRecord.$Kind
    if (-not $record) {
        throw "Release metadata is missing '$Kind' data for '$Arch'."
    }
    $record
}

$artifactRootPath = (Resolve-Path -LiteralPath $ArtifactDirectory).Path.TrimEnd('\')
$files = @(
    Get-ChildItem -LiteralPath $ArtifactDirectory -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            $relativePath = $_.FullName.Substring($artifactRootPath.Length).TrimStart('\')
            $signature = $null
            if ($_.Extension -in @('.msi', '.exe')) {
                $authenticode = Get-AuthenticodeSignature -LiteralPath $_.FullName
                $signature = [ordered]@{
                    status = $authenticode.Status.ToString()
                    signer = if ($authenticode.SignerCertificate) {
                        $authenticode.SignerCertificate.Subject
                    }
                    else {
                        $null
                    }
                }
            }

            [ordered]@{
                name = $_.Name
                relativePath = $relativePath
                sizeBytes = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                authenticode = $signature
            }
        })

$nupkgs = @(Get-ChildItem -LiteralPath $ArtifactDirectory -File -Filter '*.nupkg')
if ($nupkgs.Count -ne 1) {
    throw "Expected exactly one NuGet package in '$ArtifactDirectory'; found $($nupkgs.Count)."
}
if ($nupkgs[0].Name -ne $releaseInfo.nugetPackageFileName) {
    throw "NuGet package '$($nupkgs[0].Name)' does not match '$($releaseInfo.nugetPackageFileName)'."
}

$standaloneReleaseMetadataBytes = [System.IO.File]::ReadAllBytes($releaseMetadataPath)
$releaseMetadata = Get-Content -LiteralPath $releaseMetadataPath -Raw | ConvertFrom-Json
if ($releaseMetadata.release.canonicalRelease -ne $releaseInfo.canonicalRelease) {
    throw 'Release metadata canonical release does not match the expected release contract.'
}
if ($releaseMetadata.package.version -ne $releaseInfo.nugetVersion) {
    throw 'Release metadata package version does not match the expected NuGet version.'
}

$packageZip = [System.IO.Compression.ZipFile]::OpenRead($nupkgs[0].FullName)
try {
    $nuspecEntry = $packageZip.Entries |
        Where-Object { $_.FullName -like '*.nuspec' } |
        Select-Object -First 1
    if (-not $nuspecEntry) {
        throw "NuGet package '$($nupkgs[0].Name)' contains no nuspec."
    }

    $nuspec = Get-ZipEntryText -Archive $packageZip -EntryName $nuspecEntry.FullName
    $packageReleaseMetadataBytes = Get-ZipEntryBytes -Archive $packageZip -EntryName 'metadata/RELEASE_INFO.json'
    if (-not $packageReleaseMetadataBytes) {
        throw "NuGet package '$($nupkgs[0].Name)' is missing metadata/RELEASE_INFO.json."
    }
    Assert-BytesEqual -Expected $standaloneReleaseMetadataBytes `
        -Actual $packageReleaseMetadataBytes `
        -Label 'Standalone and embedded release metadata'

    $generationInfo = Get-ZipEntryText -Archive $packageZip -EntryName 'metadata/GENERATION_INFO.toml'
    if (-not $generationInfo) {
        throw "NuGet package '$($nupkgs[0].Name)' is missing metadata/GENERATION_INFO.toml."
    }

    $packageIdMatch = [regex]::Match($nuspec, '<id>([^<]+)</id>')
    $packageVersionMatch = [regex]::Match($nuspec, '<version>([^<]+)</version>')
    if (-not $packageIdMatch.Success -or -not $packageVersionMatch.Success) {
        throw "NuGet package '$($nupkgs[0].Name)' has no package id or version."
    }
    if ($packageIdMatch.Groups[1].Value -ne $releaseInfo.packageId) {
        throw 'NuGet package id does not match the canonical package id.'
    }
    if ($packageVersionMatch.Groups[1].Value -ne $releaseInfo.nugetVersion) {
        throw 'NuGet package version does not match the canonical NuGet version.'
    }

    $runtimeVersion = Get-ZipEntryText -Archive $packageZip `
        -EntryName 'runtime/IsoSessionApp.runtimeversion'
    if ($runtimeVersion -ne $releaseInfo.monthUnderscore) {
        throw 'NuGet runtime-version sidecar does not match the MSI registry token.'
    }

    $comClassManifest = Get-ZipEntryText -Archive $packageZip `
        -EntryName 'runtime/IsoSessionApp.comClass.manifest'
    foreach ($clsid in @(
            '{6EF3155B-D1A2-4A34-BCAA-089F8A6D9916}',
            '{36B03FF1-21AA-4F3C-819D-2430EC830DD0}')) {
        if ($comClassManifest -notmatch [regex]::Escape($clsid)) {
            throw "NuGet COM activation manifest is missing CLSID '$clsid'."
        }
    }

    $packagedAppBytes = Get-ZipEntryBytes -Archive $packageZip `
        -EntryName 'runtime/IsoSessionApp.dll'
    if (-not $packagedAppBytes) {
        throw 'NuGet package is missing runtime/IsoSessionApp.dll.'
    }
    $packagedAppHash = Get-Sha256Hex -Bytes $packagedAppBytes
    if ($packagedAppHash -ne $releaseMetadata.source.payloads.x64.isoSessionAppSha256) {
        throw 'NuGet activation shim does not match the signed x64 OS payload.'
    }

    if ($generationInfo -notmatch [regex]::Escape("instance = `"$MonthId`"")) {
        throw 'GENERATION_INFO.toml does not carry the expected runtime instance.'
    }
    if ($generationInfo -notmatch [regex]::Escape("canonical_release = `"$($releaseInfo.canonicalRelease)`"")) {
        throw 'GENERATION_INFO.toml does not carry the expected canonical release.'
    }
    if ($generationInfo -notmatch [regex]::Escape("nuget_version = `"$($releaseInfo.nugetVersion)`"")) {
        throw 'GENERATION_INFO.toml does not carry the expected NuGet version.'
    }

    $primaryWinmdHash = Get-Sha256Hex -Bytes (Get-ZipEntryBytes -Archive $packageZip -EntryName 'metadata/windows.ai.isolationsession.winmd')
    $previewWinmdHash = Get-Sha256Hex -Bytes (Get-ZipEntryBytes -Archive $packageZip -EntryName 'metadata/windows.ai.isolationsession.preview.winmd')
    if ($primaryWinmdHash -ne (Get-ReleaseWinmdRecord -Metadata $releaseMetadata -WinmdName 'windows.ai.isolationsession.winmd').sha256) {
        throw 'Embedded primary WinMD hash does not match release metadata.'
    }
    if ($previewWinmdHash -ne (Get-ReleaseWinmdRecord -Metadata $releaseMetadata -WinmdName 'windows.ai.isolationsession.preview.winmd').sha256) {
        throw 'Embedded preview WinMD hash does not match release metadata.'
    }
}
finally {
    $packageZip.Dispose()
}

foreach ($arch in @('x64', 'arm64')) {
    foreach ($kind in @('msi', 'bundle', 'clientManifest')) {
        $record = Get-InstallerRecord -Metadata $releaseMetadata -Arch $arch -Kind $kind
        $path = Join-Path $ArtifactDirectory $record.fileName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Artifact missing from release metadata: '$path'."
        }
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $record.sha256) {
            throw "Artifact '$($record.fileName)' hash does not match release metadata."
        }
    }

    $provenanceDirectory = Join-Path $ArtifactDirectory "provenance\$arch"
    foreach ($name in @('source-manifest.json', 'signature-verification.json', 'release-contract.json')) {
        $provenancePath = Join-Path $provenanceDirectory $name
        if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) {
            throw "Expected provenance file missing: '$provenancePath'."
        }
    }
}

$signatureEvidence = [ordered]@{
    x64 = Get-Content -LiteralPath (Join-Path $ArtifactDirectory 'provenance\x64\signature-verification.json') -Raw |
        ConvertFrom-Json
    arm64 = Get-Content -LiteralPath (Join-Path $ArtifactDirectory 'provenance\arm64\signature-verification.json') -Raw |
        ConvertFrom-Json
}

if ($SigningMode -eq 'production') {
    $invalidSignedArtifacts = @(
        $files |
            Where-Object {
                $_.authenticode -and
                $_.authenticode.status -ne [System.Management.Automation.SignatureStatus]::Valid.ToString()
            })
    if ($invalidSignedArtifacts.Count -gt 0) {
        throw "Production artifact signature verification failed: $($invalidSignedArtifacts.relativePath -join ', ')."
    }

    foreach ($arch in @('x64', 'arm64')) {
        $invalidEvidence = @(
            $signatureEvidence[$arch] |
                Where-Object { $_.status -ne [System.Management.Automation.SignatureStatus]::Valid.ToString() })
        if ($invalidEvidence.Count -gt 0) {
            throw "Production signature evidence is invalid for '$arch': $($invalidEvidence.name -join ', ')."
        }
    }
}

$manifest = [ordered]@{
    schema = 'mxc.isosession-artifacts/2'
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    release = $releaseInfo
    source = $releaseMetadata.source
    nuget = [ordered]@{
        packageId = $releaseMetadata.package.id
        packageVersion = $releaseMetadata.package.version
        packageFileName = $releaseMetadata.package.fileName
        releaseMetadataEntry = 'metadata/RELEASE_INFO.json'
        generationInfoEntry = 'metadata/GENERATION_INFO.toml'
    }
    installers = $releaseMetadata.installers
    signing = [ordered]@{
        mode = $SigningMode
        productionReady = ($SigningMode -eq 'production')
        evidence = $signatureEvidence
    }
    redistribution = [ordered]@{
        winMdApprovalDocumented = [bool]$RedistributionApproved
        publicReleaseReady = (
            $RedistributionApproved -and $SigningMode -eq 'production')
    }
    artifacts = $files
    pipeline = [ordered]@{
        definition = $env:BUILD_DEFINITIONNAME
        buildId = $env:BUILD_BUILDID
        sourceVersion = $env:BUILD_SOURCEVERSION
    }
}

$outputPath = Join-Path $ArtifactDirectory 'artifact-manifest.json'
$manifest | ConvertTo-Json -Depth 20 |
    Set-Content -LiteralPath $outputPath -Encoding UTF8
Write-Host "Artifact manifest: $outputPath"
