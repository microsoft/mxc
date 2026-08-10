#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceManifest,

    [Parameter(Mandatory = $true)]
    [string]$ArtifactDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}\.\d{2}$')]
    [string]$MonthId,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 65535)]
    [int]$Patch,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string]$ArchTag,

    [Parameter(Mandatory = $true)]
    [string]$BasePackageId,

    [Parameter(Mandatory = $true)]
    [string]$BasePackageVersion,

    [ValidateSet('test', 'production', 'unsigned')]
    [string]$SigningMode = 'test',

    [switch]$RedistributionApproved
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $SourceManifest -PathType Leaf)) {
    throw "Source manifest not found: '$SourceManifest'."
}
if (-not (Test-Path -LiteralPath $ArtifactDirectory -PathType Container)) {
    throw "Artifact directory not found: '$ArtifactDirectory'."
}

$source = Get-Content -LiteralPath $SourceManifest -Raw | ConvertFrom-Json
$files = @(
    Get-ChildItem -LiteralPath $ArtifactDirectory -File |
        Where-Object { $_.Extension -in @('.nupkg', '.msi', '.exe', '.manifest') } |
        Sort-Object Name |
        ForEach-Object {
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
                sizeBytes = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                authenticode = $signature
            }
        })

if ($files.Count -lt 3) {
    throw "Expected NuGet, MSI, and EXE outputs in '$ArtifactDirectory'."
}

$nupkgs = @(Get-ChildItem -LiteralPath $ArtifactDirectory -File -Filter '*.nupkg')
if ($nupkgs.Count -ne 1) {
    throw "Expected exactly one NuGet package in '$ArtifactDirectory'; found $($nupkgs.Count)."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$packageZip = [System.IO.Compression.ZipFile]::OpenRead($nupkgs[0].FullName)
try {
    $nuspecEntry = $packageZip.Entries |
        Where-Object { $_.FullName -like '*.nuspec' } |
        Select-Object -First 1
    if (-not $nuspecEntry) {
        throw "NuGet package '$($nupkgs[0].Name)' contains no nuspec."
    }
    $reader = New-Object System.IO.StreamReader($nuspecEntry.Open())
    try {
        $nuspec = $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }
}
finally {
    $packageZip.Dispose()
}

$packageIdMatch = [regex]::Match($nuspec, '<id>([^<]+)</id>')
$packageVersionMatch = [regex]::Match($nuspec, '<version>([^<]+)</version>')
if (-not $packageIdMatch.Success -or -not $packageVersionMatch.Success) {
    throw "NuGet package '$($nupkgs[0].Name)' has no package id or version."
}

$manifest = [ordered]@{
    schema = 'mxc.isosession-artifacts/1'
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    release = [ordered]@{
        monthId = $MonthId
        patch = $Patch
        arch = $ArchTag
    }
    source = $source
    nuget = [ordered]@{
        basePackageId = $BasePackageId
        basePackageVersion = $BasePackageVersion
        outputPackageId = $packageIdMatch.Groups[1].Value
        outputPackageVersion = $packageVersionMatch.Groups[1].Value
    }
    signing = [ordered]@{
        mode = $SigningMode
        productionReady = ($SigningMode -eq 'production')
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
$manifest | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $outputPath -Encoding UTF8
Write-Host "Artifact manifest: $outputPath"
