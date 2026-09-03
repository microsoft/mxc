#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')
$manifestScript = Join-Path $repoRoot '.azure-pipelines\scripts\isolation-session\New-IsoSessionArtifactManifest.ps1'
$packScript = Join-Path $repoRoot 'packaging\isolation-session\nuget\pack.ps1'
$releaseInfoScript = Join-Path $repoRoot 'packaging\isolation-session\common\Get-IsoSessionReleaseInfo.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-manifest-test-{0}' -f ([guid]::NewGuid()))
$artifactDir = Join-Path $testRoot 'artifacts'

function New-ReleaseMetadata {
    param(
        [string]$Path,
        [object]$ReleaseInfo,
        [hashtable]$InstallerHashes
    )

    $metadata = [ordered]@{
        schema = 'mxc.isosession-sdk-release/1'
        generatedUtc = '2026-08-01T00:00:00Z'
        package = [ordered]@{
            id = $ReleaseInfo.packageId
            version = $ReleaseInfo.nugetVersion
            fileName = $ReleaseInfo.nugetPackageFileName
        }
        release = $ReleaseInfo
        source = [ordered]@{
            buildGuid = '72de6fa1-35ec-8b71-6bd4-6e74b1af57db'
            osBranch = 'ge_current_directwinpd_sf2'
            winmds = @(
                [ordered]@{
                    name = 'windows.ai.isolationsession.winmd'
                    sha256 = $InstallerHashes.primaryWinmd
                    sizeBytes = 17
                    x64 = [ordered]@{
                        dropName = 'wdg/test/amd64fre/BIN/test'
                        flavor = 'amd64fre'
                        relativeSourcePath = 'windows.ai.isolationsession.winmd'
                    }
                    arm64 = [ordered]@{
                        dropName = 'wdg/test/arm64fre/BIN/test'
                        flavor = 'arm64fre'
                        relativeSourcePath = 'windows.ai.isolationsession.winmd'
                    }
                }
                [ordered]@{
                    name = 'windows.ai.isolationsession.preview.winmd'
                    sha256 = $InstallerHashes.previewWinmd
                    sizeBytes = 25
                    x64 = [ordered]@{
                        dropName = 'wdg/test/amd64fre/BIN/test'
                        flavor = 'amd64fre'
                        relativeSourcePath = 'windows.ai.isolationsession.preview.winmd'
                    }
                    arm64 = [ordered]@{
                        dropName = 'wdg/test/arm64fre/BIN/test'
                        flavor = 'arm64fre'
                        relativeSourcePath = 'windows.ai.isolationsession.preview.winmd'
                    }
                })
            payloads = [ordered]@{
                x64 = [ordered]@{
                    arch = 'x64'
                    dropName = 'wdg/test/amd64fre/BIN/test'
                    flavor = 'amd64fre'
                    isoSessionAppSha256 = $InstallerHashes.x64App
                }
                arm64 = [ordered]@{
                    arch = 'arm64'
                    dropName = 'wdg/test/arm64fre/BIN/test'
                    flavor = 'arm64fre'
                    isoSessionAppSha256 = $InstallerHashes.arm64App
                }
            }
        }
        installers = [ordered]@{
            x64 = [ordered]@{
                msi = [ordered]@{
                    fileName = "IsoSession_$($ReleaseInfo.monthUnderscore)_x64.msi"
                    sha256 = $InstallerHashes.x64Msi
                    productVersion = $ReleaseInfo.msiVersion
                }
                bundle = [ordered]@{
                    fileName = "IsoSessionSetup_$($ReleaseInfo.monthUnderscore)_x64.exe"
                    sha256 = $InstallerHashes.x64Bundle
                    fileVersion = $ReleaseInfo.bundleVersion
                }
                clientManifest = [ordered]@{
                    fileName = "IsoSessionClient_$($ReleaseInfo.monthUnderscore)_x64.manifest"
                    sha256 = $InstallerHashes.x64Manifest
                }
            }
            arm64 = [ordered]@{
                msi = [ordered]@{
                    fileName = "IsoSession_$($ReleaseInfo.monthUnderscore)_arm64.msi"
                    sha256 = $InstallerHashes.arm64Msi
                    productVersion = $ReleaseInfo.msiVersion
                }
                bundle = [ordered]@{
                    fileName = "IsoSessionSetup_$($ReleaseInfo.monthUnderscore)_arm64.exe"
                    sha256 = $InstallerHashes.arm64Bundle
                    fileVersion = $ReleaseInfo.bundleVersion
                }
                clientManifest = [ordered]@{
                    fileName = "IsoSessionClient_$($ReleaseInfo.monthUnderscore)_arm64.manifest"
                    sha256 = $InstallerHashes.arm64Manifest
                }
            }
        }
    }

    $metadata | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

try {
    New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
    $releaseInfo = & $releaseInfoScript -MonthId '2026.08' -Patch 2

    $metadataDir = Join-Path $testRoot 'metadata'
    $x64BinDir = Join-Path $testRoot 'bin\x64'
    $arm64BinDir = Join-Path $testRoot 'bin\arm64'
    New-Item -ItemType Directory -Force -Path $metadataDir, $x64BinDir, $arm64BinDir | Out-Null

    [System.IO.File]::WriteAllBytes(
        (Join-Path $metadataDir 'windows.ai.isolationsession.winmd'),
        [System.Text.Encoding]::ASCII.GetBytes('synthetic-winmd-bytes'))
    [System.IO.File]::WriteAllBytes(
        (Join-Path $metadataDir 'windows.ai.isolationsession.preview.winmd'),
        [System.Text.Encoding]::ASCII.GetBytes('synthetic-preview-winmd-bytes'))
    [System.IO.File]::WriteAllBytes(
        (Join-Path $x64BinDir 'IsoSessionApp.dll'),
        [System.Text.Encoding]::ASCII.GetBytes('synthetic-x64-IsoSessionApp-dll'))
    [System.IO.File]::WriteAllBytes(
        (Join-Path $arm64BinDir 'IsoSessionApp.dll'),
        [System.Text.Encoding]::ASCII.GetBytes('synthetic-arm64-IsoSessionApp-dll'))

    foreach ($name in @(
        "IsoSession_$($releaseInfo.monthUnderscore)_x64.msi",
        "IsoSession_$($releaseInfo.monthUnderscore)_arm64.msi",
        "IsoSessionSetup_$($releaseInfo.monthUnderscore)_x64.exe",
        "IsoSessionSetup_$($releaseInfo.monthUnderscore)_arm64.exe",
        "IsoSessionClient_$($releaseInfo.monthUnderscore)_x64.manifest",
        "IsoSessionClient_$($releaseInfo.monthUnderscore)_arm64.manifest")) {
        Set-Content -LiteralPath (Join-Path $artifactDir $name) -Value $name -Encoding UTF8
    }

    $hashes = @{
        primaryWinmd = (Get-FileHash -LiteralPath (Join-Path $metadataDir 'windows.ai.isolationsession.winmd') -Algorithm SHA256).Hash.ToLowerInvariant()
        previewWinmd = (Get-FileHash -LiteralPath (Join-Path $metadataDir 'windows.ai.isolationsession.preview.winmd') -Algorithm SHA256).Hash.ToLowerInvariant()
        x64App = (Get-FileHash -LiteralPath (Join-Path $x64BinDir 'IsoSessionApp.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
        arm64App = (Get-FileHash -LiteralPath (Join-Path $arm64BinDir 'IsoSessionApp.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
        x64Msi = (Get-FileHash -LiteralPath (Join-Path $artifactDir "IsoSession_$($releaseInfo.monthUnderscore)_x64.msi") -Algorithm SHA256).Hash.ToLowerInvariant()
        arm64Msi = (Get-FileHash -LiteralPath (Join-Path $artifactDir "IsoSession_$($releaseInfo.monthUnderscore)_arm64.msi") -Algorithm SHA256).Hash.ToLowerInvariant()
        x64Bundle = (Get-FileHash -LiteralPath (Join-Path $artifactDir "IsoSessionSetup_$($releaseInfo.monthUnderscore)_x64.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
        arm64Bundle = (Get-FileHash -LiteralPath (Join-Path $artifactDir "IsoSessionSetup_$($releaseInfo.monthUnderscore)_arm64.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
        x64Manifest = (Get-FileHash -LiteralPath (Join-Path $artifactDir "IsoSessionClient_$($releaseInfo.monthUnderscore)_x64.manifest") -Algorithm SHA256).Hash.ToLowerInvariant()
        arm64Manifest = (Get-FileHash -LiteralPath (Join-Path $artifactDir "IsoSessionClient_$($releaseInfo.monthUnderscore)_arm64.manifest") -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $releaseMetadataPath = Join-Path $artifactDir 'release-metadata.json'
    New-ReleaseMetadata -Path $releaseMetadataPath -ReleaseInfo $releaseInfo -InstallerHashes $hashes

    & $packScript `
        -X64BinDir $x64BinDir `
        -Arm64BinDir $arm64BinDir `
        -MetadataDir $metadataDir `
        -ReleaseMetadataPath $releaseMetadataPath `
        -OutDir $artifactDir `
        -MonthId $releaseInfo.monthId `
        -Patch $releaseInfo.patch | Out-Null

    foreach ($arch in @('x64', 'arm64')) {
        $provenanceDir = Join-Path $artifactDir "provenance\$arch"
        New-Item -ItemType Directory -Force -Path $provenanceDir | Out-Null

        @{
            schema = 'mxc.isosession-os-binaries/2'
            buildGuid = '72de6fa1-35ec-8b71-6bd4-6e74b1af57db'
            arch = $arch
            files = @(
                @{
                    name = 'windows.ai.isolationsession.winmd'
                    sha256 = $hashes.primaryWinmd
                },
                @{
                    name = 'windows.ai.isolationsession.preview.winmd'
                    sha256 = $hashes.previewWinmd
                })
        } | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $provenanceDir 'source-manifest.json') -Encoding UTF8

        @(
            @{
                name = "IsoSession_$($releaseInfo.monthUnderscore)_$arch.msi"
                status = 'Unknown'
            }
        ) | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $provenanceDir 'signature-verification.json') -Encoding UTF8

        $releaseInfo | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $provenanceDir 'release-contract.json') -Encoding UTF8
    }

    & $manifestScript `
        -ArtifactDirectory $artifactDir `
        -MonthId $releaseInfo.monthId `
        -Patch $releaseInfo.patch `
        -SigningMode test

    $manifest = Get-Content (Join-Path $artifactDir 'artifact-manifest.json') -Raw |
        ConvertFrom-Json
    if ($manifest.nuget.packageVersion -ne $releaseInfo.nugetVersion) {
        throw 'Artifact manifest did not record the unified NuGet version.'
    }
    if ($manifest.release.canonicalRelease -ne $releaseInfo.canonicalRelease) {
        throw 'Artifact manifest did not record the canonical release identity.'
    }
    if ($manifest.source.buildGuid -ne '72de6fa1-35ec-8b71-6bd4-6e74b1af57db') {
        throw 'Artifact manifest did not carry BuildGuid provenance.'
    }
    if ($manifest.redistribution.publicReleaseReady) {
        throw 'Test-signed artifacts must not be marked public-release-ready.'
    }
    if (@($manifest.artifacts).Count -lt 10) {
        throw 'Artifact manifest did not enumerate the expected final outputs and provenance files.'
    }

    $productionValidationFailed = $false
    try {
        & $manifestScript `
            -ArtifactDirectory $artifactDir `
            -MonthId $releaseInfo.monthId `
            -Patch $releaseInfo.patch `
            -SigningMode production
    }
    catch {
        $productionValidationFailed =
            $_.Exception.Message -match 'Production artifact signature verification failed|Production signature evidence is invalid'
    }
    if (-not $productionValidationFailed) {
        throw 'Production signing mode did not reject non-production signature evidence.'
    }

    Write-Host 'IsoSession artifact manifest tests passed.'
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
