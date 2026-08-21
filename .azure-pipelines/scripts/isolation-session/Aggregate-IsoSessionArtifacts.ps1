#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$X64ArtifactDirectory,

    [Parameter(Mandatory = $true)]
    [string]$Arm64ArtifactDirectory,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

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

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
$releaseInfoScript = Join-Path $repoRoot 'packaging\isolation-session\common\Get-IsoSessionReleaseInfo.ps1'
$packScript = Join-Path $repoRoot 'packaging\isolation-session\nuget\pack.ps1'
$artifactManifestScript = Join-Path $PSScriptRoot 'New-IsoSessionArtifactManifest.ps1'

foreach ($path in @($releaseInfoScript, $packScript, $artifactManifestScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required script not found: '$path'."
    }
}

$releaseInfo = & $releaseInfoScript -MonthId $MonthId -Patch $Patch
$monthUnderscore = $releaseInfo.monthUnderscore
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Get-MsiProductVersion {
    param([string]$Path)

    $installerCom = $null
    $database = $null
    $view = $null
    $record = $null
    try {
        $installerCom = New-Object -ComObject WindowsInstaller.Installer
        $database = $installerCom.OpenDatabase($Path, 0)
        $view = $database.OpenView(
            "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'ProductVersion'")
        $view.Execute()
        $record = $view.Fetch()
        if (-not $record) {
            throw "MSI '$Path' has no ProductVersion property."
        }
        $record.StringData(1)
    }
    finally {
        foreach ($comObject in @($record, $view, $database, $installerCom)) {
            if ($comObject) {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($comObject)
            }
        }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Get-RequiredFileHash {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Expected file not found: '$Path'."
    }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ArchArtifactState {
    param(
        [string]$Arch,
        [string]$ArtifactDirectory
    )

    if (-not (Test-Path -LiteralPath $ArtifactDirectory -PathType Container)) {
        throw "Artifact directory not found for ${Arch}: '$ArtifactDirectory'."
    }

    $sourceManifestPath = Join-Path $ArtifactDirectory 'source-manifest.json'
    $signatureVerificationPath = Join-Path $ArtifactDirectory 'signature-verification.json'
    $releaseContractPath = Join-Path $ArtifactDirectory 'release-contract.json'
    foreach ($path in @($sourceManifestPath, $signatureVerificationPath, $releaseContractPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Expected $Arch artifact metadata file missing: '$path'."
        }
    }

    $sourceManifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json
    $signatureVerification = Get-Content -LiteralPath $signatureVerificationPath -Raw |
        ConvertFrom-Json
    $releaseContract = Get-Content -LiteralPath $releaseContractPath -Raw | ConvertFrom-Json
    if ($sourceManifest.arch -ne $Arch) {
        throw "Source manifest architecture '$($sourceManifest.arch)' does not match '$Arch'."
    }
    if ($releaseContract.canonicalRelease -ne $releaseInfo.canonicalRelease) {
        throw "Release contract for $Arch does not match '$($releaseInfo.canonicalRelease)'."
    }
    if ($releaseContract.nugetVersion -ne $releaseInfo.nugetVersion -or
        $releaseContract.msiVersion -ne $releaseInfo.msiVersion) {
        throw "Release contract versions for $Arch do not match the canonical release contract."
    }

    $binDirectory = Join-Path $ArtifactDirectory "bin\$Arch"
    if (-not (Test-Path -LiteralPath $binDirectory -PathType Container)) {
        throw "Staged payload directory not found for ${Arch}: '$binDirectory'."
    }

    foreach ($entry in @($sourceManifest.files)) {
        $path = Join-Path $binDirectory $entry.name
        $hash = Get-RequiredFileHash -Path $path
        if ($entry.kind -eq 'winmd' -or $SigningMode -eq 'unsigned') {
            if ($hash -ne $entry.sha256) {
                throw "Payload hash mismatch for $Arch '$($entry.name)'."
            }
            continue
        }

        $signatureRecord = @(
            $signatureVerification |
                Where-Object { $_.name -eq $entry.name })
        if ($signatureRecord.Count -ne 1) {
            throw "Expected one signature record for $Arch '$($entry.name)'; found $($signatureRecord.Count)."
        }
        if ($signatureRecord[0].status -ne 'Valid') {
            throw "Signature record for $Arch '$($entry.name)' is not valid."
        }
        if ($signatureRecord[0].sha256 -ne $hash) {
            throw "Signed payload hash mismatch for $Arch '$($entry.name)'."
        }
    }

    $msiPath = Join-Path $ArtifactDirectory "IsoSession_${monthUnderscore}_${Arch}.msi"
    $bundlePath = Join-Path $ArtifactDirectory "IsoSessionSetup_${monthUnderscore}_${Arch}.exe"
    $clientManifestPath = Join-Path $ArtifactDirectory "IsoSessionClient_${monthUnderscore}_${Arch}.manifest"
    foreach ($path in @($msiPath, $bundlePath, $clientManifestPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Expected $Arch packaged output missing: '$path'."
        }
    }

    $msiVersion = Get-MsiProductVersion -Path $msiPath
    if ($msiVersion -ne $releaseInfo.msiVersion) {
        throw "MSI ProductVersion '$msiVersion' for $Arch does not match '$($releaseInfo.msiVersion)'."
    }

    $bundleVersion = (Get-Item -LiteralPath $bundlePath).VersionInfo.FileVersion
    if ($bundleVersion -ne $releaseInfo.bundleVersion) {
        throw "Bundle version '$bundleVersion' for $Arch does not match '$($releaseInfo.bundleVersion)'."
    }

    [pscustomobject][ordered]@{
        arch = $Arch
        artifactDirectory = $ArtifactDirectory
        binDirectory = $binDirectory
        sourceManifestPath = $sourceManifestPath
        sourceManifest = $sourceManifest
        signatureVerificationPath = $signatureVerificationPath
        signatureVerification = $signatureVerification
        releaseContractPath = $releaseContractPath
        msiPath = $msiPath
        bundlePath = $bundlePath
        clientManifestPath = $clientManifestPath
        msiHash = Get-RequiredFileHash -Path $msiPath
        bundleHash = Get-RequiredFileHash -Path $bundlePath
        clientManifestHash = Get-RequiredFileHash -Path $clientManifestPath
        msiVersion = $msiVersion
        bundleVersion = $bundleVersion
    }
}

$x64State = Get-ArchArtifactState -Arch 'x64' -ArtifactDirectory $X64ArtifactDirectory
$arm64State = Get-ArchArtifactState -Arch 'arm64' -ArtifactDirectory $Arm64ArtifactDirectory

if ($x64State.sourceManifest.buildGuid -ne $arm64State.sourceManifest.buildGuid) {
    throw "BuildGuid mismatch across architectures: x64='$($x64State.sourceManifest.buildGuid)', arm64='$($arm64State.sourceManifest.buildGuid)'."
}
if ($x64State.sourceManifest.osBranch -ne $arm64State.sourceManifest.osBranch) {
    throw "OS branch mismatch across architectures: x64='$($x64State.sourceManifest.osBranch)', arm64='$($arm64State.sourceManifest.osBranch)'."
}

foreach ($winmdName in @('windows.ai.isolationsession.winmd', 'windows.ai.isolationsession.preview.winmd')) {
    $x64Winmd = @($x64State.sourceManifest.files | Where-Object { $_.name -eq $winmdName })
    $arm64Winmd = @($arm64State.sourceManifest.files | Where-Object { $_.name -eq $winmdName })
    if ($x64Winmd.Count -ne 1 -or $arm64Winmd.Count -ne 1) {
        throw "WinMD '$winmdName' was not found exactly once in both source manifests."
    }
}

$releaseMetadata = [ordered]@{
    schema = 'mxc.isosession-sdk-release/1'
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    package = [ordered]@{
        id = $releaseInfo.packageId
        version = $releaseInfo.nugetVersion
        fileName = $releaseInfo.nugetPackageFileName
    }
    release = $releaseInfo
    source = [ordered]@{
        buildGuid = $x64State.sourceManifest.buildGuid
        osBranch = $x64State.sourceManifest.osBranch
        winmds = @(
            foreach ($winmdName in @('windows.ai.isolationsession.winmd', 'windows.ai.isolationsession.preview.winmd')) {
                $x64Record = @($x64State.sourceManifest.files | Where-Object { $_.name -eq $winmdName })[0]
                $arm64Record = @($arm64State.sourceManifest.files | Where-Object { $_.name -eq $winmdName })[0]
                [ordered]@{
                    name = $winmdName
                    sha256 = $x64Record.sha256
                    sizeBytes = $x64Record.sizeBytes
                    selectedArchitecture = 'x64'
                    x64 = [ordered]@{
                        dropName = $x64State.sourceManifest.dropName
                        flavor = $x64State.sourceManifest.flavor
                        relativeSourcePath = $x64Record.relativeSourcePath
                        sha256 = $x64Record.sha256
                        sizeBytes = $x64Record.sizeBytes
                    }
                    arm64 = [ordered]@{
                        dropName = $arm64State.sourceManifest.dropName
                        flavor = $arm64State.sourceManifest.flavor
                        relativeSourcePath = $arm64Record.relativeSourcePath
                        sha256 = $arm64Record.sha256
                        sizeBytes = $arm64Record.sizeBytes
                    }
                }
            })
        payloads = [ordered]@{
            x64 = [ordered]@{
                arch = 'x64'
                dropName = $x64State.sourceManifest.dropName
                flavor = $x64State.sourceManifest.flavor
                isoSessionAppSha256 = Get-RequiredFileHash -Path (
                    Join-Path $x64State.binDirectory 'IsoSessionApp.dll')
            }
            arm64 = [ordered]@{
                arch = 'arm64'
                dropName = $arm64State.sourceManifest.dropName
                flavor = $arm64State.sourceManifest.flavor
                isoSessionAppSha256 = Get-RequiredFileHash -Path (
                    Join-Path $arm64State.binDirectory 'IsoSessionApp.dll')
            }
        }
    }
    installers = [ordered]@{
        x64 = [ordered]@{
            msi = [ordered]@{
                fileName = [System.IO.Path]::GetFileName($x64State.msiPath)
                sha256 = $x64State.msiHash
                productVersion = $x64State.msiVersion
            }
            bundle = [ordered]@{
                fileName = [System.IO.Path]::GetFileName($x64State.bundlePath)
                sha256 = $x64State.bundleHash
                fileVersion = $x64State.bundleVersion
            }
            clientManifest = [ordered]@{
                fileName = [System.IO.Path]::GetFileName($x64State.clientManifestPath)
                sha256 = $x64State.clientManifestHash
            }
        }
        arm64 = [ordered]@{
            msi = [ordered]@{
                fileName = [System.IO.Path]::GetFileName($arm64State.msiPath)
                sha256 = $arm64State.msiHash
                productVersion = $arm64State.msiVersion
            }
            bundle = [ordered]@{
                fileName = [System.IO.Path]::GetFileName($arm64State.bundlePath)
                sha256 = $arm64State.bundleHash
                fileVersion = $arm64State.bundleVersion
            }
            clientManifest = [ordered]@{
                fileName = [System.IO.Path]::GetFileName($arm64State.clientManifestPath)
                sha256 = $arm64State.clientManifestHash
            }
        }
    }
}

$releaseMetadataPath = Join-Path $OutDir 'release-metadata.json'
$releaseMetadata | ConvertTo-Json -Depth 20 |
    Set-Content -LiteralPath $releaseMetadataPath -Encoding UTF8

$nupkg = & $packScript `
    -X64BinDir $x64State.binDirectory `
    -Arm64BinDir $arm64State.binDirectory `
    -MetadataDir $x64State.binDirectory `
    -ReleaseMetadataPath $releaseMetadataPath `
    -OutDir $OutDir `
    -MonthId $MonthId `
    -Patch $Patch
if (-not $nupkg -or -not (Test-Path -LiteralPath $nupkg -PathType Leaf)) {
    throw 'The aggregated IsoSession SDK NuGet was not produced.'
}

foreach ($state in @($x64State, $arm64State)) {
    foreach ($path in @($state.msiPath, $state.bundlePath, $state.clientManifestPath)) {
        Copy-Item -LiteralPath $path -Destination $OutDir -Force
    }

    $provenanceDirectory = Join-Path $OutDir "provenance\$($state.arch)"
    New-Item -ItemType Directory -Force -Path $provenanceDirectory | Out-Null
    Copy-Item -LiteralPath $state.sourceManifestPath -Destination (Join-Path $provenanceDirectory 'source-manifest.json') -Force
    Copy-Item -LiteralPath $state.signatureVerificationPath -Destination (Join-Path $provenanceDirectory 'signature-verification.json') -Force
    Copy-Item -LiteralPath $state.releaseContractPath -Destination (Join-Path $provenanceDirectory 'release-contract.json') -Force
}

& $artifactManifestScript `
    -ArtifactDirectory $OutDir `
    -MonthId $MonthId `
    -Patch $Patch `
    -SigningMode $SigningMode `
    -RedistributionApproved:$RedistributionApproved

Write-Host "Aggregated IsoSession artifacts: $OutDir" -ForegroundColor Cyan
Write-Host "Release: $($releaseInfo.canonicalRelease)" -ForegroundColor Cyan
