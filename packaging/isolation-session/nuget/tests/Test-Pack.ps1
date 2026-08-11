#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$nugetDir = Split-Path -Parent $PSScriptRoot
$repoRoot = Resolve-Path (Join-Path $nugetDir '..\..\..')
$packScript = Join-Path $nugetDir 'pack.ps1'
$releaseInfoScript = Join-Path $repoRoot 'packaging\isolation-session\common\Get-IsoSessionReleaseInfo.ps1'

if (-not (Test-Path -LiteralPath $packScript)) {
    throw "pack.ps1 not found at '$packScript'."
}
if (-not (Test-Path -LiteralPath $releaseInfoScript)) {
    throw "Get-IsoSessionReleaseInfo.ps1 not found at '$releaseInfoScript'."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mxc-isosession-pack-test-{0}" -f ([guid]::NewGuid()))
$failures = @()

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function Get-ZipEntryNames {
    param([string]$NupkgPath)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($NupkgPath)
    try {
        @($zip.Entries | ForEach-Object { $_.FullName })
    }
    finally {
        $zip.Dispose()
    }
}

function Get-ZipEntryTextFromPath {
    param([string]$NupkgPath, [string]$EntryName)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($NupkgPath)
    try {
        $entry = $zip.GetEntry($EntryName)
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
    finally {
        $zip.Dispose()
    }
}

function Get-ZipEntryBytesFromPath {
    param([string]$NupkgPath, [string]$EntryName)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($NupkgPath)
    try {
        $entry = $zip.GetEntry($EntryName)
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
    finally {
        $zip.Dispose()
    }
}

function New-ReleaseMetadata {
    param(
        [string]$Path,
        [string]$MonthId,
        [int]$Patch,
        [string]$BuildGuid = '72de6fa1-35ec-8b71-6bd4-6e74b1af57db',
        [string]$PrimaryWinmdHash,
        [string]$PreviewWinmdHash
    )

    $releaseInfo = & $releaseInfoScript -MonthId $MonthId -Patch $Patch
    $metadata = [ordered]@{
        schema = 'mxc.isosession-sdk-release/1'
        generatedUtc = '2026-08-01T00:00:00Z'
        package = [ordered]@{
            id = $releaseInfo.packageId
            version = $releaseInfo.nugetVersion
            fileName = $releaseInfo.nugetPackageFileName
        }
        release = $releaseInfo
        source = [ordered]@{
            buildGuid = $BuildGuid
            osBranch = 'ge_current_directwinpd_sf2'
            winmds = @(
                [ordered]@{
                    name = 'windows.ai.isolationsession.winmd'
                    sha256 = $PrimaryWinmdHash
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
                    sha256 = $PreviewWinmdHash
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
                    isoSessionAppSha256 = 'x64-runtime-sha'
                }
                arm64 = [ordered]@{
                    arch = 'arm64'
                    dropName = 'wdg/test/arm64fre/BIN/test'
                    flavor = 'arm64fre'
                    isoSessionAppSha256 = 'arm64-runtime-sha'
                }
            }
        }
        installers = [ordered]@{
            x64 = [ordered]@{
                msi = [ordered]@{
                    fileName = "IsoSession_$($releaseInfo.monthUnderscore)_x64.msi"
                    sha256 = 'x64-msi-sha'
                    productVersion = $releaseInfo.msiVersion
                }
                bundle = [ordered]@{
                    fileName = "IsoSessionSetup_$($releaseInfo.monthUnderscore)_x64.exe"
                    sha256 = 'x64-bundle-sha'
                    fileVersion = $releaseInfo.bundleVersion
                }
                clientManifest = [ordered]@{
                    fileName = "IsoSessionClient_$($releaseInfo.monthUnderscore)_x64.manifest"
                    sha256 = 'x64-clientmanifest-sha'
                }
            }
            arm64 = [ordered]@{
                msi = [ordered]@{
                    fileName = "IsoSession_$($releaseInfo.monthUnderscore)_arm64.msi"
                    sha256 = 'arm64-msi-sha'
                    productVersion = $releaseInfo.msiVersion
                }
                bundle = [ordered]@{
                    fileName = "IsoSessionSetup_$($releaseInfo.monthUnderscore)_arm64.exe"
                    sha256 = 'arm64-bundle-sha'
                    fileVersion = $releaseInfo.bundleVersion
                }
                clientManifest = [ordered]@{
                    fileName = "IsoSessionClient_$($releaseInfo.monthUnderscore)_arm64.manifest"
                    sha256 = 'arm64-clientmanifest-sha'
                }
            }
        }
    }

    $metadata | ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

function Test-Case {
    param(
        [string]$Name,
        [scriptblock]$Body
    )

    Write-Host "==> $Name"
    try {
        & $Body
        Write-Host '    PASS' -ForegroundColor Green
    }
    catch {
        Write-Host "    FAIL: $($_.Exception.Message)" -ForegroundColor Red
        $script:failures += "$Name : $($_.Exception.Message)"
    }
}

try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

    $monthId = '2026.06'
    $patch = 3
    $releaseInfo = & $releaseInfoScript -MonthId $monthId -Patch $patch
    $metadataDir = Join-Path $testRoot 'metadata'
    $x64BinDir = Join-Path $testRoot 'bin\x64'
    $arm64BinDir = Join-Path $testRoot 'bin\arm64'
    New-Item -ItemType Directory -Force -Path $metadataDir, $x64BinDir, $arm64BinDir | Out-Null

    $primaryWinmdBytes = [System.Text.Encoding]::ASCII.GetBytes('synthetic-winmd-bytes')
    $previewWinmdBytes = [System.Text.Encoding]::ASCII.GetBytes('synthetic-preview-winmd-bytes')
    $x64RuntimeBytes = [System.Text.Encoding]::ASCII.GetBytes('synthetic-x64-IsoSessionApp-dll')
    $arm64RuntimeBytes = [System.Text.Encoding]::ASCII.GetBytes('synthetic-arm64-IsoSessionApp-dll')

    [System.IO.File]::WriteAllBytes((Join-Path $metadataDir 'windows.ai.isolationsession.winmd'), $primaryWinmdBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $metadataDir 'windows.ai.isolationsession.preview.winmd'), $previewWinmdBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $x64BinDir 'IsoSessionApp.dll'), $x64RuntimeBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $arm64BinDir 'IsoSessionApp.dll'), $arm64RuntimeBytes)

    $primaryWinmdHash = (Get-FileHash -LiteralPath (Join-Path $metadataDir 'windows.ai.isolationsession.winmd') -Algorithm SHA256).Hash.ToLowerInvariant()
    $previewWinmdHash = (Get-FileHash -LiteralPath (Join-Path $metadataDir 'windows.ai.isolationsession.preview.winmd') -Algorithm SHA256).Hash.ToLowerInvariant()
    $releaseMetadataPath = Join-Path $testRoot 'release-metadata.json'
    New-ReleaseMetadata -Path $releaseMetadataPath `
        -MonthId $monthId `
        -Patch $patch `
        -PrimaryWinmdHash $primaryWinmdHash `
        -PreviewWinmdHash $previewWinmdHash

    Test-Case 'Happy path: multi-arch package carries both WinMDs and both runtimes' {
        $outDir = Join-Path $testRoot 'out-happy'
        & $packScript `
            -X64BinDir $x64BinDir `
            -Arm64BinDir $arm64BinDir `
            -MetadataDir $metadataDir `
            -ReleaseMetadataPath $releaseMetadataPath `
            -OutDir $outDir `
            -MonthId $monthId `
            -Patch $patch | Out-Null

        $expectedNupkg = Join-Path $outDir $releaseInfo.nugetPackageFileName
        Assert-True (Test-Path -LiteralPath $expectedNupkg) "expected output nupkg '$expectedNupkg' to exist"

        $entries = Get-ZipEntryNames -NupkgPath $expectedNupkg
        foreach ($entry in @(
                'metadata/windows.ai.isolationsession.winmd',
                'metadata/windows.ai.isolationsession.preview.winmd',
                'metadata/GENERATION_INFO.toml',
                'metadata/RELEASE_INFO.json',
                'runtimes/win-x64/native/IsoSessionApp.dll',
                'runtimes/win-x64/native/IsoSession.manifest',
                'runtimes/win-arm64/native/IsoSessionApp.dll',
                'runtimes/win-arm64/native/IsoSession.manifest')) {
            Assert-True ($entries -contains $entry) "entry '$entry' is present"
        }

        $nuspecText = Get-ZipEntryTextFromPath -NupkgPath $expectedNupkg -EntryName 'Microsoft.Windows.AI.IsolationSession.SDK.nuspec'
        Assert-True ($nuspecText -match '<id>Microsoft\.Windows\.AI\.IsolationSession\.SDK</id>') 'package id is canonical'
        Assert-True ($nuspecText -match [regex]::Escape("<version>$($releaseInfo.nugetVersion)</version>")) 'package version includes the patch'

        foreach ($rid in @('win-x64', 'win-arm64')) {
            $manifestText = Get-ZipEntryTextFromPath -NupkgPath $expectedNupkg -EntryName "runtimes/$rid/native/IsoSession.manifest"
            Assert-True ($manifestText -match [regex]::Escape("name=`"$monthId`"")) "$rid manifest stamped with MonthId"
        }

        $releaseMetadata = Get-ZipEntryTextFromPath -NupkgPath $expectedNupkg -EntryName 'metadata/RELEASE_INFO.json' |
            ConvertFrom-Json
        Assert-True ($releaseMetadata.source.buildGuid -eq '72de6fa1-35ec-8b71-6bd4-6e74b1af57db') 'release metadata preserves BuildGuid provenance'
        Assert-True ($releaseMetadata.installers.x64.msi.fileName -eq 'IsoSession_2026_06_x64.msi') 'release metadata carries x64 MSI linkage'
        Assert-True ($releaseMetadata.installers.arm64.bundle.fileName -eq 'IsoSessionSetup_2026_06_arm64.exe') 'release metadata carries arm64 bundle linkage'
    }

    Test-Case 'Generation info records the release identity and WinMD hashes' {
        $outDir = Join-Path $testRoot 'out-generation-info'
        & $packScript `
            -X64BinDir $x64BinDir `
            -Arm64BinDir $arm64BinDir `
            -MetadataDir $metadataDir `
            -ReleaseMetadataPath $releaseMetadataPath `
            -OutDir $outDir `
            -MonthId $monthId `
            -Patch $patch | Out-Null

        $outNupkg = Join-Path $outDir $releaseInfo.nugetPackageFileName
        $generationInfo = Get-ZipEntryTextFromPath -NupkgPath $outNupkg -EntryName 'metadata/GENERATION_INFO.toml'
        Assert-True ($generationInfo -match [regex]::Escape("instance = `"$monthId`"")) 'runtime instance is preserved'
        Assert-True ($generationInfo -match [regex]::Escape("canonical_release = `"$($releaseInfo.canonicalRelease)`"")) 'canonical release is recorded'
        Assert-True ($generationInfo -match [regex]::Escape("nuget_version = `"$($releaseInfo.nugetVersion)`"")) 'NuGet version is recorded'
        Assert-True ($generationInfo -match [regex]::Escape("winmd_sha256 = `"$primaryWinmdHash`"")) 'primary WinMD hash is recorded'
        Assert-True ($generationInfo -match [regex]::Escape("winmd_preview_sha256 = `"$previewWinmdHash`"")) 'preview WinMD hash is recorded'
    }

    Test-Case 'Strict failure: release metadata version mismatches MonthId/Patch' {
        $badMetadataPath = Join-Path $testRoot 'release-metadata-bad-version.json'
        New-ReleaseMetadata -Path $badMetadataPath `
            -MonthId $monthId `
            -Patch 9 `
            -PrimaryWinmdHash $primaryWinmdHash `
            -PreviewWinmdHash $previewWinmdHash

        $outDir = Join-Path $testRoot 'out-bad-version'
        $threw = $false
        try {
            & $packScript `
                -X64BinDir $x64BinDir `
                -Arm64BinDir $arm64BinDir `
                -MetadataDir $metadataDir `
                -ReleaseMetadataPath $badMetadataPath `
                -OutDir $outDir `
                -MonthId $monthId `
                -Patch $patch | Out-Null
        }
        catch {
            $threw = $true
        }
        Assert-True $threw 'pack.ps1 must throw when release metadata disagrees with MonthId/Patch'
    }

    Test-Case 'Strict failure: release metadata WinMD hash mismatches staged bytes' {
        $badMetadataPath = Join-Path $testRoot 'release-metadata-bad-hash.json'
        New-ReleaseMetadata -Path $badMetadataPath `
            -MonthId $monthId `
            -Patch $patch `
            -PrimaryWinmdHash ('f' * 64) `
            -PreviewWinmdHash $previewWinmdHash

        $outDir = Join-Path $testRoot 'out-bad-hash'
        $threw = $false
        try {
            & $packScript `
                -X64BinDir $x64BinDir `
                -Arm64BinDir $arm64BinDir `
                -MetadataDir $metadataDir `
                -ReleaseMetadataPath $badMetadataPath `
                -OutDir $outDir `
                -MonthId $monthId `
                -Patch $patch | Out-Null
        }
        catch {
            $threw = $true
        }
        Assert-True $threw 'pack.ps1 must throw when release metadata WinMD hashes disagree with the staged files'
    }

    Test-Case 'Strict failure: missing arm64 IsoSessionApp.dll' {
        $missingArm64Dir = Join-Path $testRoot 'bin\arm64-missing'
        New-Item -ItemType Directory -Force -Path $missingArm64Dir | Out-Null
        $outDir = Join-Path $testRoot 'out-missing-arm64'
        $threw = $false
        try {
            & $packScript `
                -X64BinDir $x64BinDir `
                -Arm64BinDir $missingArm64Dir `
                -MetadataDir $metadataDir `
                -ReleaseMetadataPath $releaseMetadataPath `
                -OutDir $outDir `
                -MonthId $monthId `
                -Patch $patch | Out-Null
        }
        catch {
            $threw = $true
        }
        Assert-True $threw 'pack.ps1 must fail when either runtime architecture is missing'
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($failures.Count -gt 0) {
    Write-Host "`n$($failures.Count) test(s) failed:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "`nAll IsoSession nuget pack.ps1 tests passed." -ForegroundColor Green
exit 0
