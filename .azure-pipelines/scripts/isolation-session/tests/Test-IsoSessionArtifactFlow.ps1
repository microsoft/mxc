#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')
$stageScript = Join-Path $repoRoot '.azure-pipelines\scripts\isolation-session\Stage-IsoSessionOsBinaries.ps1'
$manifestScript = Join-Path $repoRoot '.azure-pipelines\scripts\isolation-session\New-IsoSessionArtifactManifest.ps1'
$packScript = Join-Path $repoRoot 'packaging\isolation-session\nuget\pack.ps1'
$baseBuilder = Join-Path $repoRoot 'packaging\isolation-session\nuget\tests\New-SyntheticBaseNupkg.ps1'
$installerScript = Join-Path $repoRoot 'packaging\isolation-session\installer\makeinstaller.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-flow-test-{0}' -f ([guid]::NewGuid()))

try {
    $monthId = '2026.08'
    $baseNupkg = Join-Path $testRoot 'Microsoft.Windows.AI.IsolationSession.SDK.0.202608.0.nupkg'
    New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
    & $baseBuilder -OutFile $baseNupkg -Version '0.202608.0' -Instance $monthId | Out-Null

    foreach ($arch in @('x64', 'arm64')) {
        $flavor = if ($arch -eq 'arm64') { 'arm64fre' } else { 'amd64fre' }
        $dropRoot = Join-Path $testRoot "drop-$arch"
        $payloadDir = Join-Path $testRoot "payload-$arch"
        $nugetDir = Join-Path $testRoot "nuget-$arch"
        $installerDir = Join-Path $testRoot "installer-$arch"
        $artifactDir = Join-Path $testRoot "artifact-$arch"
        New-Item -ItemType Directory -Force -Path $dropRoot, $artifactDir | Out-Null

        foreach ($name in @(
            'IsoSessionServer.dll',
            'IsoSessionClient.dll',
            'IsoSessionApp.dll',
            'IsoSessionProxyStub.dll',
            'IsolationProxy.exe',
            'IsoSessionCli.exe'
        )) {
            Set-Content -LiteralPath (Join-Path $dropRoot $name) -Value "$arch-$name"
        }

        & $stageScript `
            -DropRoot $dropRoot `
            -OutDir $payloadDir `
            -ArchTag $arch `
            -BuildGuid '72de6fa1-35ec-8b71-6bd4-6e74b1af57db' `
            -DropName "wdg/test/$flavor/BIN/test" `
            -Flavor $flavor

        $payloadBin = Join-Path $payloadDir "bin\$arch"
        $nupkg = & $packScript `
            -BinDir $payloadBin `
            -BaseNupkg $baseNupkg `
            -OutDir $nugetDir `
            -ArchTag $arch `
            -MonthId $monthId
        & $installerScript `
            -Arch $arch `
            -BinDir $payloadBin `
            -MonthId $monthId `
            -Patch 0 `
            -OutDir $installerDir `
            -MsiOnly
        if ($LASTEXITCODE -ne 0) {
            throw "MSI build failed for $arch with exit code $LASTEXITCODE."
        }
        $msiPath = Join-Path $installerDir "IsoSession_2026_08_$arch.msi"
        $msiHashBeforeBundle = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash

        & $installerScript `
            -Arch $arch `
            -BinDir $payloadBin `
            -MonthId $monthId `
            -Patch 0 `
            -OutDir $installerDir `
            -BundleOnly
        if ($LASTEXITCODE -ne 0) {
            throw "Bundle build failed for $arch with exit code $LASTEXITCODE."
        }
        $msiHashAfterBundle = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash
        if ($msiHashAfterBundle -ne $msiHashBeforeBundle) {
            throw "Bundle phase replaced the existing MSI for $arch."
        }

        Copy-Item -LiteralPath $nupkg -Destination $artifactDir
        Copy-Item -LiteralPath $msiPath -Destination $artifactDir
        Copy-Item -LiteralPath (Join-Path $installerDir "IsoSessionSetup_2026_08_$arch.exe") -Destination $artifactDir
        Copy-Item -LiteralPath (Join-Path $payloadDir 'source-manifest.json') -Destination $artifactDir

        & $manifestScript `
            -SourceManifest (Join-Path $artifactDir 'source-manifest.json') `
            -ArtifactDirectory $artifactDir `
            -MonthId $monthId `
            -Patch 0 `
            -ArchTag $arch `
            -BasePackageId 'Microsoft.Windows.AI.IsolationSession.SDK' `
            -BasePackageVersion '0.202608.0' `
            -SigningMode unsigned

        $manifest = Get-Content (Join-Path $artifactDir 'artifact-manifest.json') -Raw |
            ConvertFrom-Json
        if ($manifest.artifacts.Count -lt 3 -or $manifest.release.arch -ne $arch) {
            throw "End-to-end artifact manifest validation failed for $arch."
        }
    }

    Write-Host 'IsoSession x64 and ARM64 artifact flow tests passed.'
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
