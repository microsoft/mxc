#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')
$stageScript = Join-Path $repoRoot '.azure-pipelines\scripts\isolation-session\Stage-IsoSessionOsBinaries.ps1'
$aggregateScript = Join-Path $repoRoot '.azure-pipelines\scripts\isolation-session\Aggregate-IsoSessionArtifacts.ps1'
$installerScript = Join-Path $repoRoot 'packaging\isolation-session\installer\makeinstaller.ps1'
$releaseInfoScript = Join-Path $repoRoot 'packaging\isolation-session\common\Get-IsoSessionReleaseInfo.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-flow-test-{0}' -f ([guid]::NewGuid()))
$failures = @()

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
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

function Copy-DirectoryTree {
    param(
        [string]$Source,
        [string]$Destination
    )

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Get-ChildItem -LiteralPath $Source -Force |
        ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination $Destination -Recurse -Force
        }
}

function Get-PreparedCaseArtifacts {
    param([string]$CaseRoot)

    $x64Dir = Join-Path $CaseRoot 'x64'
    $arm64Dir = Join-Path $CaseRoot 'arm64'
    Copy-DirectoryTree -Source (Join-Path $script:preparedRoot 'artifact-x64') -Destination $x64Dir
    Copy-DirectoryTree -Source (Join-Path $script:preparedRoot 'artifact-arm64') -Destination $arm64Dir
    [pscustomobject]@{
        x64 = $x64Dir
        arm64 = $arm64Dir
    }
}

function Invoke-AggregationExpectFailure {
    param(
        [string]$X64ArtifactDirectory,
        [string]$Arm64ArtifactDirectory,
        [string]$OutDir
    )

    $threw = $false
    try {
        & $aggregateScript `
            -X64ArtifactDirectory $X64ArtifactDirectory `
            -Arm64ArtifactDirectory $Arm64ArtifactDirectory `
            -OutDir $OutDir `
            -MonthId $script:releaseInfo.monthId `
            -Patch $script:releaseInfo.patch `
            -SigningMode unsigned
    }
    catch {
        $threw = $true
    }
    Assert-True $threw 'aggregation must fail'
}

function Write-SignedPayloadEvidence {
    param(
        [string]$ArtifactDirectory,
        [string]$Arch
    )

    $records = @(
        Get-ChildItem -LiteralPath (Join-Path $ArtifactDirectory "bin\$Arch") -File |
            Where-Object { $_.Extension -in @('.dll', '.exe') } |
            ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    path = $_.FullName
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                    status = 'Valid'
                    signer = 'CN=Synthetic Test Signer'
                    thumbprint = '0000000000000000000000000000000000000000'
                }
            })

    $records | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath (Join-Path $ArtifactDirectory 'signature-verification.json') -Encoding UTF8
}

try {
    $script:preparedRoot = Join-Path $testRoot 'prepared'
    New-Item -ItemType Directory -Force -Path $script:preparedRoot | Out-Null

    $script:releaseInfo = & $releaseInfoScript -MonthId '2026.08' -Patch 4
    $primaryWinmdContent = 'shared-primary-winmd'
    $previewWinmdContent = 'shared-preview-winmd'

    foreach ($arch in @('x64', 'arm64')) {
        $flavor = if ($arch -eq 'arm64') { 'arm64fre' } else { 'amd64fre' }
        $dropRoot = Join-Path $script:preparedRoot "drop-$arch"
        $payloadDir = Join-Path $script:preparedRoot "payload-$arch"
        $installerDir = Join-Path $script:preparedRoot "installer-$arch"
        $artifactDir = Join-Path $script:preparedRoot "artifact-$arch"
        New-Item -ItemType Directory -Force -Path $dropRoot, $artifactDir | Out-Null

        foreach ($name in @(
            'IsoSessionServer.dll',
            'IsoSessionClient.dll',
            'IsoSessionApp.dll',
            'IsoSessionProxyStub.dll',
            'IsolationProxy.exe',
            'IsoSessionCli.exe')) {
            Set-Content -LiteralPath (Join-Path $dropRoot $name) -Value "$arch-$name" -Encoding UTF8
        }
        Set-Content -LiteralPath (Join-Path $dropRoot 'windows.ai.isolationsession.winmd') -Value $primaryWinmdContent -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $dropRoot 'windows.ai.isolationsession.preview.winmd') -Value $previewWinmdContent -Encoding UTF8

        & $stageScript `
            -DropRoot $dropRoot `
            -OutDir $payloadDir `
            -ArchTag $arch `
            -BuildGuid '72de6fa1-35ec-8b71-6bd4-6e74b1af57db' `
            -DropName "wdg/test/$flavor/BIN/test" `
            -Flavor $flavor

        Copy-DirectoryTree -Source $payloadDir -Destination $artifactDir
        $script:releaseInfo | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $artifactDir 'release-contract.json') -Encoding UTF8

        @(
            @{
                name = "IsoSession_$($script:releaseInfo.monthUnderscore)_$arch.msi"
                status = 'Unknown'
            }
            @{
                name = "IsoSessionSetup_$($script:releaseInfo.monthUnderscore)_$arch.exe"
                status = 'Unknown'
            }
        ) | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $artifactDir 'signature-verification.json') -Encoding UTF8

        $payloadBin = Join-Path $payloadDir "bin\$arch"
        & $installerScript `
            -Arch $arch `
            -BinDir $payloadBin `
            -MonthId $script:releaseInfo.monthId `
            -Patch $script:releaseInfo.patch `
            -OutDir $installerDir `
            -MsiOnly
        if ($LASTEXITCODE -ne 0) {
            throw "MSI build failed for $arch with exit code $LASTEXITCODE."
        }

        & $installerScript `
            -Arch $arch `
            -BinDir $payloadBin `
            -MonthId $script:releaseInfo.monthId `
            -Patch $script:releaseInfo.patch `
            -OutDir $installerDir `
            -BundleOnly
        if ($LASTEXITCODE -ne 0) {
            throw "Bundle build failed for $arch with exit code $LASTEXITCODE."
        }

        foreach ($name in @(
            "IsoSession_$($script:releaseInfo.monthUnderscore)_$arch.msi",
            "IsoSessionSetup_$($script:releaseInfo.monthUnderscore)_$arch.exe",
            "IsoSessionClient_$($script:releaseInfo.monthUnderscore)_$arch.manifest")) {
            Copy-Item -LiteralPath (Join-Path $installerDir $name) -Destination $artifactDir -Force
        }
    }

    Test-Case 'Happy path: aggregation creates the final multi-arch outputs' {
        $caseRoot = Join-Path $testRoot 'happy'
        $artifacts = Get-PreparedCaseArtifacts -CaseRoot $caseRoot
        $outDir = Join-Path $caseRoot 'final'

        & $aggregateScript `
            -X64ArtifactDirectory $artifacts.x64 `
            -Arm64ArtifactDirectory $artifacts.arm64 `
            -OutDir $outDir `
            -MonthId $script:releaseInfo.monthId `
            -Patch $script:releaseInfo.patch `
            -SigningMode unsigned

        Assert-True (Test-Path -LiteralPath (Join-Path $outDir $script:releaseInfo.nugetPackageFileName)) 'final multi-arch NuGet exists'
        Assert-True (Test-Path -LiteralPath (Join-Path $outDir 'release-metadata.json')) 'final release metadata exists'
        Assert-True (Test-Path -LiteralPath (Join-Path $outDir 'artifact-manifest.json')) 'aggregate artifact manifest exists'
        Assert-True (Test-Path -LiteralPath (Join-Path $outDir 'provenance\x64\source-manifest.json')) 'x64 provenance is preserved'
        Assert-True (Test-Path -LiteralPath (Join-Path $outDir 'provenance\arm64\source-manifest.json')) 'arm64 provenance is preserved'

        $manifest = Get-Content (Join-Path $outDir 'artifact-manifest.json') -Raw |
            ConvertFrom-Json
        Assert-True ($manifest.release.canonicalRelease -eq $script:releaseInfo.canonicalRelease) 'artifact manifest records the canonical release'
        Assert-True ($manifest.nuget.packageVersion -eq $script:releaseInfo.nugetVersion) 'artifact manifest records the patch-bearing NuGet version'
        Assert-True (@($manifest.source.winmds).Count -eq 2) 'artifact manifest records both WinMDs'
    }

    Test-Case 'Negative: aggregation fails when BuildGuid differs across architectures' {
        $caseRoot = Join-Path $testRoot 'bad-buildguid'
        $artifacts = Get-PreparedCaseArtifacts -CaseRoot $caseRoot
        $armManifestPath = Join-Path $artifacts.arm64 'source-manifest.json'
        $armManifest = Get-Content -LiteralPath $armManifestPath -Raw | ConvertFrom-Json
        $armManifest.buildGuid = '11111111-1111-1111-1111-111111111111'
        $armManifest | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $armManifestPath -Encoding UTF8

        Invoke-AggregationExpectFailure `
            -X64ArtifactDirectory $artifacts.x64 `
            -Arm64ArtifactDirectory $artifacts.arm64 `
            -OutDir (Join-Path $caseRoot 'final')
    }

    Test-Case 'Signed payload hashes are validated independently from source hashes' {
        $caseRoot = Join-Path $testRoot 'signed-payload'
        $artifacts = Get-PreparedCaseArtifacts -CaseRoot $caseRoot
        $x64AppPath = Join-Path $artifacts.x64 'bin\x64\IsoSessionApp.dll'
        Set-Content -LiteralPath $x64AppPath -Value 'signed-x64-IsoSessionApp.dll' -Encoding UTF8
        Write-SignedPayloadEvidence -ArtifactDirectory $artifacts.x64 -Arch 'x64'
        Write-SignedPayloadEvidence -ArtifactDirectory $artifacts.arm64 -Arch 'arm64'

        $outDir = Join-Path $caseRoot 'final'
        & $aggregateScript `
            -X64ArtifactDirectory $artifacts.x64 `
            -Arm64ArtifactDirectory $artifacts.arm64 `
            -OutDir $outDir `
            -MonthId $script:releaseInfo.monthId `
            -Patch $script:releaseInfo.patch `
            -SigningMode test

        $releaseMetadata = Get-Content -LiteralPath (Join-Path $outDir 'release-metadata.json') -Raw |
            ConvertFrom-Json
        $signedHash = (Get-FileHash -LiteralPath $x64AppPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-True ($releaseMetadata.source.payloads.x64.isoSessionAppSha256 -eq $signedHash) `
            'release metadata records the signed runtime hash'
    }

    Test-Case 'Negative: aggregation fails when WinMD hashes differ across architectures' {
        $caseRoot = Join-Path $testRoot 'bad-winmd'
        $artifacts = Get-PreparedCaseArtifacts -CaseRoot $caseRoot
        $armPreviewPath = Join-Path $artifacts.arm64 'bin\arm64\windows.ai.isolationsession.preview.winmd'
        Set-Content -LiteralPath $armPreviewPath -Value 'mutated-preview-winmd' -Encoding UTF8
        $armManifestPath = Join-Path $artifacts.arm64 'source-manifest.json'
        $armManifest = Get-Content -LiteralPath $armManifestPath -Raw | ConvertFrom-Json
        $entry = @($armManifest.files | Where-Object { $_.name -eq 'windows.ai.isolationsession.preview.winmd' })[0]
        $entry.sha256 = (Get-FileHash -LiteralPath $armPreviewPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $entry.sizeBytes = (Get-Item -LiteralPath $armPreviewPath).Length
        $armManifest | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $armManifestPath -Encoding UTF8

        Invoke-AggregationExpectFailure `
            -X64ArtifactDirectory $artifacts.x64 `
            -Arm64ArtifactDirectory $artifacts.arm64 `
            -OutDir (Join-Path $caseRoot 'final')
    }

    Test-Case 'Negative: aggregation fails when an architecture payload is missing' {
        $caseRoot = Join-Path $testRoot 'missing-payload'
        $artifacts = Get-PreparedCaseArtifacts -CaseRoot $caseRoot
        Remove-Item -LiteralPath (Join-Path $artifacts.arm64 'bin\arm64\IsoSessionApp.dll') -Force

        Invoke-AggregationExpectFailure `
            -X64ArtifactDirectory $artifacts.x64 `
            -Arm64ArtifactDirectory $artifacts.arm64 `
            -OutDir (Join-Path $caseRoot 'final')
    }

    Test-Case 'Negative: aggregation fails when the release contract is inconsistent' {
        $caseRoot = Join-Path $testRoot 'bad-release'
        $artifacts = Get-PreparedCaseArtifacts -CaseRoot $caseRoot
        $armReleasePath = Join-Path $artifacts.arm64 'release-contract.json'
        $armRelease = Get-Content -LiteralPath $armReleasePath -Raw | ConvertFrom-Json
        $armRelease.nugetVersion = '0.202608.999'
        $armRelease | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $armReleasePath -Encoding UTF8

        Invoke-AggregationExpectFailure `
            -X64ArtifactDirectory $artifacts.x64 `
            -Arm64ArtifactDirectory $artifacts.arm64 `
            -OutDir (Join-Path $caseRoot 'final')
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

if ($failures.Count -gt 0) {
    Write-Host "`n$($failures.Count) test(s) failed:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host 'IsoSession x64 and ARM64 aggregation tests passed.' -ForegroundColor Green
