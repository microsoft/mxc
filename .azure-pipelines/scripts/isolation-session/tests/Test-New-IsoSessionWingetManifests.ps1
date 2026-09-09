#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')
$scriptPath = Join-Path $repoRoot '.azure-pipelines\scripts\isolation-session\New-IsoSessionWingetManifests.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-winget-test-{0}' -f ([guid]::NewGuid()))
$installerDirectory = Join-Path $testRoot 'installers'
$outDir = Join-Path $testRoot 'out'

function Assert-True {
    param([bool]$Condition, [string]$Message)

    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

try {
    New-Item -ItemType Directory -Path $installerDirectory -Force | Out-Null
    $x64Name = 'IsoSession_2026_09_x64.msi'
    $arm64Name = 'IsoSession_2026_09_arm64.msi'
    Set-Content -LiteralPath (Join-Path $installerDirectory $x64Name) -Value 'x64-msi' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $installerDirectory $arm64Name) -Value 'arm64-msi' -Encoding ASCII

    $releaseDetails = @{
        status = 'pass'
        files = @(
            @{
                name = $x64Name
                fileDownloadDetails = @(
                    @{ portalName = 'CDN'; downloadUrl = "https://example.test/$x64Name" })
            },
            @{
                distributionRelativePath = "nested/$arm64Name"
                fileDownloadDetails = @(
                    @{ portalName = 'CDN'; downloadUrl = "https://example.test/$arm64Name" })
            })
    } | ConvertTo-Json -Depth 10

    & $scriptPath `
        -InstallerDirectory $installerDirectory `
        -ReleaseDetailsJson $releaseDetails `
        -OutDir $outDir `
        -MonthId '2026.09' `
        -Patch 2 `
        -PackageIdentifier 'Microsoft.Windows.AI.IsolationSession' `
        -PackageName 'Microsoft Windows AI IsolationSession' `
        -Publisher 'Microsoft Corporation' `
        -PackageUrl 'https://github.com/microsoft/mxc' `
        -License 'MIT' `
        -LicenseUrl 'https://github.com/microsoft/mxc/blob/main/LICENSE.md' `
        -ShortDescription 'Installs the monthly Windows AI IsolationSession runtime.'

    $manifestDirectory = Join-Path $outDir 'manifests\m\Microsoft\Windows\AI\IsolationSession\2026.09.2'
    $versionPath = Join-Path $manifestDirectory 'Microsoft.Windows.AI.IsolationSession.yaml'
    $localePath = Join-Path $manifestDirectory 'Microsoft.Windows.AI.IsolationSession.locale.en-US.yaml'
    $installerPath = Join-Path $manifestDirectory 'Microsoft.Windows.AI.IsolationSession.installer.yaml'
    Assert-True (Test-Path -LiteralPath $versionPath -PathType Leaf) 'version manifest exists'
    Assert-True (Test-Path -LiteralPath $localePath -PathType Leaf) 'locale manifest exists'
    Assert-True (Test-Path -LiteralPath $installerPath -PathType Leaf) 'installer manifest exists'

    $installerManifest = Get-Content -LiteralPath $installerPath -Raw
    Assert-True ($installerManifest -match 'PackageVersion: ''2026\.09\.2''') 'canonical release is the package version'
    Assert-True ($installerManifest -match 'Architecture: x64') 'x64 installer is present'
    Assert-True ($installerManifest -match 'Architecture: arm64') 'arm64 installer is present'
    Assert-True ($installerManifest -match [regex]::Escape("https://example.test/$x64Name")) 'x64 CDN URL is present'
    Assert-True ($installerManifest -match [regex]::Escape("https://example.test/$arm64Name")) 'arm64 CDN URL is present'
    Assert-True ($installerManifest -match 'InstallerSha256: [A-F0-9]{64}') 'installer hashes are present'
    Assert-True ($installerManifest -match 'UpgradeCode: ''\{[A-F0-9-]{36}\}''') 'deterministic upgrade code is present'

    $summary = Get-Content -LiteralPath (Join-Path $outDir 'winget-release.json') -Raw |
        ConvertFrom-Json
    Assert-True ($summary.packageIdentifier -eq 'Microsoft.Windows.AI.IsolationSession') 'summary has package identifier'
    Assert-True ($summary.packageVersion -eq '2026.09.2') 'summary has package version'
    Assert-True (@($summary.installers).Count -eq 2) 'summary has both installers'

    $missingLinkFailed = $false
    try {
        $missingLinkDetails = @{
            status = 'pass'
            files = @(
                @{
                    name = $x64Name
                    fileDownloadDetails = @(
                        @{ downloadUrl = "https://example.test/$x64Name" })
                })
        } | ConvertTo-Json -Depth 10

        & $scriptPath `
            -InstallerDirectory $installerDirectory `
            -ReleaseDetailsJson $missingLinkDetails `
            -OutDir (Join-Path $testRoot 'missing-link') `
            -MonthId '2026.09' `
            -Patch 2 `
            -PackageIdentifier 'Microsoft.Windows.AI.IsolationSession' `
            -PackageName 'Microsoft Windows AI IsolationSession' `
            -Publisher 'Microsoft Corporation' `
            -PackageUrl 'https://github.com/microsoft/mxc' `
            -License 'MIT' `
            -LicenseUrl 'https://github.com/microsoft/mxc/blob/main/LICENSE.md' `
            -ShortDescription 'Installs the monthly Windows AI IsolationSession runtime.'
    }
    catch {
        $missingLinkFailed = $_.Exception.Message -match 'No ESRP CDN link was returned'
    }
    Assert-True $missingLinkFailed 'missing ESRP links are rejected'

    Write-Host 'IsoSession WinGet manifest tests passed.'
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
