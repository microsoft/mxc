#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-manifest-test-{0}' -f ([guid]::NewGuid()))
$artifactDir = Join-Path $testRoot 'artifacts'
$sourceManifest = Join-Path $testRoot 'source-manifest.json'
$script = Join-Path (Split-Path $PSScriptRoot -Parent) 'New-IsoSessionArtifactManifest.ps1'

try {
    New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
    @{
        schema = 'mxc.isosession-os-binaries/1'
        buildGuid = '72de6fa1-35ec-8b71-6bd4-6e74b1af57db'
        arch = 'x64'
    } | ConvertTo-Json | Set-Content -LiteralPath $sourceManifest -Encoding UTF8

    foreach ($name in @(
        'IsoSession_2026_08_x64.msi',
        'IsoSessionSetup_2026_08_x64.exe'
    )) {
        Set-Content -LiteralPath (Join-Path $artifactDir $name) -Value $name
    }

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $nupkgPath = Join-Path $artifactDir 'Microsoft.Windows.AI.IsolationSession.SDK.x64.0.202608.0.nupkg'
    $zip = [System.IO.Compression.ZipFile]::Open(
        $nupkgPath,
        [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = $zip.CreateEntry('Microsoft.Windows.AI.IsolationSession.SDK.nuspec')
        $writer = New-Object System.IO.StreamWriter($entry.Open())
        try {
            $writer.Write(
                '<package><metadata><id>Microsoft.Windows.AI.IsolationSession.SDK.x64</id><version>0.202608.0</version></metadata></package>')
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        $zip.Dispose()
    }

    & $script `
        -SourceManifest $sourceManifest `
        -ArtifactDirectory $artifactDir `
        -MonthId '2026.08' `
        -Patch 0 `
        -ArchTag x64 `
        -BasePackageId 'Microsoft.Windows.AI.IsolationSession.SDK' `
        -BasePackageVersion '0.202608.0' `
        -SigningMode test

    $manifest = Get-Content (Join-Path $artifactDir 'artifact-manifest.json') -Raw |
        ConvertFrom-Json
    if ($manifest.artifacts.Count -ne 3) {
        throw 'Artifact manifest did not contain the expected outputs.'
    }
    if ($manifest.redistribution.publicReleaseReady) {
        throw 'Test-signed artifacts must not be marked public-release-ready.'
    }
    if ($manifest.nuget.outputPackageId -ne 'Microsoft.Windows.AI.IsolationSession.SDK.x64') {
        throw 'Artifact manifest did not record the architecture-specific package ID.'
    }

    Write-Host 'IsoSession artifact manifest tests passed.'
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
