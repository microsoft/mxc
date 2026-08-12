#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DropRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string]$ArchTag,

    [Parameter(Mandatory = $true)]
    [guid]$BuildGuid,

    [Parameter(Mandatory = $true)]
    [string]$DropName,

    [string]$OsBranch = 'ge_current_directwinpd_sf2',

    [Parameter(Mandatory = $true)]
    [ValidateSet('amd64fre', 'arm64fre')]
    [string]$Flavor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $DropRoot -PathType Container)) {
    throw "Downloaded drop directory not found: '$DropRoot'."
}

$requiredBinaries = @(
    'IsoSessionServer.dll',
    'IsoSessionClient.dll',
    'IsoSessionApp.dll',
    'IsoSessionProxyStub.dll',
    'IsolationProxy.exe',
    'IsoSessionCli.exe'
)
$optionalWinmds = @(
    'windows.ai.isolationsession.winmd',
    'windows.ai.isolationsession.preview.winmd'
)
$recognizedFiles = @($requiredBinaries + $optionalWinmds)
$expectedFileLookup = @{}
foreach ($name in $recognizedFiles) {
    $expectedFileLookup[$name.ToLowerInvariant()] = $name
}

$foundByName = @{}
Get-ChildItem -LiteralPath $DropRoot -Recurse -File | ForEach-Object {
    $key = $_.Name.ToLowerInvariant()
    if ($expectedFileLookup.ContainsKey($key)) {
        if ($foundByName.ContainsKey($key)) {
            throw "Downloaded drop contains more than one '$($expectedFileLookup[$key])'."
        }
        $foundByName[$key] = $_
    }
}

$missing = @(
    $requiredBinaries | Where-Object {
        -not $foundByName.ContainsKey($_.ToLowerInvariant())
    })
if ($missing.Count -gt 0) {
    throw "OS drop is missing required IsoSession files: $($missing -join ', ')."
}

$stageDir = Join-Path $OutDir "bin\$ArchTag"
New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
$dropRootPath = (Resolve-Path -LiteralPath $DropRoot).Path.TrimEnd('\')
$filesToStage = @(
    $recognizedFiles | Where-Object {
        $foundByName.ContainsKey($_.ToLowerInvariant())
    })

$files = foreach ($name in $filesToStage) {
    $source = $foundByName[$name.ToLowerInvariant()]
    $destination = Join-Path $stageDir $name
    Copy-Item -LiteralPath $source.FullName -Destination $destination -Force
    $item = Get-Item -LiteralPath $destination
    $relativeSourcePath = $source.FullName.Substring($dropRootPath.Length).TrimStart('\')

    [ordered]@{
        name = $name
        kind = if ($optionalWinmds -contains $name) { 'winmd' } else { 'binary' }
        sizeBytes = $item.Length
        sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        fileVersion = $item.VersionInfo.FileVersion
        relativeSourcePath = $relativeSourcePath
    }
}

$manifest = [ordered]@{
    schema = 'mxc.isosession-os-binaries/2'
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    osBranch = $OsBranch
    buildGuid = $BuildGuid.ToString()
    dropName = $DropName
    flavor = $Flavor
    arch = $ArchTag
    files = @($files)
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$manifestPath = Join-Path $OutDir 'source-manifest.json'
$manifest | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Staged $($filesToStage.Count) IsoSession files in '$stageDir'."
Write-Host "Source manifest: $manifestPath"
