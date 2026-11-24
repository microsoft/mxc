# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Save', 'Restore')]
    [string]$Mode,

    [Parameter(Mandatory)]
    [string]$Archive,

    [Parameter(Mandatory)]
    [string]$Target,

    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..\..')
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$archivePath = [System.IO.Path]::GetFullPath($Archive)
if ($Target -notmatch '^[a-zA-Z0-9_-]+$') {
    throw "Invalid Cargo target: $Target"
}
$metadataName = '.mxc-cargo-build-snapshot.json'

function Get-GitBuildInputs {
    $gitDirectory = git -C $root rev-parse --absolute-git-dir
    if ($LASTEXITCODE -ne 0) { throw 'Resolving Git build inputs failed.' }
    $headPath = Join-Path $gitDirectory 'HEAD'
    $names = @('HEAD')
    $head = (Get-Content -LiteralPath $headPath -Raw).Trim()
    if ($head.StartsWith('ref: ')) {
        $refName = $head.Substring(5)
        if (Test-Path -LiteralPath (Join-Path $gitDirectory $refName)) {
            $names += $refName
        } elseif (Test-Path -LiteralPath (Join-Path $gitDirectory 'packed-refs')) {
            $names += 'packed-refs'
        }
    }
    foreach ($name in $names) {
        $path = Join-Path $gitDirectory $name
        [pscustomobject]@{
            Name = $name
            Path = $path
            Hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            UtcTicks = (Get-Item -LiteralPath $path).LastWriteTimeUtc.Ticks.ToString()
        }
    }
}

if ($Mode -eq 'Restore') {
    $metadataText = @(tar -xOf $archivePath $metadataName)
    if ($LASTEXITCODE -ne 0) { throw 'Reading Cargo build snapshot metadata failed.' }
    $metadata = ($metadataText -join "`n") | ConvertFrom-Json
    if ($metadata.Target -ne $Target) { throw 'Cargo build snapshot target mismatch.' }
    $currentInputs = @(Get-GitBuildInputs)
    if ($currentInputs.Count -ne @($metadata.GitInputs).Count) {
        throw 'Cargo build snapshot Git inputs do not match this checkout.'
    }
    foreach ($saved in $metadata.GitInputs) {
        $current = @($currentInputs | Where-Object Name -eq $saved.Name)
        if ($current.Count -ne 1 -or $current[0].Hash -ne $saved.Hash) {
            throw "Cargo build snapshot Git input differs: $($saved.Name)"
        }
    }
    tar -xf $archivePath --exclude $metadataName -C $root
    if ($LASTEXITCODE -ne 0) { throw 'Restoring the Cargo build snapshot failed.' }
    # Version-resource build scripts watch Git metadata as well as tracked sources.
    foreach ($saved in $metadata.GitInputs) {
        $current = $currentInputs | Where-Object Name -eq $saved.Name
        [IO.File]::SetLastWriteTimeUtc(
            $current.Path,
            [datetime]::new([long]$saved.UtcTicks, [DateTimeKind]::Utc)
        )
    }
    if (-not (Test-Path -LiteralPath (Join-Path $root "src\target\$Target\release"))) {
        throw "The Cargo build snapshot did not contain target $Target."
    }
    return
}

$tracked = @(git -C $root -c core.quotepath=false ls-files)
if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) {
    throw 'Listing snapshot source files failed.'
}
if ($tracked -contains $metadataName) {
    throw "Snapshot metadata name is reserved: $metadataName"
}
$targetPaths = @("src/target/$Target/release")
if (Test-Path -LiteralPath (Join-Path $root 'src\target\release')) {
    $targetPaths += 'src/target/release'
}
foreach ($path in $targetPaths) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $path))) {
        throw "Missing Cargo build output: $path"
    }
}

$list = [System.IO.Path]::GetTempFileName()
$metadataDirectory = Join-Path ([IO.Path]::GetTempPath()) "mxc-cargo-snapshot-$([guid]::NewGuid())"
try {
    New-Item -ItemType Directory -Path $metadataDirectory | Out-Null
    # Cargo freshness checks need the source timestamps from the producing job.
    @($tracked + $targetPaths) | Set-Content -LiteralPath $list -Encoding utf8NoBOM
    @{
        Target = $Target
        GitInputs = @(Get-GitBuildInputs | Select-Object Name, Hash, UtcTicks)
    } | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $metadataDirectory $metadataName) -Encoding utf8NoBOM
    tar --format pax -cf $archivePath -C $metadataDirectory $metadataName
    if ($LASTEXITCODE -ne 0) { throw 'Saving Cargo build snapshot metadata failed.' }
    tar --format pax -rf $archivePath -C $root -T $list
    if ($LASTEXITCODE -ne 0) { throw 'Saving the Cargo build snapshot failed.' }
} finally {
    Remove-Item -LiteralPath $list -Force
    if (Test-Path -LiteralPath (Join-Path $metadataDirectory $metadataName)) {
        Remove-Item -LiteralPath (Join-Path $metadataDirectory $metadataName) -Force
    }
    if (Test-Path -LiteralPath $metadataDirectory) {
        Remove-Item -LiteralPath $metadataDirectory -Force
    }
}
Write-Host "Cargo build snapshot: $archivePath ($((Get-Item -LiteralPath $archivePath).Length) bytes)"
