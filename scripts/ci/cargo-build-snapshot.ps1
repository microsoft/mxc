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
$metadataPath = $archivePath + '.json'
$compression = @()
if ($archivePath.EndsWith('.tar.zst', [StringComparison]::OrdinalIgnoreCase)) {
    $compression = @('--zstd')
} elseif (-not $archivePath.EndsWith('.tar', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Cargo build snapshots require a .tar or .tar.zst archive.'
}

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
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    if ($metadata.FormatVersion -ne 1) { throw 'Unsupported Cargo build snapshot metadata version.' }
    if ($metadata.Target -ne $Target) { throw 'Cargo build snapshot target mismatch.' }
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $metadata.ArchiveSha256) {
        throw 'Cargo build snapshot archive checksum mismatch.'
    }
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
    tar -xf $archivePath -C $root
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
try {
    # Cargo freshness checks need the source timestamps from the producing job.
    @($tracked + $targetPaths) | Set-Content -LiteralPath $list -Encoding utf8NoBOM
    $metadata = @{
        FormatVersion = 1
        Target = $Target
        GitInputs = @(Get-GitBuildInputs | Select-Object Name, Hash, UtcTicks)
    }
    tar --format pax @compression -cf $archivePath -C $root -T $list
    if ($LASTEXITCODE -ne 0) { throw 'Saving the Cargo build snapshot failed.' }
    $metadata.ArchiveSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    $metadata | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath $metadataPath -Encoding utf8NoBOM
} finally {
    Remove-Item -LiteralPath $list -Force
}
Write-Host "Cargo build snapshot: $archivePath ($((Get-Item -LiteralPath $archivePath).Length) bytes)"
