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

if ($Mode -eq 'Restore') {
    tar -xf $archivePath -C $root
    if ($LASTEXITCODE -ne 0) { throw 'Restoring the Cargo build snapshot failed.' }
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
    tar --format pax -cf $archivePath -C $root -T $list
    if ($LASTEXITCODE -ne 0) { throw 'Saving the Cargo build snapshot failed.' }
} finally {
    Remove-Item -LiteralPath $list -Force
}
Write-Host "Cargo build snapshot: $archivePath ($((Get-Item -LiteralPath $archivePath).Length) bytes)"
