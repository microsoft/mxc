# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Restores public npm URLs and SHA-512 integrity values in package-lock.json.

.DESCRIPTION
    npm operations performed through the 1ES npm-public feed can write ms-feed
    tarball URLs and SHA-1 integrity values into package-lock.json. This script
    downloads those tarballs from the feed, verifies any existing SHA-1 or
    SHA-512 integrity value, computes SHA-512, and rewrites the resolved URL to
    registry.npmjs.org.

    The lockfile is not changed unless every affected tarball is downloaded and
    verified successfully. Duplicate tarball URLs are downloaded only once.

.PARAMETER Path
    Path to package-lock.json. Defaults to package-lock.json in the current
    directory.

.EXAMPLE
    .\scripts\normalize-npm-package-lock.ps1

.EXAMPLE
    .\scripts\normalize-npm-package-lock.ps1 sdk\node\package-lock.json
#>

# ConvertFrom-Json -AsHashtable is required for package-lock.json's empty-string
# root package key and preserves property order when the file is serialized.
#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $Path = "package-lock.json",

    [ValidateRange(1, 3600)]
    [int] $TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$feedUrlPattern = [regex]::new(
    '^https://ms-feed-\d+\.pkgs\.visualstudio\.com/1es-public/_packaging/npm-public/npm/registry/(?<packagePath>.+)$',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)

function Find-FeedEntries {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Value,

        [Parameter(Mandatory)]
        [string] $JsonPath
    )

    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Contains("resolved") -and $Value["resolved"] -is [string]) {
            $match = $feedUrlPattern.Match($Value["resolved"])
            if ($match.Success) {
                [pscustomobject] @{
                    Map               = $Value
                    JsonPath          = $JsonPath
                    FeedUrl           = $Value["resolved"]
                    PublicUrl         = "https://registry.npmjs.org/$($match.Groups["packagePath"].Value)"
                    ExistingIntegrity = if ($Value.Contains("integrity")) {
                        $Value["integrity"]
                    } else {
                        $null
                    }
                }
            }
        }

        foreach ($key in $Value.Keys) {
            Find-FeedEntries -Value $Value[$key] -JsonPath "$JsonPath.$key"
        }
    } elseif ($Value -is [System.Collections.IList]) {
        for ($index = 0; $index -lt $Value.Count; $index++) {
            Find-FeedEntries -Value $Value[$index] -JsonPath "$JsonPath[$index]"
        }
    }
}

function Get-TarballHashes {
    param(
        [Parameter(Mandatory)]
        [System.Net.Http.HttpClient] $Client,

        [Parameter(Mandatory)]
        [string] $Uri
    )

    $response = $Client.GetAsync(
        $Uri,
        [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
    ).GetAwaiter().GetResult()

    try {
        if (-not $response.IsSuccessStatusCode) {
            throw "Download failed with HTTP $([int]$response.StatusCode) ($($response.ReasonPhrase)): $Uri"
        }

        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $sha1 = [System.Security.Cryptography.IncrementalHash]::CreateHash(
            [System.Security.Cryptography.HashAlgorithmName]::SHA1
        )
        $sha512 = [System.Security.Cryptography.IncrementalHash]::CreateHash(
            [System.Security.Cryptography.HashAlgorithmName]::SHA512
        )

        try {
            $buffer = [byte[]]::new(128KB)
            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $sha1.AppendData($buffer, 0, $bytesRead)
                $sha512.AppendData($buffer, 0, $bytesRead)
            }

            [pscustomobject] @{
                Sha1 = "sha1-$([Convert]::ToBase64String($sha1.GetHashAndReset()))"
                Sha512 = "sha512-$([Convert]::ToBase64String($sha512.GetHashAndReset()))"
            }
        } finally {
            $sha1.Dispose()
            $sha512.Dispose()
            $stream.Dispose()
        }
    } finally {
        $response.Dispose()
    }
}

function Assert-ExistingIntegrity {
    param(
        [AllowNull()]
        [object] $ExistingIntegrity,

        [Parameter(Mandatory)]
        [object] $Hashes,

        [Parameter(Mandatory)]
        [string] $JsonPath
    )

    if ($null -eq $ExistingIntegrity) {
        return
    }
    if ($ExistingIntegrity -isnot [string]) {
        throw "Expected a string integrity value at '$JsonPath', found $($ExistingIntegrity.GetType().FullName)."
    }

    if ($ExistingIntegrity -ceq $Hashes.Sha1 -or
        $ExistingIntegrity -ceq $Hashes.Sha512) {
        return
    }
    if ($ExistingIntegrity.StartsWith("sha1-", [StringComparison]::Ordinal) -or
        $ExistingIntegrity.StartsWith("sha512-", [StringComparison]::Ordinal)) {
        throw "Integrity verification failed at '$JsonPath': expected '$ExistingIntegrity', downloaded '$($Hashes.Sha1)' and '$($Hashes.Sha512)'."
    }
    throw "Unsupported integrity value at '$JsonPath': '$ExistingIntegrity'."
}

$lockPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
    throw "Package lock not found: $lockPath"
}

$original = [System.IO.File]::ReadAllText($lockPath)
try {
    $lockfile = $original | ConvertFrom-Json -AsHashtable -Depth 100
} catch {
    throw "Failed to parse '$lockPath': $($_.Exception.Message)"
}

$entries = @(Find-FeedEntries -Value $lockfile -JsonPath '$')
if ($entries.Count -eq 0) {
    Write-Host "No 1ES npm-public feed URLs found in '$lockPath'."
    exit 0
}

$hashesByUrl = @{}
$uniqueUrls = @($entries.FeedUrl | Sort-Object -Unique)
$handler = [System.Net.Http.HttpClientHandler]::new()
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)

try {
    for ($index = 0; $index -lt $uniqueUrls.Count; $index++) {
        $url = $uniqueUrls[$index]
        Write-Progress `
            -Activity "Hashing npm tarballs from 1ES npm-public" `
            -Status "$($index + 1) of $($uniqueUrls.Count)" `
            -PercentComplete ((($index + 1) / $uniqueUrls.Count) * 100)

        $hashesByUrl[$url] = Get-TarballHashes -Client $client -Uri $url
    }
} finally {
    Write-Progress -Activity "Hashing npm tarballs from 1ES npm-public" -Completed
    $client.Dispose()
    $handler.Dispose()
}

foreach ($entry in $entries) {
    $hashes = $hashesByUrl[$entry.FeedUrl]
    Assert-ExistingIntegrity `
        -ExistingIntegrity $entry.ExistingIntegrity `
        -Hashes $hashes `
        -JsonPath $entry.JsonPath
}

foreach ($entry in $entries) {
    $entry.Map["resolved"] = $entry.PublicUrl
    $entry.Map["integrity"] = $hashesByUrl[$entry.FeedUrl].Sha512
}

$updated = $lockfile | ConvertTo-Json -Depth 100
$updated += [Environment]::NewLine

if ($updated -eq $original) {
    Write-Host "No changes required in '$lockPath'."
    exit 0
}

if ($PSCmdlet.ShouldProcess(
        $lockPath,
        "replace $($entries.Count) feed URL and integrity entr$(if ($entries.Count -eq 1) { 'y' } else { 'ies' })"
    )) {
    $tempPath = Join-Path `
        (Split-Path -Parent $lockPath) `
        (".$([System.IO.Path]::GetFileName($lockPath)).$([Guid]::NewGuid().ToString('N')).tmp")

    try {
        [System.IO.File]::WriteAllText(
            $tempPath,
            $updated,
            [System.Text.UTF8Encoding]::new($false)
        )
        [System.IO.File]::Move($tempPath, $lockPath, $true)
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force
        }
    }

    Write-Host "Updated $($entries.Count) lockfile entries using $($uniqueUrls.Count) unique tarballs."
}
