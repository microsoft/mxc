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
# root package key. It returns an ordered hashtable starting in PowerShell 7.3,
# preserving property order when the file is serialized.
#Requires -Version 7.3

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
        [string] $Uri,

        [Parameter(Mandatory)]
        [int] $TimeoutSeconds
    )

    $cancellation = [System.Threading.CancellationTokenSource]::new(
        [TimeSpan]::FromSeconds($TimeoutSeconds)
    )

    try {
        try {
            $response = $Client.GetAsync(
                $Uri,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                $cancellation.Token
            ).GetAwaiter().GetResult()

            try {
                if (-not $response.IsSuccessStatusCode) {
                    throw "Download failed with HTTP $([int]$response.StatusCode) ($($response.ReasonPhrase)): $Uri"
                }

                $stream = $response.Content.ReadAsStreamAsync(
                    $cancellation.Token
                ).GetAwaiter().GetResult()
                $sha1 = [System.Security.Cryptography.IncrementalHash]::CreateHash(
                    [System.Security.Cryptography.HashAlgorithmName]::SHA1
                )
                $sha256 = [System.Security.Cryptography.IncrementalHash]::CreateHash(
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256
                )
                $sha384 = [System.Security.Cryptography.IncrementalHash]::CreateHash(
                    [System.Security.Cryptography.HashAlgorithmName]::SHA384
                )
                $sha512 = [System.Security.Cryptography.IncrementalHash]::CreateHash(
                    [System.Security.Cryptography.HashAlgorithmName]::SHA512
                )

                try {
                    $buffer = [byte[]]::new(128KB)
                    while (($bytesRead = $stream.ReadAsync(
                        $buffer,
                        0,
                        $buffer.Length,
                        $cancellation.Token
                    ).GetAwaiter().GetResult()) -gt 0) {
                        $sha1.AppendData($buffer, 0, $bytesRead)
                        $sha256.AppendData($buffer, 0, $bytesRead)
                        $sha384.AppendData($buffer, 0, $bytesRead)
                        $sha512.AppendData($buffer, 0, $bytesRead)
                    }

                    [pscustomobject] @{
                        Sha1   = "sha1-$([Convert]::ToBase64String($sha1.GetHashAndReset()))"
                        Sha256 = "sha256-$([Convert]::ToBase64String($sha256.GetHashAndReset()))"
                        Sha384 = "sha384-$([Convert]::ToBase64String($sha384.GetHashAndReset()))"
                        Sha512 = "sha512-$([Convert]::ToBase64String($sha512.GetHashAndReset()))"
                    }
                } finally {
                    $sha1.Dispose()
                    $sha256.Dispose()
                    $sha384.Dispose()
                    $sha512.Dispose()
                    $stream.Dispose()
                }
            } finally {
                $response.Dispose()
            }
        } catch [System.OperationCanceledException] {
            throw "Download timed out after $TimeoutSeconds seconds: $Uri"
        }
    } finally {
        $cancellation.Dispose()
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

    $tokensByAlgorithm = @{}
    foreach ($token in $ExistingIntegrity -split '\s+') {
        if (-not $token) {
            continue
        }

        $tokenWithoutOptions = $token.Split('?', 2)[0]
        if ($tokenWithoutOptions -notmatch '^(sha1|sha256|sha384|sha512)-.+$') {
            continue
        }

        $algorithm = $Matches[1]
        if (-not $tokensByAlgorithm.ContainsKey($algorithm)) {
            $tokensByAlgorithm[$algorithm] = [System.Collections.Generic.List[string]]::new()
        }
        $tokensByAlgorithm[$algorithm].Add($tokenWithoutOptions)
    }

    $expectedByAlgorithm = @{
        sha1   = $Hashes.Sha1
        sha256 = $Hashes.Sha256
        sha384 = $Hashes.Sha384
        sha512 = $Hashes.Sha512
    }
    $strongestAlgorithm = @("sha512", "sha384", "sha256", "sha1") |
        Where-Object { $tokensByAlgorithm.ContainsKey($_) } |
        Select-Object -First 1

    if (-not $strongestAlgorithm) {
        throw "Unsupported integrity value at '$JsonPath': '$ExistingIntegrity'."
    }
    if ($tokensByAlgorithm[$strongestAlgorithm].Contains(
        $expectedByAlgorithm[$strongestAlgorithm]
    )) {
        return
    }

    throw "Integrity verification failed at '$JsonPath': no $strongestAlgorithm token matched the downloaded tarball."
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
$client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan

try {
    for ($index = 0; $index -lt $uniqueUrls.Count; $index++) {
        $url = $uniqueUrls[$index]
        Write-Progress `
            -Activity "Hashing npm tarballs from 1ES npm-public" `
            -Status "$($index + 1) of $($uniqueUrls.Count)" `
            -PercentComplete ((($index + 1) / $uniqueUrls.Count) * 100)

        $hashesByUrl[$url] = Get-TarballHashes `
            -Client $client `
            -Uri $url `
            -TimeoutSeconds $TimeoutSeconds
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
