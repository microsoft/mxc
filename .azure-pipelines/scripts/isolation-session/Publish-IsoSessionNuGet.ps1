#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NuGetExe,

    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$FeedUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $NuGetExe -PathType Leaf)) {
    throw "nuget executable not found: '$NuGetExe'."
}
if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
    throw "NuGet package not found: '$PackagePath'."
}

$output = & $NuGetExe push $PackagePath -Source $FeedUrl -NonInteractive 2>&1
if ($LASTEXITCODE -ne 0) {
    $outputText = ($output | Out-String).Trim()
    if ($outputText -match '409|already exists|duplicate') {
        throw "Refusing to publish a duplicate package version: $outputText"
    }
    throw "NuGet push failed: $outputText"
}

Write-Host ($output | Out-String).Trim()
