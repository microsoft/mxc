#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NuGetExe,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$FeedUrl,

    [Parameter(Mandatory = $true)]
    [string]$PackageId,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$OutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $NuGetExe -PathType Leaf)) {
    throw "nuget.exe not found at '$NuGetExe'."
}
if ($FeedUrl -like 'REPLACE-*') {
    throw 'A restricted Azure Artifacts feed URL must be supplied.'
}
if ([string]::IsNullOrWhiteSpace($PackageId)) {
    throw 'A base package ID must be supplied.'
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    throw 'A base package version must be supplied.'
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
& $NuGetExe install $PackageId `
    -Version $Version `
    -Source $FeedUrl `
    -OutputDirectory $OutDir `
    -DirectDownload `
    -NonInteractive `
    -NoCache `
    -PackageSaveMode nupkg

if ($LASTEXITCODE -ne 0) {
    throw "Failed to download $PackageId $Version from the restricted feed."
}

$matches = @(
    Get-ChildItem -LiteralPath $OutDir -Recurse -File -Filter '*.nupkg' |
        Where-Object {
            $_.Name -eq "$PackageId.$Version.nupkg"
        })
if ($matches.Count -ne 1) {
    throw "Expected one '$PackageId.$Version.nupkg' under '$OutDir'; found $($matches.Count)."
}

Write-Host "##vso[task.setvariable variable=baseIsoSessionNupkg]$($matches[0].FullName)"
Write-Output $matches[0].FullName
