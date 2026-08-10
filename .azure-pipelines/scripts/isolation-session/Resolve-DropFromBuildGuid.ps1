#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DropExe,

    [string]$DropServiceUri = 'https://microsoft.artifacts.visualstudio.com/DefaultCollection',

    [Parameter(Mandatory = $true)]
    [guid]$BuildGuid,

    [ValidateSet('amd64fre', 'arm64fre')]
    [string]$Flavor,

    [string]$DropName = 'BIN',

    [switch]$UseAadAuth
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $DropExe -PathType Leaf)) {
    throw "drop.exe not found at '$DropExe'."
}

$prefix = "wdg/$BuildGuid/$Flavor/$DropName/"
$jsonFile = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-droplist-{0}.json' -f ([guid]::NewGuid()))
try {
    if ($UseAadAuth) {
        & $DropExe list `
            -s $DropServiceUri `
            -p $prefix `
            --toJsonFile $jsonFile `
            --tracelevel warn `
            -a | Out-Null
    }
    else {
        & $DropExe list `
            -s $DropServiceUri `
            -p $prefix `
            --toJsonFile $jsonFile `
            --tracelevel warn `
            --patAuthEnvVar SYSTEM_ACCESSTOKEN | Out-Null
    }

    if ($LASTEXITCODE -ne 0) {
        throw "drop list failed with exit code $LASTEXITCODE for prefix '$prefix'."
    }

    if (-not (Test-Path -LiteralPath $jsonFile -PathType Leaf)) {
        throw "drop list produced no output for prefix '$prefix'."
    }

    $raw = Get-Content -LiteralPath $jsonFile -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "No drops found for BuildGuid $BuildGuid (prefix '$prefix')."
    }

    # Windows PowerShell 5.1 emits a top-level JSON array as one pipeline
    # object. Re-pipeline the parsed value so both 5.1 and newer PowerShell
    # versions normalize it to an ordinary array of drop records.
    $parsed = ConvertFrom-Json -InputObject $raw
    $drops = @($parsed | ForEach-Object { $_ })
    $finalized = @(
        $drops | Where-Object {
            $_.UploadComplete -and -not $_.DeletePending
        })
    if ($finalized.Count -eq 0) {
        throw "No finalized drop found for BuildGuid $BuildGuid (prefix '$prefix')."
    }

    $chosen = $finalized |
        Sort-Object { [datetime]$_.CreatedDateUtc } -Descending |
        Select-Object -First 1

    Write-Output $chosen.Name
}
finally {
    Remove-Item -LiteralPath $jsonFile -Force -ErrorAction SilentlyContinue
}
