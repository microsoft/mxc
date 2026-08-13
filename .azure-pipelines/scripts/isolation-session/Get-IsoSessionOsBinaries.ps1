#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DropExe,

    [string]$DropServiceUri = 'https://microsoft.artifacts.visualstudio.com/DefaultCollection',

    [Parameter(Mandatory = $true)]
    [guid]$BuildGuid,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x64', 'arm64')]
    [string]$ArchTag,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [string]$DropNameOverride,

    [string]$OsBranch = 'ge_current_directwinpd_sf2',

    [switch]$UseAadAuth
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$flavor = if ($ArchTag -eq 'arm64') { 'arm64fre' } else { 'amd64fre' }
$dropName = if ($DropNameOverride) { $DropNameOverride.Trim() } else { '' }
if (-not $dropName) {
    $resolveArgs = @{
        DropExe = $DropExe
        DropServiceUri = $DropServiceUri
        BuildGuid = $BuildGuid
        Flavor = $flavor
    }
    if ($UseAadAuth) {
        $resolveArgs.UseAadAuth = $true
    }

    $dropName = & (Join-Path $PSScriptRoot 'Resolve-DropFromBuildGuid.ps1') @resolveArgs
    if (-not $dropName) {
        throw "Failed to resolve the OS BIN drop for BuildGuid $BuildGuid ($flavor)."
    }
}

$downloadRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-drop-{0}' -f ([guid]::NewGuid()))
New-Item -ItemType Directory -Path $downloadRoot | Out-Null

$filters = @(
    '/IsoSessionServer.dll',
    '/IsoSessionCore.dll',
    '/IsoSessionClient.dll',
    '/IsoSessionApp.dll',
    '/IsoSessionProxyStub.dll',
    '/IsolationProxy.exe',
    '/IsoSessionCli.exe'
) -join ';'

try {
    if ($UseAadAuth) {
        & $DropExe get `
            -s $DropServiceUri `
            -n $dropName `
            -d $downloadRoot `
            -r $filters `
            --tracelevel warn `
            --traceto console `
            -a
    }
    else {
        & $DropExe get `
            -s $DropServiceUri `
            -n $dropName `
            -d $downloadRoot `
            -r $filters `
            --tracelevel warn `
            --traceto console `
            --patAuthEnvVar SYSTEM_ACCESSTOKEN
    }

    if ($LASTEXITCODE -ne 0) {
        throw "drop get failed with exit code $LASTEXITCODE for '$dropName'."
    }

    & (Join-Path $PSScriptRoot 'Stage-IsoSessionOsBinaries.ps1') `
        -DropRoot $downloadRoot `
        -OutDir $OutDir `
        -ArchTag $ArchTag `
        -BuildGuid $BuildGuid `
        -DropName $dropName `
        -OsBranch $OsBranch `
        -Flavor $flavor

    Write-Host "##vso[task.setvariable variable=isoSessionResolvedDrop]$dropName"
}
finally {
    if (Test-Path -LiteralPath $downloadRoot -PathType Container) {
        Remove-Item -LiteralPath $downloadRoot -Recurse -Force
    }
}
