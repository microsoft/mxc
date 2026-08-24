# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ProxyBinary,

    [ValidateSet('x64', 'arm64')]
    [string]$Architecture = $(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }),

    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'out')
)

$ErrorActionPreference = 'Stop'

function New-PackageLogo {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$Size
    )

    Add-Type -AssemblyName System.Drawing
    $bitmap = [System.Drawing.Bitmap]::new($Size, $Size)
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.Clear([System.Drawing.Color]::FromArgb(0, 120, 212))
        } finally {
            $graphics.Dispose()
        }
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $bitmap.Dispose()
    }
}

$resolvedProxy = (Resolve-Path $ProxyBinary).Path

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
foreach ($kind in 'appcontainer', 'fulltrust') {
    $stage = Join-Path $OutputDirectory "stage-$kind"
    if (Test-Path $stage) {
        Remove-Item $stage -Recurse -Force
    }
    New-Item -ItemType Directory -Path (Join-Path $stage 'Assets') -Force | Out-Null
    Copy-Item $resolvedProxy (Join-Path $stage 'wxc-test-proxy.exe')

    $manifest = Get-Content (Join-Path $PSScriptRoot "$kind\AppxManifest.xml") -Raw
    $manifestPath = Join-Path $stage 'AppxManifest.xml'
    [IO.File]::WriteAllText(
        $manifestPath,
        $manifest.Replace('$architecture$', $Architecture),
        [Text.UTF8Encoding]::new($false)
    )
    New-PackageLogo -Path (Join-Path $stage 'Assets\Logo44.png') -Size 44
    New-PackageLogo -Path (Join-Path $stage 'Assets\Logo150.png') -Size 150
}

[pscustomobject]@{
    AppContainerManifest = Join-Path $OutputDirectory 'stage-appcontainer\AppxManifest.xml'
    FullTrustManifest = Join-Path $OutputDirectory 'stage-fulltrust\AppxManifest.xml'
    AppContainerDirectory = Join-Path $OutputDirectory 'stage-appcontainer'
    FullTrustDirectory = Join-Path $OutputDirectory 'stage-fulltrust'
    Port = 8080
}
