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
$publisher = 'CN=Microsoft MXC Test Proxy'

function Get-WindowsSdkTool {
    param([Parameter(Mandatory)][string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $tool = Get-ChildItem $kitsRoot -Filter $Name -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match '\\x64$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $tool) {
        throw "$Name was not found. Install the Windows 10/11 SDK."
    }
    return $tool.FullName
}

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

$makeAppx = Get-WindowsSdkTool -Name 'makeappx.exe'
$signTool = Get-WindowsSdkTool -Name 'signtool.exe'
$resolvedProxy = (Resolve-Path $ProxyBinary).Path

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$certificate = New-SelfSignedCertificate -Type Custom -Subject $publisher `
    -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable -HashAlgorithm SHA256 `
    -TextExtension '2.5.29.37={text}1.3.6.1.5.5.7.3.3' `
    -NotAfter (Get-Date).AddDays(7)

try {
    $certificatePath = Join-Path $OutputDirectory 'Microsoft.MXC.TestProxy.cer'
    Export-Certificate -Cert $certificate -FilePath $certificatePath -Force | Out-Null

    foreach ($kind in 'appcontainer', 'fulltrust') {
        $stage = Join-Path $OutputDirectory "stage-$kind"
        if (Test-Path $stage) {
            Remove-Item $stage -Recurse -Force
        }
        New-Item -ItemType Directory -Path (Join-Path $stage 'Assets') -Force | Out-Null
        Copy-Item $resolvedProxy (Join-Path $stage 'wxc-test-proxy.exe')

        $manifest = Get-Content (Join-Path $PSScriptRoot "$kind\AppxManifest.xml") -Raw
        $manifest.Replace('$architecture$', $Architecture) |
            Set-Content (Join-Path $stage 'AppxManifest.xml') -Encoding utf8NoBOM
        New-PackageLogo -Path (Join-Path $stage 'Assets\Logo44.png') -Size 44
        New-PackageLogo -Path (Join-Path $stage 'Assets\Logo150.png') -Size 150

        $packagePath = Join-Path $OutputDirectory "mxc-test-proxy-$kind-$Architecture.msix"
        & $makeAppx pack /d $stage /p $packagePath /o | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "makeappx failed for $kind with exit code $LASTEXITCODE"
        }
        & $signTool sign /fd SHA256 /sha1 $certificate.Thumbprint $packagePath | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed for $kind with exit code $LASTEXITCODE"
        }
        Remove-Item $stage -Recurse -Force
    }

    [pscustomobject]@{
        Certificate = $certificatePath
        AppContainerPackage = Join-Path $OutputDirectory "mxc-test-proxy-appcontainer-$Architecture.msix"
        FullTrustPackage = Join-Path $OutputDirectory "mxc-test-proxy-fulltrust-$Architecture.msix"
        Port = 8080
    }
} finally {
    Remove-Item "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
}
