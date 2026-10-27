# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Builds and stages the Windows x64 SDK MicroVM tests for artifact-only validation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BinaryDirectory,

    [Parameter(Mandatory)]
    [string]$Features
)

$ErrorActionPreference = 'Stop'
$binaryDirectoryPath = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$srcRoot = Join-Path $PSScriptRoot '..\..\src'

Push-Location $srcRoot
try {
    $messages = @(cargo test --locked --release --target x86_64-pc-windows-msvc `
        -p mxc-sdk --no-default-features --features $Features `
        --test nvx_e2e --no-run --message-format=json)
    if ($LASTEXITCODE -ne 0) {
        $messages | ForEach-Object { Write-Host $_ }
        throw "cargo test --no-run failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

$artifacts = @($messages |
    Where-Object { $_.StartsWith('{') } |
    ConvertFrom-Json |
    Where-Object {
        $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'nvx_e2e' -and
        $_.profile.test -and $_.executable
    })
if ($artifacts.Count -ne 1) {
    throw "Expected one nvx_e2e test executable from cargo; found $($artifacts.Count)."
}

$destination = Join-Path $binaryDirectoryPath 'nvx-e2e-tests.exe'
Copy-Item -LiteralPath $artifacts[0].executable -Destination $destination -Force
$discovered = @(& $destination --list)
if ($LASTEXITCODE -ne 0) {
    throw "Listing the staged NVX tests failed with exit code $LASTEXITCODE."
}
foreach ($name in @(
    'windows_x64::host_only_executor_request_matrix',
    'windows_x64::signed_bundle_executor_configs',
    'windows_x64::signed_bundle_executor_create_and_run',
    'windows_x64::signed_bundle_executor_console_interrupt',
    'windows_x64::signed_bundle_facade_create_and_run'
)) {
    if ($discovered -notcontains "$name`: test") {
        throw "The staged NVX payload did not discover $name."
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $binaryDirectoryPath 'aci-edge-sandboxes\bundle-manifest.json') -PathType Leaf)) {
    throw 'The Windows x64 artifact is missing the signed NVX bundle.'
}
Write-Host "Staged SDK MicroVM tests: $destination"
