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
        --test nvx_e2e --test nvx_bundle_integrity --no-run --message-format=json)
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
    'windows_x64::signed_agent_proxy_validation_withholds_credentials',
    'windows_x64::guest_path_resolves_windows_case_alias',
    'windows_x64::signed_executor_proxy_validation_withholds_credentials',
    'windows_x64::signed_bundle_executor_configs',
    'windows_x64::signed_bundle_executor_create_and_run',
    'windows_x64::signed_bundle_executor_console_interrupt',
    'windows_x64::signed_bundle_facade_create_and_run',
    'windows_x64::signed_bundle_sdk_json_capture',
    'windows_x64::signed_bundle_json_image_and_filesystem_policy',
    'windows_network::signed_bundle_network_rules_enforce_allow_deny_and_port_selectors',
    'windows_network::signed_bundle_host_loopback_ingress',
    'windows_network::signed_bundle_deny_default_proxy_policy'
)) {
    if ($discovered -notcontains "$name`: test") {
        throw "The staged NVX payload did not discover $name."
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $binaryDirectoryPath 'aci-edge-sandboxes\bundle-manifest.json') -PathType Leaf)) {
    throw 'The Windows x64 artifact is missing the signed NVX bundle.'
}
$signatureTests = @($messages |
    Where-Object { $_.StartsWith('{') } |
    ConvertFrom-Json |
    Where-Object {
        $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'nvx_bundle_integrity' -and
        $_.profile.test -and $_.executable
    })
if ($signatureTests.Count -ne 1) {
    throw "Expected one NVX bundle verification executable; found $($signatureTests.Count)."
}
$previousBundle = $env:ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR
try {
    $env:ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR = Join-Path $binaryDirectoryPath 'aci-edge-sandboxes'
    $signatureOutput = @(& $signatureTests[0].executable --exact crate_staged_bundle_opens_and_rejects_an_unverified_library --nocapture 2>&1)
    $signatureExit = $LASTEXITCODE
    $signatureOutput | ForEach-Object { Write-Host $_ }
    if ($signatureExit -ne 0) {
        throw "The staged NVX artifact failed signature and integrity validation with exit code $signatureExit."
    }
    if (($signatureOutput -join "`n") -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;') {
        throw 'The staged NVX signature verification did not execute its required test.'
    }
}
finally {
    $env:ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR = $previousBundle
}
Write-Host "Staged SDK MicroVM tests: $destination"
