# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
Checks bundled, unrouted, and tampered Windows telemetry component builds.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$srcRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\src')).Path
$originalTargetDirectory = $env:CARGO_TARGET_DIR
$originalComponentPath = $env:MXC_TELEMETRY_COMPONENT_PATH
$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) "mxc-telemetry-check-$([Guid]::NewGuid())"

Push-Location $srcRoot
try {
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
    $bundledComponent = Join-Path $srcRoot "mxc-sdk\resources\telemetry-component\$arch\mxc_telemetry.dll"
    if (-not (Test-Path -LiteralPath $bundledComponent -PathType Leaf)) {
        throw "Missing bundled telemetry component: $bundledComponent"
    }
    $env:CARGO_TARGET_DIR = Join-Path $srcRoot 'target\telemetry-component-check'
    Remove-Item Env:MXC_TELEMETRY_COMPONENT_PATH -ErrorAction SilentlyContinue

    cargo check --locked --release -p mxc-sdk --lib
    if ($LASTEXITCODE -ne 0) {
        throw 'Release build with the bundled telemetry component failed.'
    }

    $env:MXC_TELEMETRY_COMPONENT_PATH = ''
    cargo check --locked --release -p mxc-sdk --lib
    if ($LASTEXITCODE -ne 0) {
        throw 'Unrouted release build failed.'
    }

    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    $tamperedComponent = Join-Path $temporaryDirectory 'tampered_mxc_telemetry.dll'
    $componentBytes = [IO.File]::ReadAllBytes($bundledComponent)
    $tamperByteOffset = 2048
    $componentBytes[$tamperByteOffset] = $componentBytes[$tamperByteOffset] -bxor 0xFF
    [IO.File]::WriteAllBytes($tamperedComponent, $componentBytes)
    $env:MXC_TELEMETRY_COMPONENT_PATH = $tamperedComponent

    $ErrorActionPreference = 'Continue'
    $buildOutput = cargo check --locked --release -p mxc-sdk --lib 2>&1 | Out-String
    $tamperedExitCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Write-Host "Tampered build exit code: $tamperedExitCode"
    Write-Host ($buildOutput -split "`n" | Select-Object -Last 15 | Out-String)
    if ($tamperedExitCode -eq 0) {
        throw 'A tampered telemetry component was accepted.'
    }
    if ($buildOutput -notmatch 'no valid Authenticode signature') {
        throw "Tampered component failed for an unexpected reason:`n$buildOutput"
    }

    # Do not leave the expected Cargo failure as the caller's exit status.
    $global:LASTEXITCODE = 0
    Write-Host 'Telemetry component build checks passed.'
}
finally {
    $env:CARGO_TARGET_DIR = $originalTargetDirectory
    $env:MXC_TELEMETRY_COMPONENT_PATH = $originalComponentPath
    Pop-Location
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
