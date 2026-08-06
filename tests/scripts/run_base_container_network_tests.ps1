# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$targetTriple = "x86_64-pc-windows-msvc"
$cargoArgs = @()
if ($Release) {
    $cargoArgs += "--release"
}

Push-Location (Join-Path $repoRoot "src")
try {
    cargo build @cargoArgs `
        -p wxc `
        -p wxc_test_proxy `
        --target $targetTriple
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $env:MXC_E2E_HOST_PREPPED = "1"
    cargo test @cargoArgs `
        -p wxc_e2e_tests `
        --target $targetTriple `
        --test e2e_windows `
        test_processcontainer_network_v08 `
        -- `
        --nocapture
    exit $LASTEXITCODE
}
finally {
    Remove-Item Env:\MXC_E2E_HOST_PREPPED -ErrorAction SilentlyContinue
    Pop-Location
}
