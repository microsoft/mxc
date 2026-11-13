# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$target = Join-Path $root 'src\target\w365-sdk-fixture'
$previousFfi = $env:MXC_FFI_DIR
$previousOpenSsl = $env:MXC_W365_TEST_OPENSSL

try {
    Push-Location (Join-Path $root 'src')
    try {
        cargo build --locked -p mxc_ffi --features test-support --target-dir $target
        if ($LASTEXITCODE -ne 0) { throw 'W365 Node fixture native build failed' }
    } finally {
        Pop-Location
    }
    $env:MXC_FFI_DIR = Join-Path $target 'debug'
    if ($IsWindows -and -not $env:MXC_W365_TEST_OPENSSL) {
        $env:MXC_W365_TEST_OPENSSL = Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'
    }
    Push-Location (Join-Path $root 'sdk\node\tests\integration')
    try {
        if (-not (Test-Path 'dist\w365-fixture.js')) {
            throw 'Build the Node SDK integration tests before running the W365 fixture'
        }
        node --test dist/w365-fixture.js
        if ($LASTEXITCODE -ne 0) { throw 'W365 Node Dev JSON fixture failed' }
    } finally {
        Pop-Location
    }
} finally {
    $env:MXC_FFI_DIR = $previousFfi
    $env:MXC_W365_TEST_OPENSSL = $previousOpenSsl
}
