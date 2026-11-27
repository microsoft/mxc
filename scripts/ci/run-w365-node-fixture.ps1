# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding(DefaultParameterSetName = 'BuildAndTest')]
param(
    [Parameter(Mandatory, ParameterSetName = 'BuildOnly')]
    [switch]$BuildOnly,

    [Parameter(Mandatory, ParameterSetName = 'Prebuilt')]
    [ValidateNotNullOrEmpty()]
    [string]$NativeDirectory
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$target = Join-Path $root 'src\target\w365-sdk-fixture'
$previousFfi = $env:MXC_FFI_DIR
$previousOpenSsl = $env:MXC_W365_TEST_OPENSSL

try {
    if ($PSCmdlet.ParameterSetName -ne 'Prebuilt') {
        Push-Location (Join-Path $root 'src')
        try {
            cargo build --locked -p mxc_ffi --features test-support --target-dir $target
            if ($LASTEXITCODE -ne 0) { throw 'W365 Node fixture native build failed' }
        } finally {
            Pop-Location
        }
        $NativeDirectory = Join-Path $target 'debug'
    }
    $library = if ($IsWindows) { 'mxc_ffi.dll' }
        elseif ($IsMacOS) { 'libmxc_ffi.dylib' }
        else { 'libmxc_ffi.so' }
    if (-not (Test-Path -LiteralPath (Join-Path $NativeDirectory $library) -PathType Leaf)) {
        throw "W365 Node fixture native library missing: $NativeDirectory\$library"
    }
    if ($BuildOnly) { return }
    $env:MXC_FFI_DIR = (Resolve-Path -LiteralPath $NativeDirectory).Path
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
