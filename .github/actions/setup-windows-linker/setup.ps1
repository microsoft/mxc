# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
    [string]$Target,

    [string]$EnvironmentFile = $env:GITHUB_ENV
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'The Windows Rust linker requires a Windows host.' }
if (-not $EnvironmentFile) { throw 'A GitHub Actions environment file is required.' }
Push-Location (Join-Path $PSScriptRoot '..\..\..\src')
try {
    $sysroot = rustc --print sysroot
    if ($LASTEXITCODE -ne 0) { throw 'Resolving the pinned Rust sysroot failed.' }
    $version = @(rustc -vV)
    if ($LASTEXITCODE -ne 0) { throw 'Resolving the Rust host failed.' }
} finally {
    Pop-Location
}
$hostLine = @($version | Where-Object { $_ -match '^host: ' })
if ($hostLine.Count -ne 1) { throw 'Expected exactly one Rust host target.' }
$hostTriple = $hostLine[0].Substring(6).Trim()
$linker = Join-Path $sysroot.Trim() "lib\rustlib\$hostTriple\bin\rust-lld.exe"
if (-not (Test-Path -LiteralPath $linker -PathType Leaf)) {
    throw "The pinned Rust toolchain is missing its bundled linker: $linker"
}
$key = 'CARGO_TARGET_' + $Target.ToUpperInvariant().Replace('-', '_') + '_LINKER'
"$key=$linker" | Add-Content -LiteralPath $EnvironmentFile -Encoding utf8NoBOM
Write-Host "Using the pinned Rust LLVM linker for ${Target}: $linker"
