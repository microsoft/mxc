<#
.SYNOPSIS
    Regenerates the committed WSLC SDK Rust bindings (`wslcsdk_sys.rs`) from the
    packaged C header using bindgen.

.DESCRIPTION
    The WSLC backend loads `wslcsdk.dll` at runtime via libloading. The Rust FFI
    surface is generated from `wslcsdk.h` by bindgen so that struct sizes, layout,
    and function signatures are derived directly from the header — any ABI drift
    becomes a compile error instead of silent undefined behavior.

    The generated file is COMMITTED to the repository. Normal builds simply `mod`
    it and require NO libclang or bindgen. This script only needs to run when the
    pinned WSLC SDK version changes (see `WSLC_SDK_VERSION` in
    `src/backends/wslc/common/build.rs`).

.PREREQUISITES
    - LLVM / libclang   (winget install LLVM.LLVM)  — provides libclang for bindgen
    - bindgen CLI       (cargo install bindgen-cli)
    - Visual Studio 2022 with the MSVC toolchain + a Windows 10/11 SDK

.NOTES
    The header is extracted from the vendored NuGet package checked into
    `external/wslc-sdk/` so the generated bindings always match the pinned SDK
    version, independent of any local build cache.
#>
[CmdletBinding()]
param(
    # Override the Windows SDK include version (defaults to the newest installed).
    [string] $WindowsSdkVersion,
    # Path to libclang's directory (defaults to the standard LLVM install).
    [string] $LibClangDir = "C:\Program Files\LLVM\bin"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot   = Split-Path -Parent $PSScriptRoot
$wslcCommon = Join-Path $repoRoot "src\backends\wslc\common"
$outFile    = Join-Path $wslcCommon "src\wslcsdk_sys.rs"
$vendorDir  = Join-Path $repoRoot "external\wslc-sdk"

function Fail($msg) { Write-Error $msg; exit 1 }

# --- 1. Locate the bindgen CLI --------------------------------------------------
$bindgen = $null
$cmd = Get-Command bindgen -ErrorAction SilentlyContinue
if ($cmd) { $bindgen = $cmd.Source }
if (-not $bindgen) { $bindgen = Join-Path $env:USERPROFILE ".cargo\bin\bindgen.exe" }
if (-not (Test-Path $bindgen)) {
    Fail "bindgen CLI not found. Install it with: cargo install bindgen-cli"
}

# --- 2. Locate libclang ---------------------------------------------------------
if (-not (Test-Path (Join-Path $LibClangDir "libclang.dll"))) {
    Fail "libclang.dll not found in '$LibClangDir'. Install LLVM (winget install LLVM.LLVM) or pass -LibClangDir."
}
$env:LIBCLANG_PATH = $LibClangDir

# --- 3. Locate the MSVC toolchain include (via vswhere) -------------------------
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { Fail "vswhere.exe not found; a Visual Studio install is required." }
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { Fail "No Visual Studio install with the MSVC toolchain was found." }
$msvcRoot = Join-Path $vsPath "VC\Tools\MSVC"
$msvcVer  = Get-ChildItem $msvcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
$msvcInc  = Join-Path $msvcVer.FullName "include"
if (-not (Test-Path $msvcInc)) { Fail "MSVC include directory not found at '$msvcInc'." }

# --- 4. Locate the Windows SDK include ------------------------------------------
$sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\Include"
if (-not (Test-Path $sdkRoot)) { Fail "Windows SDK include root not found at '$sdkRoot'." }
if (-not $WindowsSdkVersion) {
    $WindowsSdkVersion = (Get-ChildItem $sdkRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1).Name
}
$sdkInc = Join-Path $sdkRoot $WindowsSdkVersion
if (-not (Test-Path (Join-Path $sdkInc "um\windows.h"))) {
    Fail "windows.h not found under '$sdkInc\um'. Check the installed Windows SDK version."
}

Write-Host "Toolchain:"
Write-Host "  bindgen : $bindgen"
Write-Host "  libclang: $LibClangDir"
Write-Host "  MSVC    : $msvcInc"
Write-Host "  WinSDK  : $sdkInc"

# --- 5. Extract wslcsdk.h from the vendored NuGet package -----------------------
$nupkg = Get-ChildItem $vendorDir -Filter "*.nupkg" | Sort-Object Name -Descending | Select-Object -First 1
if (-not $nupkg) { Fail "No vendored .nupkg found in '$vendorDir'." }

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("wslc-bindgen-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $staging | Out-Null
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg.FullName)
    try {
        $entry = $zip.Entries | Where-Object { $_.FullName -ieq "include/wslcsdk.h" } | Select-Object -First 1
        if (-not $entry) { Fail "include/wslcsdk.h not found inside '$($nupkg.Name)'." }
        $headerPath = Join-Path $staging "wslcsdk.h"
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $headerPath, $true)
    } finally { $zip.Dispose() }

    # bindgen needs the header findable by a stable include; write a wrapper.
    $wrapper = Join-Path $staging "wrapper.h"
    Set-Content -Path $wrapper -Value '#include "wslcsdk.h"' -Encoding ascii

    # --- 6. License + generated-file header (bindgen --raw-line) ----------------
    $rawLines = @(
        '// Copyright (c) Microsoft Corporation.',
        '// Licensed under the MIT License.',
        '//',
        '// @generated by scripts/generate-wslc-bindings.ps1 from the WSLC SDK header',
        '// (Microsoft.WSL.Containers wslcsdk.h). DO NOT EDIT BY HAND -- re-run the',
        '// script after bumping WSLC_SDK_VERSION in build.rs and commit the result.',
        '#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, dead_code)]',
        '#![allow(clippy::all)]'
    )

    # --- 7. Run bindgen ---------------------------------------------------------
    $bitfieldEnums = 'Wslc(ContainerFlags|SessionFeatureFlags|ContainerStartFlags|DeleteContainerFlags|ComponentFlags|VhdRequirementsFlags)'
    $newtypeEnums  = 'Wslc(PortProtocol|Signal|ProcessIOHandle|ContainerNetworkingMode|VhdType|SessionTerminationReason|ContainerState|ProcessState|ImageProgressStatus)'

    $bindgenArgs = @(
        $wrapper,
        "--dynamic-loading", "WslcSdk",
        "--allowlist-file", ".*wslcsdk\.h",
        "--bitfield-enum", $bitfieldEnums,
        "--newtype-enum", $newtypeEnums
        # Layout size/offset asserts are KEPT (default) for ABI-drift safety.
    )
    foreach ($l in $rawLines) { $bindgenArgs += @("--raw-line", $l) }
    $bindgenArgs += @(
        "-o", $outFile,
        "--",
        "--target=x86_64-pc-windows-msvc",
        "-fms-compatibility", "-fms-extensions",
        "-I$staging",
        "-I$msvcInc",
        "-I$sdkInc\ucrt",
        "-I$sdkInc\shared",
        "-I$sdkInc\um",
        "-I$sdkInc\winrt"
    )

    Write-Host "Running bindgen -> $outFile"
    & $bindgen @bindgenArgs
    if ($LASTEXITCODE -ne 0) { Fail "bindgen failed with exit code $LASTEXITCODE." }

    $size = (Get-Item $outFile).Length
    Write-Host "Generated $outFile ($size bytes)."
    Write-Host "Next: build with `--features wslc` on Windows, run cargo fmt/clippy, and commit."
}
finally {
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
}
