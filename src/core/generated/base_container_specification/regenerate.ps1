<#
.SYNOPSIS
    Regenerates the FlatBuffers Rust bindings for the base_container_specification crate.

.DESCRIPTION
    Runs `flatc` against external/windows-sdk/BaseContainerSpecification.fbs and
    rewrites the output to match the crate's module layout. Must be run from the
    repository root.

.PARAMETER Flatc
    Path to flatc.exe. Defaults to "flatc.exe" (must be on PATH).

.EXAMPLE
    pwsh -File src/core/generated/base_container_specification/regenerate.ps1
#>
[CmdletBinding()]
param(
    [string]$Flatc = "flatc.exe"
)

$ErrorActionPreference = 'Stop'

# Resolve repo root (two levels up from this script's directory's parents)
$repoRoot = (& git rev-parse --show-toplevel) 2>$null
if (-not $repoRoot) {
    throw "Not inside a git repository. Run from the repo root."
}
Set-Location $repoRoot

$crateDir = "src\core\generated\base_container_specification"
$srcDir   = Join-Path $crateDir "src"
$fbs      = "external\windows-sdk\BaseContainerSpecification.fbs"

if (-not (Test-Path $fbs)) {
    throw "FlatBuffers schema not found: $fbs"
}
if (-not (Get-Command $Flatc -ErrorAction SilentlyContinue)) {
    throw "flatc not found: $Flatc. Download from https://github.com/google/flatbuffers/releases"
}

# Require flatc >= 25.12.19. Older versions emit elided lifetimes that trigger
# the `mismatched_lifetime_syntaxes` lint (added in Rust 1.89). Fixed upstream
# in flatbuffers PR #8709, first released in v25.12.19.
$minFlatcVersion = [version]'25.12.19'
$versionOutput = (& $Flatc --version) 2>&1 | Out-String
$match = [regex]::Match($versionOutput, 'flatc version (\d+\.\d+\.\d+)')
if (-not $match.Success) {
    throw "Could not parse flatc version from output: $versionOutput"
}
$flatcVersion = [version]$match.Groups[1].Value
if ($flatcVersion -lt $minFlatcVersion) {
    throw "flatc version $flatcVersion is too old. Minimum required: $minFlatcVersion. Download a newer build from https://github.com/google/flatbuffers/releases"
}
Write-Host "Using flatc version $flatcVersion" -ForegroundColor Cyan

Write-Host "Cleaning previous generated output..." -ForegroundColor Cyan
if (Test-Path $srcDir) {
    Remove-Item $srcDir -Recurse -Force
}

Write-Host "Running flatc..." -ForegroundColor Cyan
& $Flatc `
    --rust --gen-object-api --force-empty --no-prefix --rust-module-root-file --gen-all `
    -o $crateDir `
    $fbs
if ($LASTEXITCODE -ne 0) { throw "flatc failed with exit code $LASTEXITCODE" }

Write-Host "Reorganizing generated files..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $srcDir | Out-Null
Move-Item (Join-Path $crateDir "mod.rs") (Join-Path $srcDir "lib.rs")
Move-Item (Join-Path $crateDir "sandbox_tech_spec_layout") (Join-Path $srcDir "base_container_layout")

Write-Host "Patching lib.rs..." -ForegroundColor Cyan
$libRs = Join-Path $srcDir "lib.rs"
(Get-Content $libRs) `
    -replace 'pub mod sandbox_tech_spec_layout', 'pub mod base_container_layout' `
    -replace '// @generated', "// @generated`n#![allow(unused_imports, non_snake_case, non_camel_case_types, clippy::all)]" |
    Set-Content $libRs

Write-Host "Formatting with cargo fmt..." -ForegroundColor Cyan
Push-Location src
try {
    & cargo fmt -p sandbox_spec
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

Write-Host "Done. Regenerated bindings in $srcDir" -ForegroundColor Green
