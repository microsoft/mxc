<#
.SYNOPSIS
    Regenerates the FlatBuffers Rust bindings for the
    `mxc_sdk::process_security_environment_spec` module, reproducibly.

.DESCRIPTION
    Runs `flatc` against external/windows-sdk/ProcessSecurityEnvironment.fbs and
    rewrites the output into the SDK module layout. Before generating it:
      * validates the vendored schema's SHA-256 against the recorded provenance
        (external/windows-sdk/ProcessSecurityEnvironment.provenance.toml), and
      * pins the EXACT flatc version recorded in that provenance file, so the
        generated output is byte-reproducible.

    The generated files are checked in and must NOT be hand-edited; rerun this
    script instead. The CI drift gate (scripts/versioning/check-psec-codegen.js)
    fails if the committed schema or generated module drifts.

.PARAMETER Flatc
    Path to flatc.exe. Defaults to "flatc.exe" (must be on PATH).

.EXAMPLE
    pwsh -File scripts/versioning/regenerate-psec.ps1
#>
[CmdletBinding()]
param(
    [string]$Flatc = "flatc.exe"
)

$ErrorActionPreference = 'Stop'

$repoRoot = (& git rev-parse --show-toplevel) 2>$null
if (-not $repoRoot) {
    throw "Not inside a git repository."
}
Set-Location $repoRoot

$moduleDir = Join-Path $repoRoot "src\mxc-sdk\src\core\process_security_environment_spec"
$generatedDir = Join-Path $moduleDir ".generated-$PID"
$fbs = "external\windows-sdk\ProcessSecurityEnvironment.fbs"
$provenanceFile = "external\windows-sdk\ProcessSecurityEnvironment.provenance.toml"

if (-not (Test-Path $fbs)) {
    throw "FlatBuffers schema not found: $fbs"
}
if (-not (Test-Path $provenanceFile)) {
    throw "Provenance file not found: $provenanceFile"
}
if (-not (Test-Path $Flatc) -and -not (Get-Command $Flatc -ErrorAction SilentlyContinue)) {
    throw "flatc not found: $Flatc. Download from https://github.com/google/flatbuffers/releases"
}

# --- Read pinned toolchain + expected schema hash from provenance ------------
$provenance = Get-Content $provenanceFile -Raw
$pinnedFlatc = [regex]::Match($provenance, 'flatc_version\s*=\s*"([^"]+)"')
$expectedHash = [regex]::Match($provenance, 'sha256\s*=\s*"([^"]+)"')
if (-not $pinnedFlatc.Success) {
    throw "Could not read flatc_version from $provenanceFile"
}
if (-not $expectedHash.Success) {
    throw "Could not read schema sha256 from $provenanceFile"
}
$pinnedFlatcVersion = $pinnedFlatc.Groups[1].Value
$expectedSchemaHash = $expectedHash.Groups[1].Value.ToLower()

# --- Validate the vendored schema hash matches provenance --------------------
# Hash the LF-normalized content so the check is checkout-independent (autocrlf).
$schemaText = (Get-Content $fbs -Raw) -replace "`r`n", "`n"
$schemaBytes = [System.Text.Encoding]::UTF8.GetBytes($schemaText)
$sha = [System.Security.Cryptography.SHA256]::Create()
$actualSchemaHash = (($sha.ComputeHash($schemaBytes) | ForEach-Object { $_.ToString("x2") }) -join "")
if ($actualSchemaHash -ne $expectedSchemaHash) {
    throw "Schema hash mismatch for $fbs.`n  expected (provenance): $expectedSchemaHash`n  actual   (on disk):    $actualSchemaHash`nIf you intentionally refreshed the schema, update $provenanceFile (sha256 + source revision) first."
}
Write-Host "Schema hash OK ($expectedSchemaHash)" -ForegroundColor Cyan

# --- Pin the EXACT flatc version for reproducible output ---------------------
$versionOutput = (& $Flatc --version) 2>&1 | Out-String
$match = [regex]::Match($versionOutput, 'flatc version (\d+\.\d+\.\d+)')
if (-not $match.Success) {
    throw "Could not parse flatc version from output: $versionOutput"
}
$flatcVersion = $match.Groups[1].Value
if ($flatcVersion -ne $pinnedFlatcVersion) {
    throw "flatc version $flatcVersion does not match the pinned version $pinnedFlatcVersion (from $provenanceFile). Install the exact version for reproducible output: https://github.com/google/flatbuffers/releases/tag/v$pinnedFlatcVersion"
}
Write-Host "Using pinned flatc version $flatcVersion" -ForegroundColor Cyan

Write-Host "Running flatc..." -ForegroundColor Cyan
try {
    New-Item -ItemType Directory -Path $generatedDir | Out-Null
    & $Flatc `
        --rust --gen-object-api --force-empty --no-prefix --rust-module-root-file --gen-all `
        -o $generatedDir `
        $fbs
    if ($LASTEXITCODE -ne 0) {
        throw "flatc failed with exit code $LASTEXITCODE"
    }

    Write-Host "Replacing generated module files..." -ForegroundColor Cyan
    $moduleRoot = Join-Path $moduleDir "mod.rs"
    $layoutDir = Join-Path $moduleDir "process_security_environment_layout"
    if (Test-Path $moduleRoot) {
        Remove-Item $moduleRoot -Force
    }
    if (Test-Path $layoutDir) {
        Remove-Item $layoutDir -Recurse -Force
    }
    Move-Item (Join-Path $generatedDir "mod.rs") $moduleRoot
    Move-Item (Join-Path $generatedDir "process_security_environment_layout") $layoutDir

    Write-Host "Patching mod.rs (lint suppression)..." -ForegroundColor Cyan
    (Get-Content $moduleRoot) `
        -replace '// @generated', "// @generated`n#![allow(unused_imports, non_snake_case, non_camel_case_types, clippy::all)]" |
        Set-Content $moduleRoot

    Write-Host "Formatting with cargo fmt..." -ForegroundColor Cyan
    Push-Location src
    try {
        & cargo fmt -p mxc-sdk
        if ($LASTEXITCODE -ne 0) {
            throw "cargo fmt failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    Write-Host "Done. Regenerated bindings in $moduleDir" -ForegroundColor Green
} finally {
    if (Test-Path $generatedDir) {
        Remove-Item $generatedDir -Recurse -Force
    }
}
