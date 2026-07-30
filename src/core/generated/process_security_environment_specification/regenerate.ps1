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

$crateDir = $PSScriptRoot
$srcDir = Join-Path $crateDir "src"
$fbs = "external\windows-sdk\ProcessSecurityEnvironment.fbs"

if (-not (Test-Path $fbs)) {
    throw "FlatBuffers schema not found: $fbs"
}
if (-not (Test-Path $Flatc) -and -not (Get-Command $Flatc -ErrorAction SilentlyContinue)) {
    throw "flatc not found: $Flatc"
}

$minFlatcVersion = [version]'25.12.19'
$versionOutput = (& $Flatc --version) 2>&1 | Out-String
$match = [regex]::Match($versionOutput, 'flatc version (\d+\.\d+\.\d+)')
if (-not $match.Success) {
    throw "Could not parse flatc version: $versionOutput"
}
if ([version]$match.Groups[1].Value -lt $minFlatcVersion) {
    throw "flatc must be at least $minFlatcVersion"
}

if (Test-Path $srcDir) {
    Remove-Item $srcDir -Recurse -Force
}

& $Flatc `
    --rust --gen-object-api --force-empty --no-prefix --rust-module-root-file --gen-all `
    -o $crateDir `
    $fbs
if ($LASTEXITCODE -ne 0) {
    throw "flatc failed with exit code $LASTEXITCODE"
}

New-Item -ItemType Directory -Path $srcDir | Out-Null
Move-Item (Join-Path $crateDir "mod.rs") (Join-Path $srcDir "lib.rs")
Move-Item (Join-Path $crateDir "process_security_environment_layout") `
    (Join-Path $srcDir "process_security_environment_layout")

$libRs = Join-Path $srcDir "lib.rs"
(Get-Content $libRs) `
    -replace '// @generated', "// @generated`n#![allow(unused_imports, non_snake_case, non_camel_case_types, clippy::all)]" |
    Set-Content $libRs

Push-Location src
try {
    & cargo fmt -p process_security_environment_spec
    if ($LASTEXITCODE -ne 0) {
        throw "cargo fmt failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}
