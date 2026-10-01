<#
.SYNOPSIS
    Reproducibly regenerates the PSEC specification and experimental PSEP result bindings.
.DESCRIPTION
    Validates both vendored schema hashes and the exact flatc version in
    external/windows-sdk/ProcessSecurityEnvironment.provenance.toml.
    Generated Rust files are checked in and must not be hand-edited.
.PARAMETER Flatc
    Path to the pinned flatc.exe. Defaults to flatc.exe on PATH.
#>
[CmdletBinding()]
param([string]$Flatc = 'flatc.exe')
$ErrorActionPreference = 'Stop'
$repoRoot = (& git rev-parse --show-toplevel) 2>$null
if (-not $repoRoot) { throw 'Not inside a git repository.' }
Set-Location $repoRoot
$provenance = Get-Content 'external\windows-sdk\ProcessSecurityEnvironment.provenance.toml' -Raw
$pinned = [regex]::Match($provenance, 'flatc_version\s*=\s*"([^"]+)"')
if (-not $pinned.Success) { throw 'Missing pinned flatc version.' }
$reported = & $Flatc --version 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or
    -not ($reported -match 'flatc version (\d+\.\d+\.\d+)') -or
    $Matches[1] -ne $pinned.Groups[1].Value) {
    throw "flatc must match pinned version $($pinned.Groups[1].Value): $reported"
}
$contracts = @(
    @{Name='ProcessSecurityEnvironment'; Section='schema';
      Module='process_security_environment_spec'; Layout='process_security_environment_layout'},
    @{Name='ExperimentalProcessSecurityEnvironmentPolicyResult'; Section='policy_result';
      Module='process_security_environment_policy_result'; Layout='experimental_process_security_environment_policy_result'}
)
foreach ($contract in $contracts) {
    $section = [regex]::Match($provenance,
        '(?ms)^\[' + [regex]::Escape($contract.Section) + '\]\s*(.*?)(?=^\[|\z)')
    $expected = [regex]::Match($section.Groups[1].Value, 'sha256\s*=\s*"([^"]+)"')
    if (-not $expected.Success) { throw "Missing schema hash: $($contract.Name)" }
    $schema = "external\windows-sdk\$($contract.Name).fbs"
    $text = [IO.File]::ReadAllText((Join-Path $repoRoot $schema)).Replace("`r`n","`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($actual -ne $expected.Groups[1].Value) {
        throw "Schema hash differs from provenance: $schema"
    }
}
foreach ($contract in $contracts) {
    $module = Join-Path $repoRoot "src\mxc-sdk\src\core\$($contract.Module)"
    $generated = Join-Path $module ".generated-$PID"
    try {
        New-Item -ItemType Directory -Path $generated -ErrorAction Stop | Out-Null
        & $Flatc --rust --gen-object-api --force-empty --no-prefix --rust-module-root-file --gen-all `
            -o $generated "external\windows-sdk\$($contract.Name).fbs"
        if ($LASTEXITCODE -ne 0) { throw "flatc failed: $($contract.Name)" }
        foreach ($name in @('mod.rs',$contract.Layout)) {
            $destination = Join-Path $module $name
            if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force }
            Move-Item -LiteralPath (Join-Path $generated $name) -Destination $destination
        }
        $root = Join-Path $module 'mod.rs'
        $body = [IO.File]::ReadAllText($root).Replace('// @generated',
            "// @generated`n#![allow(unused_imports, non_snake_case, non_camel_case_types, clippy::all)]")
        [IO.File]::WriteAllText($root,$body,[Text.UTF8Encoding]::new($false))
        Write-Host "Regenerated $($contract.Name) with flatc $($pinned.Groups[1].Value)"
    } finally {
        if (Test-Path -LiteralPath $generated) { Remove-Item -LiteralPath $generated -Recurse -Force }
    }
}
Push-Location src
try {
    & cargo fmt -p mxc-sdk
    if ($LASTEXITCODE -ne 0) { throw 'cargo fmt failed.' }
} finally { Pop-Location }
