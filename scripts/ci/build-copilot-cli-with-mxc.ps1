#Requires -Version 7.0

<#
.SYNOPSIS
    Orchestrates building Copilot CLI against the current MXC source.

.DESCRIPTION
    Performs strict preflight checks, configures the MSVC build environment,
    rewrites the CLI's mxc-sdk dependency to use the local MXC checkout,
    verifies Cargo provenance, builds the runtime and CLI bundle, stages a
    job-local launcher, and writes a sanitized provenance manifest.

    Designed for 1ES CI on the 1es-mxc-windows-prerelease-t1-x64 pool.
    Must not be used as a general-purpose build tool.

.PARAMETER MxcRoot
    Root of the MXC source checkout.

.PARAMETER CliRoot
    Root of the Copilot CLI source checkout.

.PARAMETER StageRoot
    Directory for the staged CLI launcher and dist-cli bundle.

.PARAMETER ManifestPath
    Output path for the sanitized provenance manifest JSON.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$MxcRoot,
    [Parameter(Mandatory)][string]$CliRoot,
    [Parameter(Mandatory)][string]$StageRoot,
    [Parameter(Mandatory)][string]$ManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Reject invalid source roots before changing process build settings or touching
# the stage directory. This keeps bad invocations side-effect free.
if (-not (Test-Path -LiteralPath $MxcRoot -PathType Container)) {
    throw "MXC root does not exist or is not a directory: $MxcRoot"
}
if (-not (Test-Path -LiteralPath $CliRoot -PathType Container)) {
    throw "CLI root does not exist or is not a directory: $CliRoot"
}
$MxcRoot = (Resolve-Path -LiteralPath $MxcRoot).Path
$CliRoot = (Resolve-Path -LiteralPath $CliRoot).Path

$requiredSourceFiles = @(
    (Join-Path $MxcRoot 'src\core\mxc-sdk\Cargo.toml')
    (Join-Path $CliRoot 'package.json')
    (Join-Path $CliRoot 'rust-toolchain.toml')
    (Join-Path $CliRoot 'src\runtime\src\sandbox_engine\Cargo.toml')
)
$missingSourceFiles = @($requiredSourceFiles | Where-Object {
    -not (Test-Path -LiteralPath $_ -PathType Leaf)
})
if ($missingSourceFiles.Count -gt 0) {
    throw "Source checkout contract is incomplete. Missing:`n  - $($missingSourceFiles -join "`n  - ")"
}

$env:CARGO_BUILD_JOBS = '2'
$env:CARGO_INCREMENTAL = '0'

# Import the build helper module
$modulePath = Join-Path $PSScriptRoot 'CopilotCliMxcBuild.psm1'
Import-Module $modulePath -Force

# ---------------------------------------------------------------
# Step 1: Validate build prerequisites
# ---------------------------------------------------------------
Write-Host '=== Step 1: Validate build prerequisites ==='
Assert-CopilotCliBuildPrerequisites -WorkspacePath $MxcRoot

# ---------------------------------------------------------------
# Step 2: Enter MSVC build environment
# ---------------------------------------------------------------
Write-Host "`n=== Step 2: Enter MSVC build environment ==="
Enter-MsvcBuildEnvironment

# ---------------------------------------------------------------
# Step 3: Record exact source SHAs
# ---------------------------------------------------------------
Write-Host "`n=== Step 3: Record source SHAs ==="
$mxcSha = (git -C $MxcRoot rev-parse HEAD).Trim()
$cliSha = (git -C $CliRoot rev-parse HEAD).Trim()
if ($mxcSha -notmatch '^[0-9a-f]{40}$') {
    throw "Invalid MXC SHA: '$mxcSha'"
}
if ($cliSha -notmatch '^[0-9a-f]{40}$') {
    throw "Invalid CLI SHA: '$cliSha'"
}
Write-Host "MXC SHA: $mxcSha"
Write-Host "CLI SHA: $cliSha"

# ---------------------------------------------------------------
# Step 4: Install the Rust toolchain required by the CLI workspace
# ---------------------------------------------------------------
Write-Host "`n=== Step 4: Install Rust toolchain ==="
$toolchainFile = Join-Path $CliRoot 'rust-toolchain.toml'
if (-not (Test-Path $toolchainFile)) {
    throw "rust-toolchain.toml not found at $toolchainFile"
}
$toolchainContent = Get-Content $toolchainFile -Raw
$channelMatch = [regex]::Match($toolchainContent, 'channel\s*=\s*"([^"]+)"')
if (-not $channelMatch.Success) {
    throw "Could not parse channel from $toolchainFile"
}
$channel = $channelMatch.Groups[1].Value
Write-Host "Installing Rust toolchain: $channel"
& rustup toolchain install $channel --profile minimal
if ($LASTEXITCODE -ne 0) { throw "rustup toolchain install failed (exit $LASTEXITCODE)" }
& rustup target add x86_64-pc-windows-msvc --toolchain $channel
if ($LASTEXITCODE -ne 0) { throw "rustup target add failed (exit $LASTEXITCODE)" }
$env:RUSTUP_TOOLCHAIN = $channel
Write-Host "RUSTUP_TOOLCHAIN set to $channel"

# ---------------------------------------------------------------
# Step 5: Activate pnpm via Corepack
# ---------------------------------------------------------------
Write-Host "`n=== Step 5: Activate pnpm via Corepack ==="
$cliPackageJson = Join-Path $CliRoot 'package.json'
if (-not (Test-Path $cliPackageJson)) {
    throw "CLI package.json not found at $cliPackageJson"
}
$packageJson = Get-Content $cliPackageJson -Raw | ConvertFrom-Json
$packageManager = $packageJson.packageManager
if (-not $packageManager) {
    throw "No packageManager field in $cliPackageJson"
}
if ($packageManager -notmatch '^pnpm@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+sha(?:224|256|384|512)\.[A-Za-z0-9_-]+)?$') {
    throw "CLI packageManager must pin an exact pnpm version, found '$packageManager'."
}
Write-Host "packageManager: $packageManager"

$corepack = Get-Command corepack -ErrorAction SilentlyContinue
if (-not $corepack) {
    Write-Host 'Corepack not found; installing via npm...'
    & npm install -g corepack
    if ($LASTEXITCODE -ne 0) { throw "npm install -g corepack failed (exit $LASTEXITCODE)" }
}
& corepack enable pnpm
if ($LASTEXITCODE -ne 0) { throw "corepack enable pnpm failed (exit $LASTEXITCODE)" }
& corepack prepare $packageManager --activate
if ($LASTEXITCODE -ne 0) { throw "corepack prepare $packageManager --activate failed (exit $LASTEXITCODE)" }

# ---------------------------------------------------------------
# Step 6: Rewrite mxc-sdk dependency
# ---------------------------------------------------------------
Write-Host "`n=== Step 6: Rewrite mxc-sdk dependency ==="
Set-CopilotCliMxcDependency -CliRoot $CliRoot -MxcRoot $MxcRoot

# ---------------------------------------------------------------
# Step 7: Update Cargo lockfile for mxc-sdk
# ---------------------------------------------------------------
Write-Host "`n=== Step 7: Update Cargo lockfile ==="
$cliManifest = Join-Path $CliRoot 'src\runtime\src\sandbox_engine\Cargo.toml'
& cargo update -p mxc-sdk --manifest-path $cliManifest
if ($LASTEXITCODE -ne 0) { throw "cargo update -p mxc-sdk failed (exit $LASTEXITCODE)" }

# ---------------------------------------------------------------
# Step 8: Assert Cargo provenance before compilation
# ---------------------------------------------------------------
Write-Host "`n=== Step 8: Assert Cargo provenance ==="
Assert-CopilotCliMxcProvenance -CliRoot $CliRoot -MxcRoot $MxcRoot

# ---------------------------------------------------------------
# Step 9: Build the native addons
# ---------------------------------------------------------------
Write-Host "`n=== Step 9: Build native addons ==="
Push-Location $CliRoot
try {
    & pnpm install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { throw "pnpm install failed (exit $LASTEXITCODE)" }

    & pnpm run build:runtime
    if ($LASTEXITCODE -ne 0) { throw "pnpm run build:runtime failed (exit $LASTEXITCODE)" }

    & pnpm run build:native-addons
    if ($LASTEXITCODE -ne 0) { throw "pnpm run build:native-addons failed (exit $LASTEXITCODE)" }
}
finally {
    Pop-Location
}

$runtimeSource = Join-Path $CliRoot 'src\native\runtime\runtime.win32-x64-msvc.node'
if (-not (Test-Path $runtimeSource)) {
    throw "Runtime build output not found: $runtimeSource"
}
$runtimeSourceHash = (Get-FileHash $runtimeSource -Algorithm SHA256).Hash.ToLower()
Write-Host "Runtime source hash: $runtimeSourceHash"

# ---------------------------------------------------------------
# Step 10: Build the CLI bundle
# ---------------------------------------------------------------
Write-Host "`n=== Step 10: Build CLI bundle ==="
Push-Location $CliRoot
try {
    $env:COPILOT_NAPI_ADDONS_PREBUILT = '1'
    & pnpm run build
    if ($LASTEXITCODE -ne 0) { throw "pnpm run build failed (exit $LASTEXITCODE)" }
}
finally {
    Pop-Location
}

$distIndex = Join-Path $CliRoot 'dist-cli\index.js'
$runtimeBundle = Join-Path $CliRoot 'dist-cli\prebuilds\win32-x64\runtime.node'
if (-not (Test-Path $distIndex)) {
    throw "CLI bundle not found: $distIndex"
}
if (-not (Test-Path $runtimeBundle)) {
    throw "Bundled runtime not found: $runtimeBundle"
}
$runtimeBundleHash = (Get-FileHash $runtimeBundle -Algorithm SHA256).Hash.ToLower()
Write-Host "Runtime bundle hash: $runtimeBundleHash"

if ($runtimeSourceHash -ne $runtimeBundleHash) {
    throw "Runtime hash mismatch! Source=$runtimeSourceHash Bundle=$runtimeBundleHash. The bundled runtime must be identical to the compiled runtime."
}
Write-Host 'Runtime source and bundle hashes match.'

# ---------------------------------------------------------------
# Step 11: Stage job-local CLI
# ---------------------------------------------------------------
Write-Host "`n=== Step 11: Stage job-local CLI ==="
if (Test-Path $StageRoot) {
    Remove-Item $StageRoot -Recurse -Force
}
New-Item -Path $StageRoot -ItemType Directory -Force | Out-Null
Copy-Item -Path (Join-Path $CliRoot 'dist-cli') -Destination (Join-Path $StageRoot 'dist-cli') -Recurse

$nodeExe = (Get-Command node).Source
# NOTE: Future permission-sensitive tests must invoke Node and index.js directly
# because %* forwarding in a .cmd wrapper can change argument boundaries.
$launcherContent = "@echo off`r`n`"$nodeExe`" `"%~dp0dist-cli\index.js`" %*"
Set-Content -Path (Join-Path $StageRoot 'copilot-mxc-test.cmd') -Value $launcherContent -Encoding ascii
Write-Host "Staged CLI at $StageRoot"

# ---------------------------------------------------------------
# Step 12: Smoke test CLI
# ---------------------------------------------------------------
Write-Host "`n=== Step 12: Smoke test CLI ==="
$launcherExe = Join-Path $StageRoot 'copilot-mxc-test.cmd'
$launcherVersion = & $launcherExe --version 2>&1 | Out-String
$launcherVersion = $launcherVersion.Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Launcher --version failed (exit $LASTEXITCODE): $launcherVersion"
}
Write-Host "Launcher version: $launcherVersion"

$directVersion = & $nodeExe (Join-Path $StageRoot 'dist-cli\index.js') --version 2>&1 | Out-String
$directVersion = $directVersion.Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Direct Node entry --version failed (exit $LASTEXITCODE): $directVersion"
}
Write-Host "Direct version: $directVersion"

if ($launcherVersion -ne $directVersion) {
    throw "Version mismatch between launcher ('$launcherVersion') and direct entry ('$directVersion')."
}
if ($launcherVersion -notmatch '^GitHub Copilot CLI [^\\/\r\n]+$') {
    throw "Unexpected CLI version output: '$launcherVersion'"
}
Write-Host 'Launcher and direct entry point produce identical version output.'

# ---------------------------------------------------------------
# Step 13: Write sanitized provenance manifest
# ---------------------------------------------------------------
Write-Host "`n=== Step 13: Write sanitized provenance manifest ==="
New-CopilotCliMxcManifest `
    -ManifestPath $ManifestPath `
    -MxcSha $mxcSha `
    -CliSha $cliSha `
    -MxcSdkManifest 'src/core/mxc-sdk/Cargo.toml' `
    -RuntimeSourceSha256 $runtimeSourceHash `
    -RuntimeBundleSha256 $runtimeBundleHash `
    -CliVersion $launcherVersion `
    -CargoBuildJobs ([int]$env:CARGO_BUILD_JOBS)

Write-Host "`n=== Build and staging complete ==="
