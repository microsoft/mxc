<#
.SYNOPSIS
    Builds the MXC isolation-session test package zip for deployment to
    Windows 11 targets with IsoEnvBroker (IsolationSession) APIs.

.DESCRIPTION
    Assembles Rust binaries, test configs, PS1 runners, and the Node.js
    SDK integration test suite into a single zip with a manifest.json.
    Designed to run in GitHub Actions (where binary artifacts are
    pre-downloaded) OR locally from a development machine with a full
    Rust + Node build.

    The produced zip is consumed by Invoke-MxcIsolationSessionTests.ps1.

.PARAMETER BinX64Path
    Path to the x64 Rust release binaries. Default: src/target/x86_64-pc-windows-msvc/release

.PARAMETER BinArm64Path
    Path to the arm64 Rust release binaries. Default: src/target/aarch64-pc-windows-msvc/release

.PARAMETER SdkTgzPath
    Path to the packed SDK .tgz. If omitted, skips sdk-integration bundling.

.PARAMETER OutputPath
    Directory to write the output zip. Default: current directory.

.PARAMETER RepoRoot
    Root of the MXC repository. Default: parent of this script's directory.

.EXAMPLE
    # In GitHub Actions (binaries already downloaded to _staging/bin/):
    .\Build-MxcIsolationSessionPackage.ps1 `
        -BinX64Path _staging/bin/x64 `
        -BinArm64Path _staging/bin/arm64 `
        -SdkTgzPath _staging/sdk-pkg/mxc-sdk-0.1.0.tgz

.EXAMPLE
    # Local build (after cargo build --release for both targets):
    .\Build-MxcIsolationSessionPackage.ps1
#>

[CmdletBinding()]
param(
    [string]$BinX64Path,
    [string]$BinArm64Path,
    [string]$SdkTgzPath,
    [string]$OutputPath = '.',
    [string]$RepoRoot
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# Resolve paths
# ============================================================================

if (-not $RepoRoot) {
    # Assume script lives in scripts/ci/ under the repo root
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

$rustBinaries = @(
    'wxc-exec.exe',
    'winhttp-proxy-shim.exe',
    'wxc-test-proxy.exe',
    'wxc-windows-sandbox-daemon.exe',
    'wxc-windows-sandbox-guest.exe'
)

if (-not $BinX64Path) {
    $BinX64Path = Join-Path $RepoRoot 'src/target/x86_64-pc-windows-msvc/release'
}
if (-not $BinArm64Path) {
    $BinArm64Path = Join-Path $RepoRoot 'src/target/aarch64-pc-windows-msvc/release'
}

# ============================================================================
# Staging directory
# ============================================================================

$stamp = (Get-Date).ToUniversalTime().ToString('yyMMdd-HHmmss')
$staging = Join-Path ([System.IO.Path]::GetTempPath()) "mxc-iso-pkg-$stamp"
New-Item -ItemType Directory -Path $staging -Force | Out-Null

Write-Host "==> Staging directory: $staging"

# ============================================================================
# 1. Binaries
# ============================================================================

Write-Host "==> Collecting binaries"

foreach ($arch in @(@{Name='x64'; Path=$BinX64Path}, @{Name='arm64'; Path=$BinArm64Path})) {
    $destDir = Join-Path $staging "bin/$($arch.Name)"
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null

    foreach ($exe in $rustBinaries) {
        $src = Join-Path $arch.Path $exe
        if (Test-Path $src) {
            Copy-Item $src $destDir
            Write-Host "  -> $($arch.Name)/$exe"
        } else {
            Write-Warning "  ! Missing: $src"
        }
    }
}

# ============================================================================
# 2. Test configs
# ============================================================================

Write-Host "==> Collecting test_configs"
$configsSrc = Join-Path $RepoRoot 'test_configs'
if (Test-Path $configsSrc) {
    Copy-Item -Recurse $configsSrc (Join-Path $staging 'test_configs')
} else {
    throw "test_configs/ not found at $configsSrc"
}

# ============================================================================
# 3. Test scripts (PS1 runners)
# ============================================================================

Write-Host "==> Collecting test_scripts"
$scriptsSrc = Join-Path $RepoRoot 'test_scripts'
if (Test-Path $scriptsSrc) {
    Copy-Item -Recurse $scriptsSrc (Join-Path $staging 'test_scripts')
} else {
    throw "test_scripts/ not found at $scriptsSrc"
}

# ============================================================================
# 4. SDK integration tests (optional — requires SdkTgzPath)
# ============================================================================

if ($SdkTgzPath -and (Test-Path $SdkTgzPath)) {
    Write-Host "==> Building sdk-integration tests"
    $integrationSrc = Join-Path $RepoRoot 'sdk/tests/integration'

    if (-not (Test-Path $integrationSrc)) {
        Write-Warning "  ! sdk/tests/integration not found; skipping"
    } else {
        Push-Location $integrationSrc
        try {
            & npm install (Resolve-Path $SdkTgzPath).Path
            & npm run build
        } finally {
            Pop-Location
        }

        $sdkDest = Join-Path $staging 'sdk-integration'
        New-Item -ItemType Directory -Path $sdkDest -Force | Out-Null
        Copy-Item (Join-Path $integrationSrc 'package.json') $sdkDest
        $runTests = Join-Path $integrationSrc 'run-tests.js'
        if (Test-Path $runTests) { Copy-Item $runTests $sdkDest }
        Copy-Item -Recurse (Join-Path $integrationSrc 'dist') (Join-Path $sdkDest 'dist')
        Copy-Item -Recurse (Join-Path $integrationSrc 'node_modules') (Join-Path $sdkDest 'node_modules')
        Write-Host "  -> sdk-integration bundled"
    }
} else {
    Write-Host "==> Skipping sdk-integration (no -SdkTgzPath provided)"
}

# ============================================================================
# 5. Manifest
# ============================================================================

Write-Host "==> Generating manifest.json"

$commitSha = ''
try {
    $commitSha = (& git -C $RepoRoot rev-parse HEAD 2>$null).Trim()
} catch { }

$manifest = @{
    format_version = 1
    produced_at    = (Get-Date).ToUniversalTime().ToString('o')
    producer       = @{
        host_arch   = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
        host_os     = (Get-CimInstance Win32_OperatingSystem).Caption
        powershell  = $PSVersionTable.PSVersion.ToString()
    }
    mxc = @{
        repo_url      = 'https://github.com/microsoft/mxc.git'
        commit_sha    = $commitSha
        cargo_version = '0.1.0'
    }
    contents = @{
        binaries     = @('bin/x64', 'bin/arm64')
        test_configs = 'test_configs/'
        ps1_runners  = @(
            'test_scripts/run_isolation_session_tests.ps1',
            'test_scripts/run_isolation_session_state_aware_tests.ps1'
        )
        node_e2e = 'sdk-integration/'
    }
}

$manifest | ConvertTo-Json -Depth 5 |
    Set-Content (Join-Path $staging 'manifest.json') -Encoding UTF8

# ============================================================================
# 6. Zip
# ============================================================================

$zipName = "mxc-iso-test-package-$stamp.zip"
$zipPath = Join-Path (Resolve-Path $OutputPath).Path $zipName

Write-Host "==> Creating $zipName"
Compress-Archive -Path "$staging\*" -DestinationPath $zipPath -Force

Write-Host ""
Write-Host "Package created: $zipPath" -ForegroundColor Green
Write-Host "  Size: $([math]::Round((Get-Item $zipPath).Length / 1MB, 1)) MB"
Write-Host ""

# ============================================================================
# Cleanup
# ============================================================================

Remove-Item -Recurse -Force $staging

return $zipPath
