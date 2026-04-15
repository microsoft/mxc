<#
.SYNOPSIS
    Packages the MXC CLI, SDK, native binaries, test configs, and test scripts
    into a ZIP that can be copied to a VM and extracted to C:\mxc.

.DESCRIPTION
    Creates mxc-test-package.zip in the repo root containing:
      cli/          - compiled CLI (dist + runtime deps only + package.json)
      sdk/          - compiled SDK (dist + bin + runtime deps only + package.json)
      test_configs/ - JSON test configuration files
      test_scripts/ - batch/shell test runner scripts
      examples/     - example configs

    On the VM, extract to C:\mxc and run:
      node C:\mxc\cli\dist\index.js <args>

.PARAMETER OutPath
    Output ZIP path. Default: <repo>\mxc-test-package.zip

.PARAMETER SkipBuild
    Skip building CLI/SDK (use existing dist/ output).
#>
param(
    [string]$OutPath,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

if (-not $OutPath) {
    $OutPath = Join-Path $env:temp 'mxc-test-package.zip'
}

# --- Build if needed ---
if (-not $SkipBuild) {
    Write-Host "[1/4] Building SDK..." -ForegroundColor Cyan
    Push-Location (Join-Path $RepoRoot 'sdk')
    npm install --quiet 2>&1 | Out-Null
    npm run build
    Pop-Location

    Write-Host "[2/4] Building CLI..." -ForegroundColor Cyan
    Push-Location (Join-Path $RepoRoot 'cli')
    npm install --quiet 2>&1 | Out-Null
    npm run build
    Pop-Location
} else {
    Write-Host "[1/4] Skipping SDK build (--SkipBuild)" -ForegroundColor Yellow
    Write-Host "[2/4] Skipping CLI build (--SkipBuild)" -ForegroundColor Yellow
}

# --- Stage into temp directory ---
Write-Host "[3/4] Staging files..." -ForegroundColor Cyan
$repoHash = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($RepoRoot)
    )
).Replace('-','').Substring(0,8).ToLower()
$staging = Join-Path ([System.IO.Path]::GetTempPath()) "mxc-vm-pack-$repoHash"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging -Force | Out-Null
Write-Host "Staging path: $staging" -ForegroundColor Gray

function Copy-Filtered {
    param([string]$Src, [string]$Dst, [string[]]$Exclude)
    $robocopyArgs = @($Src, $Dst, '/E', '/NJH', '/NJS', '/NP', '/NFL', '/NDL')
    foreach ($ex in $Exclude) { $robocopyArgs += '/XD'; $robocopyArgs += $ex }
    & robocopy @robocopyArgs | Out-Null
}

# SDK: dist, bin, package.json + runtime-only node_modules
$sdkStage = Join-Path $staging 'sdk'
New-Item -ItemType Directory -Path $sdkStage -Force | Out-Null
Copy-Item (Join-Path $RepoRoot 'sdk\package.json') $sdkStage
Copy-Filtered (Join-Path $RepoRoot 'sdk\dist') (Join-Path $sdkStage 'dist')
Copy-Filtered (Join-Path $RepoRoot 'sdk\bin') (Join-Path $sdkStage 'bin')
# Runtime deps only: node-pty (+ its dep node-addon-api), semver
foreach ($mod in @('node-pty', 'node-addon-api', 'semver')) {
    Copy-Filtered (Join-Path $RepoRoot "sdk\node_modules\$mod") (Join-Path $sdkStage "node_modules\$mod")
}

# CLI: dist, package.json + runtime-only node_modules
$cliStage = Join-Path $staging 'cli'
New-Item -ItemType Directory -Path $cliStage -Force | Out-Null
Copy-Item (Join-Path $RepoRoot 'cli\package.json') $cliStage
Copy-Filtered (Join-Path $RepoRoot 'cli\dist') (Join-Path $cliStage 'dist')
# Runtime deps only: commander, @microsoft/mxc-sdk (symlink to staged sdk)
Copy-Filtered (Join-Path $RepoRoot 'cli\node_modules\commander') (Join-Path $cliStage 'node_modules\commander')
$sdkLink = Join-Path $cliStage 'node_modules\@microsoft\mxc-sdk'
New-Item -ItemType Directory -Path (Split-Path $sdkLink) -Force | Out-Null
Copy-Filtered $sdkStage $sdkLink

# Test configs
Copy-Filtered (Join-Path $RepoRoot 'test_configs') (Join-Path $staging 'test_configs')

# Test scripts
Copy-Filtered (Join-Path $RepoRoot 'test_scripts') (Join-Path $staging 'test_scripts')

# Examples
Copy-Filtered (Join-Path $RepoRoot 'examples') (Join-Path $staging 'examples')

# --- Create ZIP ---
Write-Host "[4/4] Creating $OutPath ..." -ForegroundColor Cyan
if (Test-Path $OutPath) { Remove-Item $OutPath -Force }
Compress-Archive -Path "$staging\*" -DestinationPath $OutPath -CompressionLevel Optimal

$size= [math]::Round((Get-Item $OutPath).Length / 1MB, 1)
Write-Host "`nDone! Package: $OutPath ($size MB)" -ForegroundColor Green
Write-Host @"

--- On the VM ---
1. Copy mxc-test-package.zip to VM
     $OutPath
2. Extract to C:\mxc:
     Expand-Archive $OutPath -DestinationPath C:\mxc
3. Run npm test:
     cd C:\mxc\cli
     npm test
"@
