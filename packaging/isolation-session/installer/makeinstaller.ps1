# Copyright (c) Microsoft Corporation. All rights reserved.
#
# Build script for the IsoSession UI installer.
#
# Produces, for a given monthly release AND target architecture:
#   1. IsoSession_<month>_<arch>.msi          - the MSI (WiX v5, from IsoSessionInstaller.wixproj)
#   2. IsoSessionSetup_<month>_<arch>.exe      - the user-facing UI installer that wraps
#                                                the MSI (WiX v5 bundle, from IsoSessionBundle.wixproj)
#
# The bundle uses a WixStandardBootstrapperApplication (rtfLicense theme + logo),
# modeled on the PowerToys bootstrapper, and chains a terminate step + the MSI.
#
# Side-by-side monthly releases: each month gets unique deterministic GUIDs
# (MSI UpgradeCode, bundle UpgradeCode, COM AppID, CLSIDs) derived from
# MonthId. x64 and arm64 packages preserve the same monthly runtime identity
# because the OS binaries resolve service names, registry keys, and install
# directories from MonthId alone. The architecture changes the native package
# platform and output filename, not that runtime contract.
#
# Prerequisites:
#   - .NET SDK (dotnet) on PATH — WiX v5 SDK + wixext packages restore via NuGet
#   - The six IsoSession binaries for the target architecture staged under -BinDir
#     (IsoSessionServer.dll, IsoSessionClient.dll, IsoSessionApp.dll,
#      IsoSessionProxyStub.dll, IsoSessionCli.exe, IsolationProxy.exe)
#
# Usage:
#   powershell -File makeinstaller.ps1 -Arch x64 -BinDir C:\path\to\x64\bin
#   powershell -File makeinstaller.ps1 -Arch arm64 -BinDir C:\path\to\arm64\bin -MonthId 2026.07 -Patch 1
#   powershell -File makeinstaller.ps1 -Arch x64 -BinDir C:\path\to\x64\bin -MsiOnly    # skip the EXE
#   powershell -File makeinstaller.ps1 -Arch x64 -BinDir C:\path\to\x64\bin -BundleOnly # use an existing MSI
#
# Exit codes: this script fails NONZERO (never a silent/soft exit 0) whenever
# a required input is missing — the .NET SDK, the target-architecture binary
# payload, or any of the maintained WiX/bootstrapper source assets alongside
# this script — so CI callers can rely on the exit code alone.

param(
    # Target architecture — this product only supports native 64-bit
    # platforms; there is no x86 build.
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = $(
        switch ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture) {
            'X64'   { 'x64' }
            'Arm64' { 'arm64' }
            default { $null }
        }
    ),

    # Directory containing the six IsoSession binaries for -Arch (see header).
    # No fragile environment-variable-based default: the caller (CI or a dev)
    # must stage these explicitly, since they come from the separate OS binary
    # drop, not from this repo's own build.
    [string]$BinDir,

    # Monthly release identifier (e.g., "2026.06"). Defaults to current year.month.
    [string]$MonthId = ("{0:yyyy.MM}" -f (Get-Date)),

    # Patch number within the month (0 = initial release, 1+ = in-month patches).
    [int]$Patch = 0,

    # Output directory for the built MSI/EXE/generated include. Defaults to a
    # per-arch folder under this script's own (gitignored) obj\ directory.
    [string]$OutDir,

    # Build only the MSI (skip the bootstrapper EXE).
    [switch]$MsiOnly,

    # Build only the bootstrapper EXE using the existing MSI in -OutDir. This
    # supports the CI signing sequence: build MSI -> sign MSI -> build bundle
    # (embedding the signed MSI) -> sign bundle.
    [switch]$BundleOnly
)

$ErrorActionPreference = 'Stop'

# Resolve script directory (works regardless of caller's working directory)
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

if (-not $OutDir) {
    $OutDir = Join-Path $scriptDir "obj\out\$Arch"
}

# ---------------------------------------------------------------------------
# Validate required inputs up front. Any failure here exits NONZERO — this is
# a hard requirement (no silent/soft "not built" success exit).
# ---------------------------------------------------------------------------

if (-not $Arch) {
    Write-Error "Unable to determine a default -Arch (unsupported process architecture). Pass -Arch x64 or -Arch arm64 explicitly."
    exit 1
}

if ($MsiOnly -and $BundleOnly) {
    Write-Error '-MsiOnly and -BundleOnly cannot be used together.'
    exit 1
}

if ($MonthId -notmatch '^\d{4}\.\d{2}$') {
    Write-Error "MonthId must be in YYYY.MM format (e.g., 2026.06). Got: $MonthId"
    exit 1
}

if (-not $BinDir) {
    Write-Error "-BinDir is required: it must point to a directory containing the six IsoSession binaries built for '$Arch' (IsoSessionServer.dll, IsoSessionClient.dll, IsoSessionApp.dll, IsoSessionProxyStub.dll, IsoSessionCli.exe, IsolationProxy.exe)."
    exit 1
}

if (-not (Test-Path -LiteralPath $BinDir -PathType Container)) {
    Write-Error "-BinDir does not exist or is not a directory: $BinDir"
    exit 1
}

$requiredBinaries = @(
    'IsoSessionServer.dll',
    'IsoSessionClient.dll',
    'IsoSessionApp.dll',
    'IsoSessionProxyStub.dll',
    'IsoSessionCli.exe',
    'IsolationProxy.exe'
)
$missingBinaries = @($requiredBinaries | Where-Object { -not (Test-Path -LiteralPath (Join-Path $BinDir $_) -PathType Leaf) })
if ($missingBinaries.Count -gt 0) {
    Write-Error "INSTALLER NOT CREATED: missing required binaries under -BinDir '$BinDir' for architecture '$Arch': $($missingBinaries -join ', ')"
    exit 1
}

# Maintained WiX/bootstrapper source assets this script depends on. All are
# committed alongside this script; a missing file means the installer subtree
# is incomplete/corrupt, so fail loudly rather than silently skip authoring.
$requiredSourceFiles = [System.Collections.Generic.List[string]]::new()
$requiredSourceFiles.Add((Join-Path $scriptDir 'IsoSession.wxs'))
$requiredSourceFiles.Add((Join-Path $scriptDir 'IsoSessionInstaller.wixproj'))
$requiredSourceFiles.Add((Join-Path $scriptDir 'IsoSessionCli.exe.manifest'))
if (-not $MsiOnly) {
    $requiredSourceFiles.Add((Join-Path $scriptDir 'IsoSessionBundle.wxs'))
    $requiredSourceFiles.Add((Join-Path $scriptDir 'IsoSessionBundle.wixproj'))
    $requiredSourceFiles.Add((Join-Path $scriptDir 'bootstrapper\icon.ico'))
    $requiredSourceFiles.Add((Join-Path $scriptDir 'bootstrapper\logo.png'))
    $requiredSourceFiles.Add((Join-Path $scriptDir 'bootstrapper\License.rtf'))
    $requiredSourceFiles.Add((Join-Path $scriptDir 'bootstrapper\RtfTheme.xml'))
    $requiredSourceFiles.Add((Join-Path $scriptDir 'bootstrapper\terminate_isosession.cmd'))
}
$missingSourceFiles = @($requiredSourceFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
if ($missingSourceFiles.Count -gt 0) {
    Write-Error "INSTALLER NOT CREATED: missing required installer source file(s): $($missingSourceFiles -join ', ')"
    exit 1
}

# ---------------------------------------------------------------------------
# Derive version and deterministic GUIDs from MonthId
# ---------------------------------------------------------------------------

$yearFull = [int]($MonthId.Split('.')[0])
$month = [int]($MonthId.Split('.')[1])
$yearShort = $yearFull % 100

# MSI/Bundle Version: YY.M.Patch.0 (version fields are 0-65535)
$msiVersion = "$yearShort.$month.$Patch.0"

# RFC 4122 DNS namespace, used as the base for all deterministic UUID v5 values.
$namespace = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
$nsGuid = [System.Guid]::Parse($namespace)
$nsBytes = $nsGuid.ToByteArray()
# Swap to network byte order (.NET Guid stores first 3 fields little-endian)
$t = $nsBytes[0]; $nsBytes[0] = $nsBytes[3]; $nsBytes[3] = $t
$t = $nsBytes[1]; $nsBytes[1] = $nsBytes[2]; $nsBytes[2] = $t
$t = $nsBytes[4]; $nsBytes[4] = $nsBytes[5]; $nsBytes[5] = $t
$t = $nsBytes[6]; $nsBytes[6] = $nsBytes[7]; $nsBytes[7] = $t

$sha1 = [System.Security.Cryptography.SHA1]::Create()

# Compute a deterministic UUID v5 for a given name under the fixed namespace.
function New-DeterministicGuid([string]$name) {
    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($name)
    $hash = $sha1.ComputeHash($nsBytes + $nameBytes)

    $b = [byte[]]$hash[0..15]
    $b[6] = ($b[6] -band 0x0F) -bor 0x50  # version 5
    $b[8] = ($b[8] -band 0x3F) -bor 0x80  # variant 10xx
    # Swap back to .NET GUID byte order
    $t = $b[0]; $b[0] = $b[3]; $b[3] = $t
    $t = $b[1]; $b[1] = $b[2]; $b[2] = $t
    $t = $b[4]; $b[4] = $b[5]; $b[5] = $t
    $t = $b[6]; $b[6] = $b[7]; $b[7] = $t

    return ([System.Guid]::new([byte[]]$b)).ToString("B").ToUpper()
}

# Per-month identities must match on x64 and arm64. The runtime activation
# contract derives these registrations from MonthId and has no architecture
# discriminator.
$upgradeCode = New-DeterministicGuid "IsoSession:$MonthId"
$bundleUpgradeCode = New-DeterministicGuid "IsoSession:BundleUpgradeCode:$MonthId"
$appId = New-DeterministicGuid "IsoSession:AppId:$MonthId"
$clientClsid = New-DeterministicGuid "IsoSession:ClientClsid:$MonthId"
$proxyConnectionClsid = New-DeterministicGuid "IsoSession:ProxyClsid:$MonthId"

# Derived names
$monthUnderscore = $MonthId.Replace('.', '_')
$serviceName = "IsolationSession_$monthUnderscore"
$installSubDir = "Microsoft\Agentic Runtime\$MonthId"

Write-Host "Arch:             $Arch"
Write-Host "MonthId:          $MonthId"
Write-Host "Patch:            $Patch"
Write-Host "Version:          $msiVersion"
Write-Host "MSI UpgradeCode:  $upgradeCode"
Write-Host "Bundle UpgradeCode: $bundleUpgradeCode"
Write-Host "AppID:            $appId"
Write-Host "ClientClsid:      $clientClsid"
Write-Host "ProxyConnClsid:   $proxyConnectionClsid"
Write-Host "ServiceName:      $serviceName"
Write-Host "InstallDir:       %ProgramFiles%\$installSubDir"

# ---------------------------------------------------------------------------
# Locate the .NET SDK (WiX v5 builds as an SDK-style project via dotnet)
# ---------------------------------------------------------------------------

$dotnet = (Get-Command dotnet.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
if (-not $dotnet) {
    Write-Error "INSTALLER NOT CREATED: .NET SDK (dotnet) not found on PATH. WiX v5 builds require the .NET SDK. Install it, then re-run."
    exit 1
}

Write-Host "Using dotnet:     $dotnet"
Write-Host "BinDir:           $BinDir"
Write-Host "InstallerDir:     $scriptDir"
Write-Host "OutDir:           $OutDir"

# Ensure output directory exists
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$msiFileName = "IsoSession_${monthUnderscore}_$Arch"          # (no extension; OutputName)
$exeFileName = "IsoSessionSetup_${monthUnderscore}_$Arch"     # (no extension; OutputName)
$msiPath = Join-Path $OutDir "$msiFileName.msi"

# ---------------------------------------------------------------------------
# Generate the per-build WiX include consumed by BOTH projects.
# A single generated include avoids fragile multi-value DefineConstants on the
# command line (MSBuild splits ';'-separated -p values into separate properties).
# ---------------------------------------------------------------------------

$varsWxi = Join-Path $OutDir "IsoSessionVars_${monthUnderscore}_$Arch.wxi"
$varsContent = @"
<?xml version="1.0" encoding="utf-8"?>
<!-- GENERATED by makeinstaller.ps1 for MonthId $MonthId, Arch $Arch. Do not edit by hand. -->
<Include>
  <?define Version = "$msiVersion" ?>
  <?define UpgradeCode = "$upgradeCode" ?>
  <?define BundleUpgradeCode = "$bundleUpgradeCode" ?>
  <?define AppId = "$appId" ?>
  <?define ClientClsid = "$clientClsid" ?>
  <?define ProxyConnectionClsid = "$proxyConnectionClsid" ?>
  <?define MonthId = "$MonthId" ?>
  <?define Arch = "$Arch" ?>
  <?define ServiceName = "$serviceName" ?>
  <?define InstallSubDir = "$installSubDir" ?>
  <?define BinDir = "$BinDir" ?>
  <?define InstallerDir = "$scriptDir" ?>
  <?define MsiPath = "$msiPath" ?>
</Include>
"@
Set-Content -Path $varsWxi -Value $varsContent -Encoding UTF8
Write-Host "`nGenerated vars include: $varsWxi"

# ---------------------------------------------------------------------------
# Build the MSI (IsoSessionInstaller.wixproj)
# ---------------------------------------------------------------------------

$msiProj = Join-Path $scriptDir "IsoSessionInstaller.wixproj"
$msiIntermediate = Join-Path $OutDir "obj\msi_${monthUnderscore}_$Arch\"

if (-not $BundleOnly) {
    Write-Host "`nBuilding MSI..."
    & $dotnet build $msiProj -c Release -p:Platform=$Arch `
        -p:OutputName=$msiFileName `
        -p:OutputPath="$OutDir\" `
        -p:IntermediateOutputPath="$msiIntermediate" `
        "-p:DefineConstants=IsoSessionVars=$varsWxi"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "INSTALLER NOT CREATED: MSI build failed ($LASTEXITCODE)." -ForegroundColor Cyan
        exit $LASTEXITCODE
    }

    if (-not (Test-Path $msiPath)) {
        Write-Host "INSTALLER NOT CREATED: expected MSI missing at $msiPath." -ForegroundColor Cyan
        exit 1
    }
    Write-Host "MSI CREATED: $msiPath" -ForegroundColor Cyan
}
elseif (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    Write-Error "BUNDLE NOT CREATED: -BundleOnly requires the existing MSI '$msiPath'."
    exit 1
}
else {
    Write-Host "Using existing MSI for bundle: $msiPath" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Build the bootstrapper bundle (IsoSessionBundle.wixproj)
# Run from the source dir so the bundle's relative asset paths
# (bootstrapper\*.*) resolve correctly.
# ---------------------------------------------------------------------------

$exePath = Join-Path $OutDir "$exeFileName.exe"

if (-not $MsiOnly) {
    $bundleProj = Join-Path $scriptDir "IsoSessionBundle.wixproj"
    $bundleIntermediate = Join-Path $OutDir "obj\bundle_${monthUnderscore}_$Arch\"

    Write-Host "`nBuilding UI installer (bundle)..."
    Push-Location $scriptDir
    try {
        & $dotnet build $bundleProj -c Release -p:Platform=$Arch `
            -p:OutputName=$exeFileName `
            -p:OutputPath="$OutDir\" `
            -p:IntermediateOutputPath="$bundleIntermediate" `
            "-p:DefineConstants=IsoSessionVars=$varsWxi"
        $bundleExit = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    if ($bundleExit -ne 0) {
        Write-Host "EXE NOT CREATED: bundle build failed ($bundleExit)." -ForegroundColor Cyan
        exit $bundleExit
    }

    if (-not (Test-Path $exePath)) {
        Write-Host "EXE NOT CREATED: expected EXE missing at $exePath." -ForegroundColor Cyan
        exit 1
    }
    Write-Host "EXE CREATED: $exePath" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Generate client manifest for registration-free COM activation
# ---------------------------------------------------------------------------
# Apps embed this manifest to activate this month's/architecture's version
# without relying on global CLSID registry entries. Two apps with different
# manifests can activate different months (or architectures) simultaneously.

$manifestTemplate = Join-Path $scriptDir "IsoSessionClient.manifest.template"
if (Test-Path $manifestTemplate) {
    $manifestContent = (Get-Content $manifestTemplate -Raw) `
        -replace '\$\(MonthId\)', $MonthId `
        -replace '\$\(Arch\)', $Arch `
        -replace '\$\(AppId\)', $appId `
        -replace '\$\(ClientClsid\)', $clientClsid `
        -replace '\$\(ProxyConnectionClsid\)', $proxyConnectionClsid `
        -replace '\$\(InstallDir\)', "%ProgramFiles%\$installSubDir"

    $manifestOut = Join-Path $OutDir "IsoSessionClient_${monthUnderscore}_$Arch.manifest"
    Set-Content -Path $manifestOut -Value $manifestContent -Encoding UTF8
    Write-Host "`nClient manifest: $manifestOut" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n============================================================" -ForegroundColor Cyan
if (-not $MsiOnly) {
    Write-Host "UI INSTALLER: $exePath" -ForegroundColor Cyan
    Write-Host "Deploy to VM: copy the EXE to the target and run it (UI), or:" -ForegroundColor Cyan
    Write-Host "  $exeFileName.exe /quiet   (silent)" -ForegroundColor Cyan
} else {
    Write-Host "MSI ONLY: $msiPath" -ForegroundColor Cyan
    Write-Host "  msiexec /i $msiFileName.msi /qn" -ForegroundColor Cyan
}
Write-Host "Service name on target: $serviceName" -ForegroundColor Cyan
Write-Host "AppID:            $appId" -ForegroundColor Cyan
Write-Host "ClientClsid:      $clientClsid" -ForegroundColor Cyan
Write-Host "ProxyConnClsid:   $proxyConnectionClsid" -ForegroundColor Cyan
