#Requires -Version 7.0

<#
.SYNOPSIS
    Prepares a Windows host for a backend's artifact-only test suite.

.PARAMETER Backend
    Matrix backend id (not the handler command), because process-t1 and
    process-t3 share a handler but differ in host preparation.

.PARAMETER BinaryDirectory
    Directory holding the downloaded build artifact.

.EXAMPLE
    ./scripts/ci/prepare-windows-host.ps1 -Backend process-t3 -BinaryDirectory artifacts/bin
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'process-t1',
        'process-t3',
        'isolation-session',
        'wslc',
        'windows-sandbox',
        'microvm',
        'hyperlight'
    )]
    [string]$Backend,

    [Parameter(Mandatory)]
    [string]$BinaryDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Exit-WithError {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host "::error::$Message"
    exit 1
}

function Assert-RequiredFile {
    param(
        [Parameter(Mandatory)][string[]]$RelativePath
    )

    $missing = $RelativePath | Where-Object { -not (Test-Path (Join-Path $BinaryDirectory $_)) }
    if ($missing) {
        Exit-WithError "Missing binaries: $($missing -join ', ')"
    }

    $leaves = $RelativePath | ForEach-Object { Split-Path $_ -Leaf }
    Get-ChildItem $BinaryDirectory -Include $leaves -Recurse | Format-Table FullName, Length
}

# Fetch the pinned NanVix release onto the test host, mirroring the offline-build
# contract in docs/nanvix-microvm/nanvix.md: flat binaries plus bin/, verified
# against checksums.json, and no snapshots (the runtime cold-boots and
# regenerates a verified one on first use).
function Install-NanvixBinaries {
    $configDir = Join-Path $PSScriptRoot '..\..\src\backends\nanvix\binaries'
    $versionsPath = Join-Path $configDir 'versions.json'
    $checksumsPath = Join-Path $configDir 'checksums.json'
    foreach ($path in $versionsPath, $checksumsPath) {
        if (-not (Test-Path $path)) {
            Exit-WithError "NanVix pin file not found: $path"
        }
    }

    $release = (Get-Content $versionsPath -Raw | ConvertFrom-Json).nanvix_python
    $checksums = (Get-Content $checksumsPath -Raw | ConvertFrom-Json).windows
    $prefix = [System.IO.Path]::GetFileNameWithoutExtension($release.asset)
    $binSubdir = Join-Path $BinaryDirectory 'bin'

    # The build VM's copies are discarded: its snapshots are a host-specific WHP
    # memory image, and a partial set would silently cost a cold boot per run.
    Write-Host 'Discarding build-staged NanVix binaries in favor of the pinned release.'
    Remove-Item (Join-Path $BinaryDirectory 'snapshots') -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($name in $release.binaries) {
        Remove-Item (Join-Path $BinaryDirectory $name) -Force -ErrorAction SilentlyContinue
    }
    Remove-Item (Join-Path $binSubdir 'kernel.elf') -Force -ErrorAction SilentlyContinue

    $url = "https://github.com/nanvix/nanvix-python/releases/download/$($release.tag)/$($release.asset)"
    $archive = Join-Path ([System.IO.Path]::GetTempPath()) $release.asset
    Write-Host "Downloading nanvix/nanvix-python $($release.tag)..."

    try {
        $curlArgs = @(
            '--silent', '--show-error', '--fail', '--location',
            '--retry', '5', '--retry-delay', '5', '--retry-all-errors',
            '--output', $archive
        )
        $token = if ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $env:GH_TOKEN }
        if ($token) {
            $curlArgs += @('--header', "Authorization: Bearer $token")
        }
        $curlArgs += $url

        & curl.exe @curlArgs
        if ($LASTEXITCODE -ne 0) {
            Exit-WithError "curl failed for $url (exit code $LASTEXITCODE)"
        }

        New-Item -ItemType Directory -Force -Path $binSubdir | Out-Null

        # nanvixd.exe and kernel.elf live under <prefix>/bin/; the rest at <prefix>/.
        Expand-NanvixEntry -Archive $archive -Entry "$prefix/bin/nanvixd.exe" -StripComponents 2 -Destination $BinaryDirectory
        Expand-NanvixEntry -Archive $archive -Entry "$prefix/bin/kernel.elf" -StripComponents 2 -Destination $binSubdir
        foreach ($name in $release.binaries | Where-Object { $_ -ne 'nanvixd.exe' }) {
            Expand-NanvixEntry -Archive $archive -Entry "$prefix/$name" -StripComponents 1 -Destination $BinaryDirectory
        }
    } finally {
        Remove-Item $archive -Force -ErrorAction SilentlyContinue
    }

    Assert-NanvixChecksum -Path (Join-Path $binSubdir 'kernel.elf') -Expected $checksums.'kernel.elf'
    foreach ($name in $release.binaries) {
        Assert-NanvixChecksum -Path (Join-Path $BinaryDirectory $name) -Expected $checksums.$name
    }

    Write-Host "NanVix $($release.tag) staged and verified; the runner will cold-boot and regenerate its snapshot."
}

function Expand-NanvixEntry {
    param(
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Entry,
        [Parameter(Mandatory)][int]$StripComponents,
        [Parameter(Mandatory)][string]$Destination
    )

    & tar.exe -xf $Archive -C $Destination --strip-components $StripComponents $Entry
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "tar failed to extract $Entry (exit code $LASTEXITCODE)"
    }
}

function Assert-NanvixChecksum {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Expected
    )

    if (-not (Test-Path $Path)) {
        Exit-WithError "NanVix binary missing after extraction: $Path"
    }
    if (-not $Expected) {
        Exit-WithError "No pinned checksum for $(Split-Path $Path -Leaf)"
    }

    $actual = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    if ($actual -ne $Expected) {
        Exit-WithError "Checksum mismatch for $(Split-Path $Path -Leaf): expected $($Expected.ToLowerInvariant()), got $($actual.ToLowerInvariant())"
    }
    Write-Host "  $(Split-Path $Path -Leaf) verified"
}

# Read a Windows optional feature's state without throwing, so both the
# diagnostic and assertion paths can share one query. A host that cannot answer
# (querying needs elevation) reports the reason as its state rather than
# aborting, which keeps the failure message actionable.
function Get-OptionalFeatureState {
    param([Parameter(Mandatory)][string]$Name)

    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
    } catch {
        return "query-failed: $($_.Exception.Message.Trim())"
    }

    if ($null -eq $feature) {
        return 'unknown'
    }
    return [string]$feature.State
}

# Require every named optional feature to be Enabled. Enabling one needs a
# reboot the runner cannot take mid-job, so this verifies rather than installs:
# a mis-imaged pool fails here with a pointed message instead of surfacing
# later as an opaque backend error. $Remedy names the image-level fix.
function Assert-RequiredFeature {
    param(
        [Parameter(Mandatory)][string[]]$Name,
        [Parameter(Mandatory)][string]$Remedy
    )

    $notEnabled = @()
    foreach ($feature in $Name) {
        $state = Get-OptionalFeatureState -Name $feature
        Write-Host "  $feature = $state"
        if ($state -ne 'Enabled') {
            $notEnabled += "$feature ($state)"
        }
    }

    if ($notEnabled) {
        Exit-WithError "Required Windows optional feature(s) not enabled: $($notEnabled -join '; '). $Remedy"
    }
}

# Report the hypervisor state a VM-backed backend depends on. Purely
# diagnostic: never fails, so a hypervisor problem surfaces as the explicit
# check below rather than as an unexplained collection error.
function Write-HypervisorDiagnostic {
    Write-Host '=== Hypervisor Diagnostics ==='
    Write-Host "OS: $([System.Environment]::OSVersion)"

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $hypervisorPresent = if ($null -eq $computerSystem) { 'unknown' } else { $computerSystem.HypervisorPresent }
    Write-Host "HypervisorPresent: $hypervisorPresent"
    Write-Host "WinHvPlatform.dll exists: $(Test-Path "$env:SystemRoot\System32\WinHvPlatform.dll")"
    Write-Host '=== end diagnostics ==='
}

# The feature can be enabled while the hypervisor is not actually running (for
# example when a host reboot is still pending), so both are required.
function Assert-HypervisorPlatform {
    Assert-RequiredFeature -Name 'HypervisorPlatform' `
        -Remedy 'This backend requires Windows Hypervisor Platform on the runner image.'

    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($null -eq $computerSystem -or -not $computerSystem.HypervisorPresent) {
        Exit-WithError 'HypervisorPresent is false - WHP feature is enabled but hypervisor is not running.'
    }

    Write-Host 'WHP is enabled and hypervisor is present.'
}

function Initialize-ProcessContainerHost {
    $hostPrep = Join-Path $BinaryDirectory 'wxc-host-prep.exe'
    if (-not (Test-Path $hostPrep)) {
        Exit-WithError "wxc-host-prep.exe not found in $BinaryDirectory"
    }

    # The AppContainer tier needs the system-drive ACEs and the \Device\Null
    # security descriptor. --no-sacl keeps the descriptor within what a CI host
    # can grant without SeSecurityPrivilege.
    & $hostPrep prepare-system-drive
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "wxc-host-prep prepare-system-drive failed with exit code $LASTEXITCODE"
    }

    & $hostPrep prepare-null-device --no-sacl
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "wxc-host-prep prepare-null-device failed with exit code $LASTEXITCODE"
    }
}

function Initialize-MicroVmHost {
    Assert-RequiredFile @('wxc-exec.exe')
    Install-NanvixBinaries

    # NanVix boots a VM from these images on every invocation; Defender scanning
    # them can push boot past its timeout.
    Add-MpPreference -ExclusionPath $BinaryDirectory
    Write-Host "Added Defender exclusion for $BinaryDirectory"

    Write-HypervisorDiagnostic
    Assert-HypervisorPlatform
}

# The optional features must be baked into the pool image (enabling one needs a
# reboot this job cannot take), but the WSL runtime package is installed here if
# missing. Container images are pulled by the suite itself
# (tests/scripts/run_wslc_all_tests.ps1).
function Initialize-WslcHost {
    # wslcsdk.dll ships beside wxc-exec.exe only in a --features wslc build.
    Assert-RequiredFile @('wxc-exec.exe', 'wslcsdk.dll')

    Assert-RequiredFeature -Name 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform' `
        -Remedy 'WSL2 must be baked into the runner image; enabling these features requires a host reboot this job cannot take.'

    # The optional features can be enabled while the WSL runtime package itself
    # is absent. Installing that package needs no reboot once the features are
    # on, so it is safe to do mid-job.
    if ((Invoke-Wsl @('--version')) -ne 0) {
        Write-Host 'WSL runtime not installed; installing (features are already enabled, so no reboot is needed)...'
        if ((Invoke-Wsl @('--install', '--no-distribution')) -ne 0) {
            Exit-WithError 'wsl --install failed; the WSL2 runtime could not be installed on this runner.'
        }
        if ((Invoke-Wsl @('--version')) -ne 0) {
            Exit-WithError 'wsl --version still fails after install; the WSL2 runtime is not usable on this runner.'
        }
    }

    # Diagnostic only: --status exits non-zero with no distribution installed,
    # which is expected since WSLC creates its own containers via the SDK.
    Invoke-Wsl @('--status') | Out-Null
}

# wsl.exe emits UTF-16LE, which the default console encoding renders as
# null-separated garbage. Returns the exit code.
function Invoke-Wsl {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $previousEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        & wsl.exe @Arguments 2>&1 | Write-Host
        return $LASTEXITCODE
    } catch {
        Write-Host "WARNING: wsl.exe $($Arguments -join ' ') could not be run: $($_.Exception.Message)"
        return 1
    } finally {
        [Console]::OutputEncoding = $previousEncoding
    }
}

if (-not (Test-Path $BinaryDirectory)) {
    Exit-WithError "Binary directory not found: $BinaryDirectory"
}
$BinaryDirectory = (Resolve-Path $BinaryDirectory).Path

Write-Host "Preparing Windows host for backend '$Backend' using $BinaryDirectory"

switch ($Backend) {
    'process-t3' { Initialize-ProcessContainerHost }
    'microvm' { Initialize-MicroVmHost }
    'wslc' { Initialize-WslcHost }
    default { Write-Host "$Backend has no artifact-only Windows test prerequisites yet." }
}
