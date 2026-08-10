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

# Report whether the artifact carries a complete WHP warm-start snapshot set.
# A partial set is worth calling out: the runner treats a complete set as the
# signal to warm-boot, so a missing half silently costs a cold boot per run.
function Write-SnapshotAvailability {
    $snapshots = @('snapshots\kernel.vmem', 'snapshots\kernel.whp.cbor')
    $present = @($snapshots | Where-Object { Test-Path (Join-Path $BinaryDirectory $_) })

    if ($present.Count -eq $snapshots.Count) {
        Write-Host 'WHP warm-start snapshots are present; the runner will warm-boot.'
    } elseif ($present.Count -eq 0) {
        Write-Host 'WHP warm-start snapshots are absent; the runner will cold-boot (slower, expected on cross-arch or offline builds).'
    } else {
        Write-Host "WARNING: incomplete WHP snapshot set (found: $($present -join ', ')); the runner will cold-boot."
    }
}

# Report the hypervisor state a VM-backed backend depends on. Purely
# diagnostic: never fails, so a hypervisor problem surfaces as the explicit
# check below rather than as an unexplained collection error.
function Write-HypervisorDiagnostic {
    Write-Host '=== Hypervisor Diagnostics ==='
    try {
        Write-Host "OS: $([System.Environment]::OSVersion)"

        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $hypervisorPresent = if ($null -eq $computerSystem) { 'unknown' } else { $computerSystem.HypervisorPresent }
        Write-Host "HypervisorPresent: $hypervisorPresent"
        Write-Host "WinHvPlatform.dll exists: $(Test-Path "$env:SystemRoot\System32\WinHvPlatform.dll")"

        $feature = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
        $featureState = if ($null -eq $feature) { 'unknown' } else { $feature.State }
        Write-Host "HypervisorPlatform feature state: $featureState"
    } catch {
        Write-Host "WARNING: hypervisor diagnostics could not be collected: $($_.Exception.Message)"
    }
    Write-Host '=== end diagnostics ==='
}

# The feature can be enabled while the hypervisor is not actually running (for
# example when a host reboot is still pending), so both are required.
function Assert-HypervisorPlatform {
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
    } catch {
        # Querying optional features needs elevation; a host that cannot answer
        # cannot be certified as WHP-capable.
        Exit-WithError "Unable to query the HypervisorPlatform feature: $($_.Exception.Message)"
    }

    if ($null -eq $feature -or $feature.State -ne 'Enabled') {
        Exit-WithError 'Windows Hypervisor Platform is not enabled. This backend requires WHP.'
    }

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
    # NanVix binaries are pinned GitHub release assets fetched and checksum-
    # verified at build time, so the build either staged all of them or failed.
    # Their absence here means a broken artifact, not a host problem.
    Assert-RequiredFile @(
        'wxc-exec.exe',
        'nanvixd.exe',
        'nanvix_rootfs.img',
        'python3.initrd',
        'bin\kernel.elf'
    )

    # The WHP snapshots are a warm-start cache generated by running nanvixd on
    # an x86_64 build host, not a release asset. The build legitimately skips
    # them (cross-arch or offline NANVIX_BIN builds) and the runner cold-boots
    # when they are absent, so report the boot path instead of failing.
    Write-SnapshotAvailability

    # NanVix boots a VM from these images on every invocation; Defender
    # scanning them can push boot past its timeout.
    Add-MpPreference -ExclusionPath $BinaryDirectory
    Write-Host "Added Defender exclusion for $BinaryDirectory"

    Write-HypervisorDiagnostic
    Assert-HypervisorPlatform
}

if (-not (Test-Path $BinaryDirectory)) {
    Exit-WithError "Binary directory not found: $BinaryDirectory"
}
$BinaryDirectory = (Resolve-Path $BinaryDirectory).Path

Write-Host "Preparing Windows host for backend '$Backend' using $BinaryDirectory"

switch ($Backend) {
    'process-t3' { Initialize-ProcessContainerHost }
    'microvm' { Initialize-MicroVmHost }
    default { Write-Host "$Backend has no artifact-only Windows test prerequisites yet." }
}
