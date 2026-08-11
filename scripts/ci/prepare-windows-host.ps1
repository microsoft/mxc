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
    # Staged next to wxc-exec.exe by the --features microvm build, so their
    # absence means a broken artifact rather than a host problem. Snapshots are
    # excluded: they are a warm-start cache the runner regenerates on demand.
    Assert-RequiredFile @(
        'wxc-exec.exe',
        'nanvixd.exe',
        'nanvix_rootfs.img',
        'python3.initrd',
        'bin\kernel.elf'
    )

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

    Write-Host "=== wsl.exe presence + status ==="
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($wsl) {
        Write-Host "wsl.exe: $($wsl.Source)"
        wsl --status  2>&1 | Write-Host
        wsl --version 2>&1 | Write-Host
        Write-Host "wsl --status exit code: $LASTEXITCODE"
    } else {
        Write-Host "wsl.exe NOT found on PATH"
        Exit-WithError 'WSL2 is not installed on this runner. The runner image must include WSL2 for this backend.'
    }

    Write-Host "=== installing WSL ==="

    wsl --install  2>&1 | Write-Host
    Write-Host "=== post-install status check ==="
    wsl --status  2>&1 | Write-Host
    Write-Host "=== post-install version check ==="
    wsl --version 2>&1 | Write-Host

    Write-Host "=== updating WSL to pre-release ==="    

    wsl --update --prerelease  2>&1 | Write-Host
    Write-Host "=== post-update status check ==="
    wsl --status  2>&1 | Write-Host
    Write-Host "=== post-update version check ==="
    wsl --version 2>&1 | Write-Host

    Write-Host "=== done. ===" 
}


# wsl.exe emits UTF-16LE, which the default console encoding renders as
# null-separated garbage. Returns @{ ExitCode; Output } with the output decoded.
# function Invoke-WslCapture {
#     param([Parameter(Mandatory)][string[]]$Arguments)

#     $previousEncoding = [Console]::OutputEncoding
#     try {
#         [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
#         $output = & wsl.exe @Arguments 2>&1 | Out-String
#         return @{ ExitCode = $LASTEXITCODE; Output = $output }
#     } catch {
#         return @{ ExitCode = 1; Output = "wsl.exe could not be run: $($_.Exception.Message)" }
#     } finally {
#         [Console]::OutputEncoding = $previousEncoding
#     }
# }

# # Run wsl.exe and return its exit code. -Quiet suppresses output for probes,
# # where the legacy wsl.exe dumps its whole usage text on an unknown switch.
# function Invoke-Wsl {
#     param(
#         [Parameter(Mandatory)][string[]]$Arguments,
#         [switch]$Quiet
#     )

#     $result = Invoke-WslCapture -Arguments $Arguments
#     if (-not $Quiet -and $result.Output.Trim()) {
#         Write-Host $result.Output.Trim()
#     }
#     return $result.ExitCode
# }

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
