#Requires -Version 7.0

<#
.SYNOPSIS
    Installs or updates the WSL runtime, optionally from the pre-release ring, and checks for required Windows optional features.

.DESCRIPTION
    Prepares and reports on a host's WSL2 installation: it verifies that the
    Windows optional features WSL2 depends on are enabled, then inspects the
    installed runtime, updating an inbox build to the modern runtime and
    updating from the pre-release ring when -InstallPreRelease is set. It is
    diagnostic-only in the sense that nothing aborts it: every problem is
    reported as a FAILED line and the script always exits with code 0.

.PARAMETER InstallPreRelease
    Update WSL from the pre-release ring. Off by default, which leaves the host
    on the stable ring.

.EXAMPLE
    ./scripts/ci/Setup.ps1

.EXAMPLE
    ./scripts/ci/Setup.ps1 -InstallPreRelease $true
#>

[CmdletBinding()]
param(
    [bool]$InstallPreRelease = $false
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

$script:Failed = $false

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host "=== $Message ==="
}

function Write-Failure {
    param([Parameter(Mandatory)][string]$Message)
    $script:Failed = $true
    Write-Host "FAILED: $Message"
}

# Read a Windows optional feature's state without throwing. A host that cannot
# answer (querying needs elevation) reports the reason as its state.
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

# Enabling an optional feature needs a reboot, so this reports rather than
# installs.
function Test-RequiredFeature {
    param([Parameter(Mandatory)][string[]]$Name)

    foreach ($feature in $Name) {
        $state = Get-OptionalFeatureState -Name $feature
        Write-Host "  $feature = $state"
        if ($state -ne 'Enabled') {
            Write-Failure "Windows optional feature not enabled: $feature ($state). WSL2 must be baked into the image; enabling it requires a reboot."
        }
    }
}

# wsl.exe emits UTF-16LE, which the default console encoding renders as
# null-separated garbage. Returns @{ ExitCode; Output } with the output decoded.
function Invoke-WslCapture {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $previousEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $output = & wsl.exe @Arguments 2>&1 | Out-String
        return @{ ExitCode = $LASTEXITCODE; Output = $output }
    } catch {
        return @{ ExitCode = 1; Output = "wsl.exe could not be run: $($_.Exception.Message)" }
    } finally {
        [Console]::OutputEncoding = $previousEncoding
    }
}

# Run wsl.exe and return its exit code. -Quiet suppresses output for probes,
# where the legacy wsl.exe dumps its whole usage text on an unknown switch.
function Invoke-Wsl {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$Quiet
    )

    Write-Host "  > wsl.exe $($Arguments -join ' ')"
    $result = Invoke-WslCapture -Arguments $Arguments
    if (-not $Quiet -and $result.Output.Trim()) {
        Write-Host $result.Output.Trim()
    }
    Write-Host "  exit code: $($result.ExitCode)"
    return $result.ExitCode
}

# Installed modern-runtime version, or $null when wsl.exe is the legacy inbox
# build (no --version) or otherwise unusable.
function Get-InstalledWslVersion {
    $result = Invoke-WslCapture -Arguments @('--version')
    if ($result.ExitCode -ne 0) {
        return $null
    }

    $match = [regex]::Match($result.Output, '(?im)^\s*WSL version:\s*([0-9]+(?:\.[0-9]+)+)')
    if (-not $match.Success) {
        return $null
    }
    return [version]$match.Groups[1].Value
}

function Initialize-WslcHost {
    Write-Step 'WSLC artifact binaries'

    Write-Step 'Required Windows optional features'
    Test-RequiredFeature -Name 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform'

    Write-Step 'wsl.exe presence + status'
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($wsl) {
        Write-Host "wsl.exe: $($wsl.Source)"
    } else {
        Write-Failure 'wsl.exe NOT found on PATH; WSL2 is not installed on this host.'
        return
    }

    $status = Invoke-WslCapture -Arguments @('--status')
    Write-Host $status.Output.Trim()

    if ($status.Output -match 'wsl.exe --install') {
        Write-Failure 'WSL2 is not installed on this host (wsl --status advertises --install).'
        return
    }

    Write-Step 'WSL runtime version'
    if ((Invoke-Wsl @('--version') -Quiet) -ne 0) {
        Write-Host 'wsl --version failed, so WSL2 is installed but not updated.'
        Write-Host 'Updating inbox WSL to the modern runtime...'

        if ((Invoke-Wsl @('--update', '--web-download') -Quiet) -ne 0 -and
            (Invoke-Wsl @('--update')) -ne 0) {
            Write-Failure 'wsl --update failed; the WSL2 runtime could not be installed on this host.'
            return
        }

        if ((Invoke-Wsl @('--version') -Quiet) -ne 0) {
            Write-Failure 'wsl --version failed after updating; the WSL2 runtime is not usable on this host.'
            return
        }

        Write-Host 'WSL2 is installed and updated (not prerelease, yet).'
    }

    # The pre-release ring carries builds the stable ring lands well behind, so
    # it is opt-in rather than a version the script decides on its own.
    $installed = Get-InstalledWslVersion
    Write-Host "Installed WSL version: $(if ($null -eq $installed) { '<none>' } else { $installed })"

    if ($InstallPreRelease) {
        Write-Host 'Updating WSL to the latest pre-release build...'
        if ((Invoke-Wsl @('--update', '--pre-release', '--web-download') -Quiet) -ne 0 -and
            (Invoke-Wsl @('--update', '--pre-release')) -ne 0) {
            Write-Failure 'wsl --update --pre-release failed; the pre-release WSL2 runtime could not be installed on this host.'
            return
        }
        $installed = Get-InstalledWslVersion
        Write-Host "Installed WSL version after update: $(if ($null -eq $installed) { '<none>' } else { $installed })"
    }

    if ($null -eq $installed) {
        Write-Failure 'wsl --version failed; the WSL2 runtime is not usable on this host.'
        return
    }

    Write-Host "WSL runtime $installed is ready."
}

Write-Host "WSLC host setup starting on $([System.Environment]::OSVersion)"

try {
    Initialize-WslcHost
} catch {
    Write-Failure "unexpected error: $($_.Exception.Message)"
}

Write-Step 'Result'
if ($script:Failed) {
    Write-Host 'WSLC host setup completed WITH failures (see FAILED lines above).'
} else {
    Write-Host 'WSLC host setup completed successfully.'
}

exit 0
