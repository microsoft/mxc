#Requires -Version 7.0

<#
.SYNOPSIS
    TEMP scratch script: runs only the WSLC host initialization steps.

.DESCRIPTION
    A trimmed copy of scripts/ci/prepare-windows-host.ps1 that keeps just the
    WSLC path. Unlike the CI script this one is diagnostic-only: every failure
    is reported and execution always ends with exit code 0.

.PARAMETER BinaryDirectory
    Optional directory holding a built/downloaded artifact. When supplied, the
    WSLC binaries are checked for presence; otherwise that check is skipped.

.EXAMPLE
    ./scripts/ci/Setup.ps1
    ./scripts/ci/Setup.ps1 -BinaryDirectory src/target/x86_64-pc-windows-msvc/release
#>

[CmdletBinding()]
param(
    [string]$BinaryDirectory
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

function Test-RequiredFile {
    param([Parameter(Mandatory)][string[]]$RelativePath)

    if (-not $BinaryDirectory) {
        Write-Host 'No -BinaryDirectory supplied; skipping artifact presence check.'
        return
    }

    foreach ($relative in $RelativePath) {
        $full = Join-Path $BinaryDirectory $relative
        if (Test-Path $full) {
            $item = Get-Item $full
            Write-Host "  found $($item.FullName) ($($item.Length) bytes)"
        } else {
            Write-Failure "missing binary: $full"
        }
    }
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

# Minimum WSL runtime for WSLC, read from the pinned SDK version so the two
# cannot drift. The SDK's own runtime error names this same version.
function Get-RequiredWslVersion {
    $buildScript = Join-Path $PSScriptRoot '..\..\src\backends\wslc\common\build.rs'
    if (-not (Test-Path $buildScript)) {
        Write-Host "WARNING: $buildScript not found; skipping the WSL version gate."
        return $null
    }

    $match = [regex]::Match((Get-Content $buildScript -Raw), 'WSLC_SDK_VERSION:\s*&str\s*=\s*"([0-9]+(?:\.[0-9]+)+)"')
    if (-not $match.Success) {
        Write-Host 'WARNING: could not parse WSLC_SDK_VERSION; skipping the WSL version gate.'
        return $null
    }
    return [version]$match.Groups[1].Value
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
    # wslcsdk.dll ships beside wxc-exec.exe only in a --features wslc build.
    Test-RequiredFile @('wxc-exec.exe', 'wslcsdk.dll')

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

    # WSLC needs a runtime at least as new as the pinned WSLC SDK, and those
    # builds ship only on the pre-release ring - the stable ring lands well
    # behind it. Without this the SDK fails at run time with
    # "WSLC runtime unavailable. Missing components: WslPackage".
    $required = Get-RequiredWslVersion
    $installed = Get-InstalledWslVersion
    Write-Host "Required WSL version: $(if ($null -eq $required) { '<unknown>' } else { $required })"
    Write-Host "Installed WSL version: $(if ($null -eq $installed) { '<none>' } else { $installed })"

    if ($null -ne $required -and ($null -eq $installed -or $installed -lt $required)) {
        Write-Host "WSL $installed is older than the $required WSLC requires; updating to pre-release..."
        if ((Invoke-Wsl @('--update', '--pre-release', '--web-download') -Quiet) -ne 0 -and
            (Invoke-Wsl @('--update', '--pre-release')) -ne 0) {
            Write-Failure "wsl --update --pre-release failed; WSLC requires WSL $required or newer."
            return
        }
        $installed = Get-InstalledWslVersion
        Write-Host "Installed WSL version after update: $(if ($null -eq $installed) { '<none>' } else { $installed })"
    }

    if ($null -eq $installed) {
        Write-Failure 'wsl --version failed after updating; the WSL2 runtime is not usable on this host.'
        return
    }
    if ($null -ne $required -and $installed -lt $required) {
        Write-Failure "WSL $installed is installed, but WSLC requires $required or newer."
        return
    }

    Write-Host "WSL runtime $installed is ready (WSLC requires $required or newer)."
}

Write-Host "WSLC host setup starting on $([System.Environment]::OSVersion)"

if ($BinaryDirectory) {
    if (Test-Path $BinaryDirectory) {
        $BinaryDirectory = (Resolve-Path $BinaryDirectory).Path
        Write-Host "Binary directory: $BinaryDirectory"
    } else {
        Write-Failure "Binary directory not found: $BinaryDirectory"
        $BinaryDirectory = $null
    }
}

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
