#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstalls the MXC Diagnostic Service.
.DESCRIPTION
    Stops and removes the MxcDiagnosticService Windows service.
.PARAMETER BinaryPath
    Optional path to mxc-diagnostic-console.exe for the --uninstall command.
    If not specified, uses the service's registered binary path. The supplied
    or registered path is validated (must be an existing file named
    mxc-diagnostic-console.exe) before it is executed elevated.
.PARAMETER AllowUnsigned
    Allow running an uninstall binary whose Authenticode signature is not Valid.
    Must be passed explicitly and is warned loudly.
#>
param(
    [string]$BinaryPath,
    [switch]$AllowUnsigned
)

$ErrorActionPreference = 'Stop'

$ExpectedServiceName = 'MxcDiagnosticService'
$ExpectedBinaryName  = 'mxc-diagnostic-console.exe'

# Verify the binary is named as expected, resolves to an existing file, and has
# a valid Authenticode signature before we execute it elevated.
function Test-UninstallBinary {
    param([string]$Path)

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $resolved) { return $null }
    $full = $resolved.ProviderPath
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return $null }
    if ((Split-Path -Leaf $full) -ne $ExpectedBinaryName) {
        Write-Warning "Ignoring unexpected uninstall binary (not $ExpectedBinaryName): $full"
        return $null
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $full
    if ($signature.Status -ne 'Valid') {
        if ($AllowUnsigned) {
            Write-Warning "Authenticode signature is NOT valid (status: $($signature.Status)) for: $full. Proceeding because -AllowUnsigned was specified."
        } else {
            Write-Warning "Skipping binary --uninstall: Authenticode signature is not valid (status: $($signature.Status)) for: $full. Pass -AllowUnsigned to override."
            return $null
        }
    }
    return $full
}

# Stop the service if running. Verify it is the expected service first.
$svc = Get-Service $ExpectedServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Name -ne $ExpectedServiceName) {
        Write-Error "Refusing to remove unexpected service '$($svc.Name)' (expected '$ExpectedServiceName')."
        exit 1
    }
    if ($svc.Status -eq 'Running') {
        Write-Host "Stopping $ExpectedServiceName..."
        Stop-Service $ExpectedServiceName -Force
        Start-Sleep -Seconds 2
    }
} else {
    Write-Host "Service $ExpectedServiceName not found. Nothing to uninstall."
    exit 0
}

# Prefer the binary the service is actually registered with, so we run the same
# trusted binary that was installed rather than rediscovering an arbitrary one.
if (-not $BinaryPath) {
    $registered = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$ExpectedServiceName'" -ErrorAction SilentlyContinue).PathName
    if ($registered) {
        # PathName may be quoted and include trailing arguments; take the exe.
        if ($registered -match '^\s*"([^"]+)"') {
            $BinaryPath = $Matches[1]
        } else {
            $BinaryPath = ($registered -split '\s+')[0]
        }
    }
}

$validBinary = $null
if ($BinaryPath) {
    $validBinary = Test-UninstallBinary -Path $BinaryPath
}

if ($validBinary) {
    Write-Host "Uninstalling MXC Diagnostic Service..."
    Write-Host "  Binary: $validBinary"
    & $validBinary --uninstall
} else {
    # Fallback: delete the (verified) service registration directly.
    Write-Host "No valid binary available, removing service registration directly..."
    sc.exe delete $ExpectedServiceName
}

Write-Host ""
Write-Host "MXC Diagnostic Service uninstalled." -ForegroundColor Green
