#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the MXC Diagnostic Service for denied-resource detection.
.DESCRIPTION
    Registers mxc-diagnostic-console.exe as a Windows service (MxcDiagnosticService)
    that monitors ETW events to detect resource access denials in sandboxed processes.
.PARAMETER BinaryPath
    Optional path to mxc-diagnostic-console.exe. If not specified, searches a
    trusted, admin-only install location under %ProgramFiles%.
.PARAMETER AllowDevPath
    Opt in to discovering the binary from user-writable repo build-output
    directories (sdk\bin, src\target). These paths are unsafe for production
    installs because any non-admin who can write there could plant a binary
    that then runs elevated and persists as an auto-start service.
.PARAMETER AllowUnsigned
    Allow installing a binary whose Authenticode signature is not Valid.
    Dev builds are unsigned (codesigning happens at release time), so this
    override exists, but it must be passed explicitly and is warned loudly.
#>
param(
    [string]$BinaryPath,
    [switch]$AllowDevPath,
    [switch]$AllowUnsigned
)

$ErrorActionPreference = 'Stop'

# Trusted, admin-only install location. Only Administrators/SYSTEM can write
# under %ProgramFiles% by default, so a binary resolved here cannot be planted
# by a non-admin user.
$TrustedInstallDir = Join-Path $env:ProgramFiles 'MXC\DiagnosticService'

# Locations that are writable by the user that produced the build. Discovering
# the binary from here is a dev convenience only and is gated behind
# -AllowDevPath because these paths are not safe for a production install.
function Get-DevBinaryCandidates {
    $scriptDir = Split-Path -Parent $PSScriptRoot

    # Support both architectures, preferring the native one first so a build for
    # the host arch is discovered ahead of a cross-compiled one.
    $triples = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
        @('aarch64-pc-windows-msvc', 'x86_64-pc-windows-msvc')
    } else {
        @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')
    }

    $candidates = @()
    # npm-packaged SDK binary location.
    foreach ($triple in $triples) {
        $candidates += (Join-Path $scriptDir "sdk\bin\$triple\mxc-diagnostic-console.exe")
    }
    # Architecture-specific cargo build output (monorepo dev).
    foreach ($triple in $triples) {
        $candidates += (Join-Path $scriptDir "src\target\$triple\release\mxc-diagnostic-console.exe")
        $candidates += (Join-Path $scriptDir "src\target\$triple\debug\mxc-diagnostic-console.exe")
    }
    # Default cargo build output (no explicit --target).
    $candidates += (Join-Path $scriptDir 'src\target\release\mxc-diagnostic-console.exe')
    $candidates += (Join-Path $scriptDir 'src\target\debug\mxc-diagnostic-console.exe')
    return $candidates
}

function Find-ServiceBinary {
    # Prefer the trusted, admin-only install location.
    $trusted = Join-Path $TrustedInstallDir 'mxc-diagnostic-console.exe'
    if (Test-Path -LiteralPath $trusted -PathType Leaf) { return $trusted }

    # Fall back to user-writable build-output dirs only with explicit opt-in.
    if ($AllowDevPath) {
        Write-Warning "Discovering binary from build-output directories. These paths are user-writable and are NOT safe for a production install."
        foreach ($path in (Get-DevBinaryCandidates)) {
            if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
        }
    }
    return $null
}

# Returns $true if the path resolves under a user-writable location that a
# non-admin could use to plant a binary.
function Test-PathIsUserWritable {
    param([string]$Path)

    $userWritableRoots = @(
        $env:USERPROFILE,
        $env:TEMP,
        $env:TMP,
        $env:LOCALAPPDATA,
        $env:APPDATA,
        $env:PUBLIC
    ) | Where-Object { $_ } | ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') }

    foreach ($root in $userWritableRoots) {
        if ($Path.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
            $Path.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

if (-not $BinaryPath) {
    $BinaryPath = Find-ServiceBinary
    if (-not $BinaryPath) {
        Write-Error "Could not find mxc-diagnostic-console.exe in the trusted location ($TrustedInstallDir). Specify -BinaryPath, install the binary to the trusted location, or pass -AllowDevPath to use a build-output directory."
        exit 1
    }
}

# Resolve to a fully-qualified, absolute path and confirm it is an existing file.
$resolved = Resolve-Path -LiteralPath $BinaryPath -ErrorAction SilentlyContinue
if (-not $resolved) {
    Write-Error "Binary path does not exist: $BinaryPath"
    exit 1
}
$BinaryPath = $resolved.ProviderPath
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    Write-Error "Binary path is not a file: $BinaryPath"
    exit 1
}

# Reject user-writable locations for a production install unless the operator
# explicitly opted in to dev paths.
if ((Test-PathIsUserWritable -Path $BinaryPath) -and -not $AllowDevPath) {
    Write-Error "Refusing to install a binary from a user-writable location: $BinaryPath. Install it under '$TrustedInstallDir', or pass -AllowDevPath to override (unsafe)."
    exit 1
}

# Verify the Authenticode signature before executing or registering the binary.
$signature = Get-AuthenticodeSignature -LiteralPath $BinaryPath
if ($signature.Status -ne 'Valid') {
    if ($AllowUnsigned) {
        Write-Warning "Authenticode signature is NOT valid (status: $($signature.Status)) for: $BinaryPath"
        Write-Warning "Proceeding because -AllowUnsigned was specified. This is unsafe for a production install."
    } else {
        Write-Error "Refusing to install: Authenticode signature is not valid (status: $($signature.Status)) for: $BinaryPath. Pass -AllowUnsigned to override (unsafe; dev builds are unsigned)."
        exit 1
    }
} else {
    Write-Host "  Signature: Valid ($($signature.SignerCertificate.Subject))"
}

Write-Host "Installing MXC Diagnostic Service..."
Write-Host "  Binary: $BinaryPath"

& $BinaryPath --install
if ($LASTEXITCODE -ne 0) {
    Write-Error "Service installation failed (exit code $LASTEXITCODE)"
    exit $LASTEXITCODE
}

# Start the service
Start-Service MxcDiagnosticService -ErrorAction Stop
Write-Host ""
Write-Host "MXC Diagnostic Service installed and running." -ForegroundColor Green
Write-Host "  Service name: MxcDiagnosticService"
Write-Host "  Status: $(Get-Service MxcDiagnosticService | Select-Object -ExpandProperty Status)"
