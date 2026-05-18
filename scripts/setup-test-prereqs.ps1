# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Sets up test prerequisites for MXC E2E tests on Windows.

.DESCRIPTION
    Installs and configures prerequisites needed to run MXC E2E tests:
    - Python 3.12 (system-wide install, accessible from AppContainers)
    - Disables App Execution Aliases for python.exe, python3.exe, and pwsh.exe
      (Store reparse points are incompatible with AppContainer/BaseContainer sandboxes)

    Must be run elevated (Administrator). Only needs to run once per machine.

.EXAMPLE
    # Run from an elevated PowerShell prompt:
    .\scripts\setup-test-prereqs.ps1

    # Check prerequisites without installing anything:
    .\scripts\setup-test-prereqs.ps1 -CheckOnly
#>

param(
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"

# --- Helpers ---

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-StoreAlias {
    param([string]$ExeName)
    $cmd = Get-Command $ExeName -ErrorAction SilentlyContinue
    if (-not $cmd) { return $false }
    $path = $cmd.Source
    return ($path -like "*WindowsApps*") -or ($path -like "*AppData*Microsoft*WindowsApps*")
}

function Disable-StoreAlias {
    param([string]$ExeName)
    # App Execution Aliases are stored as reparse points in WindowsApps directories.
    # Removing them from the user-local path disables the alias for the current user.
    $userAlias = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$ExeName"
    if (Test-Path $userAlias) {
        Remove-Item $userAlias -Force -ErrorAction SilentlyContinue
        Write-Host "  Disabled user alias: $userAlias" -ForegroundColor Green
    }

    # Also check the system-wide WindowsApps path and warn (can't remove without TrustedInstaller)
    $systemPaths = @(Get-Command $ExeName -All -ErrorAction SilentlyContinue | 
        Where-Object { $_.Source -like "*WindowsApps*" } |
        Select-Object -ExpandProperty Source)
    
    foreach ($p in $systemPaths) {
        if ($p -notlike "*$env:LOCALAPPDATA*") {
            Write-Host "  WARNING: System-wide Store alias exists: $p" -ForegroundColor Yellow
            Write-Host "           This may still shadow the real executable in some contexts." -ForegroundColor Yellow
            Write-Host "           Disable it manually: Settings > Apps > Advanced app settings > App execution aliases" -ForegroundColor Yellow
        }
    }
}

function Test-SystemPython {
    $commands = Get-Command python.exe -All -ErrorAction SilentlyContinue
    if (-not $commands) { return $false }
    # Satisfied if ANY match is a real system-wide install (not Store/AppData)
    foreach ($cmd in $commands) {
        $path = $cmd.Source
        if (($path -notlike "*WindowsApps*") -and ($path -notlike "*AppData*")) {
            return $true
        }
    }
    return $false
}

# --- Main ---

Write-Host ""
Write-Host "MXC E2E Test Prerequisites" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

$issues = @()

# 1. Check Python
Write-Host "[1/3] Python..." -NoNewline
if (Test-SystemPython) {
    $ver = & python.exe --version 2>&1
    Write-Host " OK ($ver, system-wide)" -ForegroundColor Green
} else {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Host " ISSUE (per-user or Store alias: $($cmd.Source))" -ForegroundColor Yellow
        $issues += "Python is installed per-user or via Store alias. AppContainers cannot access it."
    } else {
        Write-Host " MISSING" -ForegroundColor Red
        $issues += "Python is not installed."
    }
}

# 2. Check App Execution Aliases
Write-Host "[2/3] App Execution Aliases..." -NoNewline
$aliasIssues = @()
foreach ($exe in @("python.exe", "python3.exe", "pwsh.exe")) {
    if (Test-StoreAlias $exe) {
        $aliasIssues += $exe
    }
}
if ($aliasIssues.Count -eq 0) {
    Write-Host " OK (no Store aliases shadowing executables)" -ForegroundColor Green
} else {
    Write-Host " ISSUE ($($aliasIssues -join ', ') resolve to Store aliases)" -ForegroundColor Yellow
    $issues += "App Execution Aliases active for: $($aliasIssues -join ', '). These cause CreateProcessW failures in sandboxed containers."
}

# 3. Check PowerShell 7
Write-Host "[3/3] PowerShell 7..." -NoNewline
$pwshReal = Get-Command pwsh.exe -All -ErrorAction SilentlyContinue | 
    Where-Object { $_.Source -notlike "*WindowsApps*" } | 
    Select-Object -First 1
if ($pwshReal) {
    Write-Host " OK ($($pwshReal.Source))" -ForegroundColor Green
} else {
    Write-Host " MISSING (no non-Store pwsh.exe found)" -ForegroundColor Red
    $issues += "PowerShell 7 is not installed (or only available via Store alias)."
}

Write-Host ""

if ($issues.Count -eq 0) {
    Write-Host "All prerequisites met!" -ForegroundColor Green
    exit 0
}

# Report issues
Write-Host "Issues found:" -ForegroundColor Yellow
foreach ($issue in $issues) {
    Write-Host "  - $issue" -ForegroundColor Yellow
}
Write-Host ""

if ($CheckOnly) {
    Write-Host "Run without -CheckOnly to fix these issues (requires elevation)." -ForegroundColor Cyan
    exit 1
}

# --- Fix mode ---

if (-not (Test-Elevated)) {
    Write-Host "ERROR: Fixing prerequisites requires elevation. Run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "Fixing issues..." -ForegroundColor Cyan
Write-Host ""

# Fix: Install Python system-wide
if (-not (Test-SystemPython)) {
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        Write-Host "ERROR: winget is not available. Install Python 3.12 manually from https://python.org" -ForegroundColor Red
        Write-Host "       Choose 'Install for all users' during setup." -ForegroundColor Yellow
    } else {
        Write-Host "Installing Python 3.12 system-wide via winget..." -ForegroundColor Cyan
        winget install Python.Python.3.12 --scope machine --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: winget install failed (exit code $LASTEXITCODE)." -ForegroundColor Red
            Write-Host "       Install Python 3.12 manually from https://python.org (choose 'Install for all users')." -ForegroundColor Yellow
        } else {
            # Refresh PATH for current session
            $machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
            $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
            $env:PATH = "$machinePath;$userPath"

            if (Test-SystemPython) {
                $ver = & python.exe --version 2>&1
                Write-Host "Python installed successfully ($ver)" -ForegroundColor Green
            } else {
                Write-Host "WARNING: Python install completed but python.exe not found in PATH." -ForegroundColor Yellow
                Write-Host "         You may need to restart your terminal." -ForegroundColor Yellow
            }
        }
    }
}

# Fix: Disable Store aliases
foreach ($exe in @("python.exe", "python3.exe", "pwsh.exe")) {
    if (Test-StoreAlias $exe) {
        Write-Host "Disabling Store alias for $exe..." -ForegroundColor Cyan
        Disable-StoreAlias $exe
    }
}

Write-Host ""
Write-Host "Done. Restart your terminal, then verify with:" -ForegroundColor Green
Write-Host "  .\scripts\setup-test-prereqs.ps1 -CheckOnly" -ForegroundColor Gray
Write-Host ""
