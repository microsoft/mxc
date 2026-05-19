# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Sets up test prerequisites for MXC E2E tests on Windows.

.DESCRIPTION
    Installs and configures prerequisites needed to run MXC E2E tests:
    - Python 3.12 (system-wide install, accessible from AppContainers)
    - Disables App Execution Aliases for python.exe, python3.exe, and pwsh.exe
      (their reparse points are incompatible with AppContainer/BaseContainer sandboxes)

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

function Test-AppExecutionAlias {
    param([string]$ExeName)
    $aliasPath = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$ExeName"
    return (Test-Path $aliasPath)
}

function Disable-AppExecutionAlias {
    param([string]$ExeName)
    # NOTE: This script is intended for TEST MACHINES ONLY.
    # App Execution Aliases are reparse points at %LOCALAPPDATA%\Microsoft\WindowsApps\<exe>.
    # The Settings UI ("Apps > Advanced app settings > App execution aliases")
    # disables an alias by deleting this file (per Windows OS source:
    # onecore/base/appmodel/AppExecutionAlias/settingshandlers/lib/SettingsHandlers.cpp,
    # AppAliasListItemSetting::SetValue -> DeleteFileIgnoreNotFound).
    # Removing the file IS the documented Windows mechanism to disable an alias.
    # Caveats:
    #   - Windows Updates / packaged app updates may restore the reparse point.
    #   - For legitimately packaged apps (e.g. Store-installed PowerShell), removing
    #     the alias also removes the convenient `pwsh.exe` PATH entry. Tests should
    #     use a fully-qualified install path (e.g. C:\Program Files\PowerShell\7\pwsh.exe).
    $userAlias = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$ExeName"
    if (Test-Path $userAlias) {
        try {
            Remove-Item $userAlias -Force -ErrorAction Stop
            Write-Host "  Disabled user alias: $userAlias" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to remove $userAlias`: $($_.Exception.Message)"
        }
    }
}

function Test-SystemPython {
    $commands = Get-Command python.exe -All -ErrorAction SilentlyContinue
    if (-not $commands) { return $false }
    # Satisfied if ANY match is a real system-wide install (not an alias / per-user path)
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
        Write-Host " ISSUE (per-user or App Execution Alias: $($cmd.Source))" -ForegroundColor Yellow
        $issues += "Python is installed per-user or only as an App Execution Alias. AppContainers cannot access it."
    } else {
        Write-Host " MISSING" -ForegroundColor Red
        $issues += "Python is not installed."
    }
}

# 2. Check App Execution Aliases
Write-Host "[2/3] App Execution Aliases..." -NoNewline
$aliasIssues = @()
foreach ($exe in @("python.exe", "python3.exe", "pwsh.exe")) {
    if (Test-AppExecutionAlias $exe) {
        $aliasIssues += $exe
    }
}
if ($aliasIssues.Count -eq 0) {
    Write-Host " OK (no App Execution Aliases shadowing executables)" -ForegroundColor Green
} else {
    Write-Host " ISSUE ($($aliasIssues -join ', ') resolve to App Execution Aliases)" -ForegroundColor Yellow
    $issues += "App Execution Aliases active for: $($aliasIssues -join ', '). These cause CreateProcessW failures in sandboxed containers."
}

# 3. Check PowerShell 7 at expected install path
$PwshExpectedPath = "C:\Program Files\PowerShell\7\pwsh.exe"
Write-Host "[3/3] PowerShell 7..." -NoNewline
if (Test-Path $PwshExpectedPath) {
    Write-Host " OK ($PwshExpectedPath)" -ForegroundColor Green
} else {
    Write-Host " MISSING (not found at $PwshExpectedPath)" -ForegroundColor Red
    $issues += "PowerShell 7 is not installed at $PwshExpectedPath (required by test configs)."
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
    Write-Warning "Fixing prerequisites requires elevation. Run as Administrator."
    exit 1
}

Write-Host "Fixing issues..." -ForegroundColor Cyan
Write-Host ""

# Fix: Install Python system-wide
if (-not (Test-SystemPython)) {
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        Write-Warning "winget is not available. Install Python 3.12 manually from https://python.org (choose 'Install for all users')."
    } else {
        Write-Host "Installing Python 3.12 system-wide via winget..." -ForegroundColor Cyan
        winget install Python.Python.3.12 --scope machine --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "winget install failed (exit code $LASTEXITCODE). Install Python 3.12 manually from https://python.org (choose 'Install for all users')."
        } else {
            # Refresh PATH for current session
            $machinePath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
            $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
            $env:PATH = "$machinePath;$userPath"

            if (Test-SystemPython) {
                $ver = & python.exe --version 2>&1
                Write-Host "Python installed successfully ($ver)" -ForegroundColor Green
            } else {
                Write-Warning "Python install completed but python.exe not found in PATH. You may need to restart your terminal."
            }
        }
    }
}

# Fix: Disable App Execution Aliases that shadow real executables
foreach ($exe in @("python.exe", "python3.exe", "pwsh.exe")) {
    if (Test-AppExecutionAlias $exe) {
        Write-Host "Disabling App Execution Alias for $exe..." -ForegroundColor Cyan
        Disable-AppExecutionAlias $exe
    }
}

Write-Host ""
Write-Host "Done. Restart your terminal, then verify with:" -ForegroundColor Green
Write-Host "  .\scripts\setup-test-prereqs.ps1 -CheckOnly" -ForegroundColor Gray
Write-Host ""
