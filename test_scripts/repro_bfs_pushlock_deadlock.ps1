# repro_bfs_pushlock_deadlock.ps1
# Reproducer for bfs.sys pushlock deadlock on Windows 25H2+.
#
# Runs the mxc CLI test suite repeatedly. The combination of AppContainer
# creation, BFS policy setup, proxy/firewall configuration, and containerized
# process I/O triggers a pushlock deadlock in bfs!BfsPreCreateOperation that
# freezes the entire system.
#
# PREREQUISITES:
#   - Windows 25H2+ with C:\Windows\System32\bfscfg.exe present
#   - mxc repo with cli/ built (npm run build in cli/)
#   - Run as Administrator
#   - Take a VM checkpoint first! This WILL freeze the machine.
#
# USAGE (Admin PowerShell, from mxc repo root):
#   .\test_scripts\repro_bfs_pushlock_deadlock.ps1 [-CliDir <path>] [-Iterations <n>]

#Requires -RunAsAdministrator

param(
    [string]$CliDir,
    [int]$Iterations = 30
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path "$env:SystemRoot\System32\bfscfg.exe")) {
    Write-Error "bfscfg.exe not found. Requires Windows 25H2+."
    exit 1
}

# Find cli directory
if (-not $CliDir) {
    $candidates = @(
        (Join-Path $PSScriptRoot "..\cli"),
        "C:\Users\bbonaby\Downloads\mxc\cli"
    )
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "package.json")) { $CliDir = (Resolve-Path $c).Path; break }
    }
}

if (-not $CliDir -or -not (Test-Path (Join-Path $CliDir "package.json"))) {
    Write-Error "cli directory not found. Use -CliDir <path> or run from the mxc repo."
    exit 1
}

Write-Host "=== BFS Pushlock Deadlock Reproducer ===" -ForegroundColor Red
Write-Host "WARNING: This WILL freeze the system if the bug is present!" -ForegroundColor Yellow
Write-Host "CLI dir:    $CliDir"
Write-Host "Iterations: $Iterations (npm test runs)"
Write-Host ""
Write-Host "Press Ctrl+C within 5 seconds to abort..." -ForegroundColor Yellow
Start-Sleep 5

Write-Host "Running npm test in a loop..." -ForegroundColor Cyan
Write-Host "If the system freezes, the bug is confirmed." -ForegroundColor Yellow
Write-Host ""

Push-Location $CliDir
try {
    for ($i = 1; $i -le $Iterations; $i++) {
        $ts = Get-Date -Format "HH:mm:ss.fff"
        Write-Host "[$ts] npm test run $i/$Iterations" -ForegroundColor White

        npm test 2>&1 | Select-Object -Last 5
        Write-Host ""
    }

    Write-Host "Completed $Iterations runs without deadlock." -ForegroundColor Green
} finally {
    Pop-Location
}
