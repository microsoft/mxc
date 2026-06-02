# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Windows Sandbox E2E test runner.
# Requires: Windows 11 Pro/Enterprise, Windows Sandbox enabled, Python on host.
# Cannot run in GitHub Actions CI (needs Hyper-V + Sandbox feature).
#
# Usage:
#   .\run_windows_sandbox_tests.ps1              # debug build
#   .\run_windows_sandbox_tests.ps1 -Release     # release build

param(
    [switch]$Release,
    [string]$BinDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$TestConfigs = Join-Path $RepoRoot "tests\configs"

# Find binaries
if (-not $BinDir) {
    if ($Release) {
        $BinDir = Join-Path $RepoRoot "src\target\release"
    } else {
        $BinDir = Join-Path $RepoRoot "src\target\debug"
    }
}

$WxcExec = Join-Path $BinDir "wxc-exec.exe"
$Daemon = Join-Path $BinDir "wxc-windows-sandbox-daemon.exe"

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}
if (-not (Test-Path $Daemon)) {
    Write-Host "ERROR: wxc-windows-sandbox-daemon.exe not found at $Daemon" -ForegroundColor Red
    exit 1
}

# Preflight: check Windows Sandbox is available
$sandboxFeature = dism /online /get-featureinfo /featurename:Containers-DisposableClientVM 2>&1 |
    Select-String "State"
if ($sandboxFeature -notmatch "Enabled") {
    Write-Host "ERROR: Windows Sandbox feature is not enabled." -ForegroundColor Red
    Write-Host "Run: dism /online /enable-feature /featurename:Containers-DisposableClientVM /all" -ForegroundColor Yellow
    exit 1
}

# Helpers
function Run-SandboxTest {
    param(
        [string]$ConfigFile,
        [int]$ExpectedExit = 0,
        [string]$OutputContains = "",
        [switch]$ExpectNonZero
    )

    $configPath = Join-Path $TestConfigs $ConfigFile
    if (-not (Test-Path $configPath)) {
        return @{ Name = $ConfigFile; Pass = $false; Reason = "Config file not found" }
    }

    Write-Host "  Running $ConfigFile... " -NoNewline

    # wxc-exec outputs base64-encoded stdout/stderr when not attached to a
    # terminal (e.g. when daemon was started via Start-Process). We capture
    # everything and try to decode any base64 lines we find.
    $output = & $WxcExec --debug --experimental $configPath 2>&1 | Out-String
    $exitCode = $LASTEXITCODE

    # Build a combined string: raw output + any decoded base64 lines.
    $decoded = $output
    $lines = $output -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    foreach ($line in $lines) {
        if ($line -match "^[A-Za-z0-9+/]{4,}[A-Za-z0-9+/=]*$") {
            try {
                $text = [System.Text.Encoding]::UTF8.GetString(
                    [System.Convert]::FromBase64String($line))
                $decoded += "`n" + $text
            } catch { }
        }
    }

    # Validate
    $pass = $true
    $reason = ""

    if ($ExpectNonZero) {
        if ($exitCode -eq 0) {
            $pass = $false
            $reason = "Expected non-zero exit, got 0"
        }
    } else {
        if ($exitCode -ne $ExpectedExit) {
            $pass = $false
            $reason = "Expected exit $ExpectedExit, got $exitCode"
        }
    }

    if ($pass -and $OutputContains -and $decoded -notmatch [regex]::Escape($OutputContains)) {
        $pass = $false
        $reason = "Output missing '$OutputContains'"
    }

    if ($pass) {
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host "    Reason: $reason" -ForegroundColor Red
        $meaningful = $output -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 5
        foreach ($line in $meaningful) {
            Write-Host "    > $($line.TrimEnd())" -ForegroundColor Gray
        }
    }

    return @{ Name = $ConfigFile; Pass = $pass; Reason = $reason }
}

# Clean up stale processes
Write-Host "`nSandbox E2E Tests" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan
Write-Host "`nCleaning up stale sandbox processes..." -ForegroundColor Yellow
Get-Process -Name "wxc-windows-sandbox-daemon","WindowsSandbox*" -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Remove-Item "$env:TEMP\wxc-sandbox-rendezvous\*" -ErrorAction SilentlyContinue
Start-Sleep 5

# Start daemon
Write-Host "Starting sandbox daemon..." -ForegroundColor Yellow
$daemonProc = Start-Process -FilePath $Daemon -ArgumentList "wxc-windows-sandbox","300000" `
    -PassThru -NoNewWindow -RedirectStandardError "$env:TEMP\wxc-windows-sandbox-daemon.log"
Start-Sleep 2

if ($daemonProc.HasExited) {
    Write-Host "ERROR: Daemon exited immediately. Check $env:TEMP\wxc-windows-sandbox-daemon.log" -ForegroundColor Red
    exit 1
}
Write-Host "Daemon started (PID $($daemonProc.Id))`n" -ForegroundColor Green

# Run tests
[System.Collections.ArrayList]$results = @()

Write-Host "--- Basic Tests ---" -ForegroundColor Cyan
$null = $results.Add((Run-SandboxTest "windows_sandbox_echo.json" -OutputContains "Hello from sandbox!"))
$null = $results.Add((Run-SandboxTest "basic_windows_sandbox.json" -OutputContains "executed successfully"))
$null = $results.Add((Run-SandboxTest "windows_sandbox_powershell.json" -OutputContains "PowerShell works"))
$null = $results.Add((Run-SandboxTest "windows_sandbox_powershell_env.json" -OutputContains "ComputerName="))
$null = $results.Add((Run-SandboxTest "windows_sandbox_stderr.json" -OutputContains "stdout-message"))
$null = $results.Add((Run-SandboxTest "windows_sandbox_exit_code.json" -ExpectedExit 42))

Write-Host "`n--- Timeout Test ---" -ForegroundColor Cyan
$null = $results.Add((Run-SandboxTest "windows_sandbox_timeout.json" -ExpectNonZero))

Write-Host "`n--- Multi-Exec Test (3x echo on same VM) ---" -ForegroundColor Cyan
for ($iter = 1; $iter -le 3; $iter++) {
    $result = Run-SandboxTest "windows_sandbox_echo.json" -OutputContains "Hello from sandbox!"
    $result.Name = "multi-exec #$iter (windows_sandbox_echo.json)"
    $null = $results.Add($result)
}

# Summary
$passed = ($results | Where-Object { $_.Pass }).Count
$failed = ($results | Where-Object { -not $_.Pass }).Count
$total = $results.Count

Write-Host "`n===================" -ForegroundColor Cyan
if ($failed -eq 0) {
    Write-Host "ALL $total TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "$passed/$total passed, $failed FAILED:" -ForegroundColor Red
    $results | Where-Object { -not $_.Pass } | ForEach-Object {
        Write-Host "  FAIL: $($_.Name) - $($_.Reason)" -ForegroundColor Red
    }
}

# Cleanup
Write-Host "`nStopping daemon..." -ForegroundColor Yellow
if (-not $daemonProc.HasExited) {
    Stop-Process -Id $daemonProc.Id -Force -ErrorAction SilentlyContinue
}
Get-Process -Name "WindowsSandbox*" -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

Write-Host "Daemon log: $env:TEMP\wxc-windows-sandbox-daemon.log" -ForegroundColor Gray

exit $(if ($failed -gt 0) { 1 } else { 0 })
