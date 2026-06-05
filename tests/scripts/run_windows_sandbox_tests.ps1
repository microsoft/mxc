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

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
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
function Wait-ForSandboxIdle {
    # Each Run-SandboxTest spawns a fresh, disposable Windows Sandbox VM. The
    # VM's `WindowsSandbox*` host processes are reaped by the one-shot
    # teardown path, but the `vmmem*` Hyper-V memory residue can take longer
    # to release (Hyper-V backend cooldown). Running tests back-to-back
    # without waiting for that residue can stack vmmem processes and OOM the
    # host on memory-constrained machines.
    #
    # Wait until: no WindowsSandbox* processes remain AND fewer than 2 vmmem*
    # processes remain (one residual is normal — vmmemCmZygote always exists
    # on hosts with Containers feature enabled).
    param([int]$TimeoutSec = 60)

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $wsb = @(Get-Process -Name "WindowsSandbox*" -ErrorAction SilentlyContinue)
        $vmmem = @(Get-Process -Name "vmmem*" -ErrorAction SilentlyContinue)
        if ($wsb.Count -eq 0 -and $vmmem.Count -le 1) {
            return $true
        }
        Start-Sleep -Seconds 2
    }
    Write-Host "    [warn] sandbox processes still present after ${TimeoutSec}s settle wait" -ForegroundColor Yellow
    return $false
}

function Test-MemoryHeadroom {
    # If free memory is below 2 GB we cannot safely spin another sandbox VM
    # (each VM reserves ~1-1.5 GB minimum). Skip rather than risk OOM.
    $os = Get-CimInstance Win32_OperatingSystem
    $freeMb = [int]($os.FreePhysicalMemory / 1024)
    if ($freeMb -lt 2048) {
        Write-Host "    [skip] insufficient free memory (${freeMb} MB free, need >=2048 MB)" -ForegroundColor Yellow
        return $false
    }
    return $true
}

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

    # Pre-flight: ensure prior test's VM has fully released, and we have
    # enough free memory to launch another VM.
    [void](Wait-ForSandboxIdle -TimeoutSec 60)
    if (-not (Test-MemoryHeadroom)) {
        return @{ Name = $ConfigFile; Pass = $false; Reason = "Insufficient memory for new VM" }
    }

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

# The one-shot Windows Sandbox path (`containment: "windows_sandbox"` with no
# state-aware phase envelope) spawns a fresh, disposable VM per invocation
# directly from `wxc-exec.exe`. It does NOT use the persistent
# `wxc-windows-sandbox-daemon.exe` — that daemon is now exclusively for the
# state-aware lifecycle (see run_windows_sandbox_state_aware_tests.ps1).
# Earlier versions of this script pre-spawned the daemon to drive a
# warm-reuse one-shot path that no longer exists; that pre-spawn now just
# breaks (the daemon requires `--token` + stdin nonce, not positional args).
Write-Host "Using fresh-VM-per-call one-shot path (no pre-spawned daemon).`n" -ForegroundColor Yellow

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

Write-Host "`n--- Multi-Exec Test (3x echo, each on its own fresh VM) ---" -ForegroundColor Cyan
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
Write-Host "`nFinal cleanup of any lingering Windows Sandbox processes..." -ForegroundColor Yellow
Get-Process -Name "WindowsSandbox*","wxc-windows-sandbox-daemon" -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

exit $(if ($failed -gt 0) { 1 } else { 0 })
