# Registry Override Test Script
# Requires: Administrator privileges, wxc-exec.exe built
#
# This script:
#   1. Sets up registry keys pointing at test config files
#   2. Runs wxc-exec with baseline configs and verifies the registry override is applied
#   3. Tests all three modes: no override, merge mode, full override
#   4. Cleans up registry keys when done
#
# Usage:
#   .\run_registry_override_tests.ps1 [-BinDir <path>] [-Debug]

param(
    [string]$BinDir = "",
    [switch]$Debug
)

$ErrorActionPreference = "Stop"

# Suppress hard-error crash dialogs (e.g. STATUS_DLL_INIT_FAILED) so
# expected-failure tests don't hang waiting for user input.
# Child processes inherit the parent's error mode.
Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public class WxcTestNative {
    [DllImport("kernel32.dll")]
    public static extern uint SetErrorMode(uint uMode);
}
"@
# SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
$script:prevErrorMode = [WxcTestNative]::SetErrorMode(0x8003)

# Locate wxc-exec.exe
# build.bat defaults to release with --target, so we match that here.
# Pass -Debug to use debug binaries instead.
if ($BinDir -eq "") {
    $profile = if ($Debug) { "debug" } else { "release" }
    $BinDir = Join-Path $PSScriptRoot "..\..\src\target\x86_64-pc-windows-msvc\$profile"
}
$BinDir = [IO.Path]::GetFullPath($BinDir)
$wxcExec = Join-Path $BinDir "wxc-exec.exe"
if (-not (Test-Path $wxcExec)) {
    Write-Host "FAIL: wxc-exec.exe not found at $wxcExec" -ForegroundColor Red
    exit 1
}

$configDir = Join-Path $PSScriptRoot "..\..\test_configs\registry_override_configs"
$configDir = [IO.Path]::GetFullPath($configDir)

Write-Host "Using wxc-exec: $wxcExec"
Write-Host "Config dir:    $configDir"

$regBase = "HKLM:\SOFTWARE\Microsoft\MXC\Diagnostics\Exec"
$markerDir = "C:\MxcTestOutput"
$markerFile = "$markerDir\marker.txt"
$passed = 0
$failed = 0
$results = @()
$script:lastRegistryMsg = $null

function Run-Test {
    param(
        [string]$Name,
        [string]$ConfigPath,
        [string]$ExpectPattern,
        [switch]$ExpectFail
    )

    $testNum = $script:passed + $script:failed + 1
    Write-Host ""
    Write-Host "  [$testNum] $Name" -ForegroundColor Cyan
    if ($script:lastRegistryMsg) {
        Write-Host "      $($script:lastRegistryMsg)" -ForegroundColor DarkGray
        $script:lastRegistryMsg = $null
    }

    # Prepare marker dir for sandbox output and clean any stale marker
    if (-not (Test-Path $markerDir)) { New-Item -ItemType Directory -Path $markerDir -Force | Out-Null }
    if (Test-Path $markerFile) { Remove-Item $markerFile -Force }

    $output = ""
    $exitCode = 0
    try {
        $proc = Start-Process -FilePath $wxcExec -ArgumentList "--debug", $ConfigPath `
            -Wait -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput "$env:TEMP\wxc_test_stdout.txt" `
            -RedirectStandardError "$env:TEMP\wxc_test_stderr.txt"
        $exitCode = $proc.ExitCode
        $output = (Get-Content "$env:TEMP\wxc_test_stdout.txt" -Raw) + (Get-Content "$env:TEMP\wxc_test_stderr.txt" -Raw)
    }
    catch {
        $output = $_.Exception.Message
        $exitCode = 1
    }

    # Read the marker file written by the sandboxed process
    $marker = ""
    if (Test-Path $markerFile) {
        $marker = (Get-Content $markerFile -Raw).Trim()
        Remove-Item $markerFile -Force
    }

    $success = $false
    if ($ExpectFail) {
        if ($exitCode -ne 0) {
            $success = $true
            Write-Host "      PASS - failed as expected (exit code $exitCode)" -ForegroundColor Green
        } else {
            Write-Host "      FAIL - expected failure but process succeeded" -ForegroundColor Red
        }
    } elseif ($exitCode -eq 0) {
        if ($ExpectPattern -ne "" -and $marker -notmatch $ExpectPattern) {
            Write-Host "      FAIL - marker did not match '$ExpectPattern'" -ForegroundColor Red
            Write-Host "      Marker: $marker"
        } else {
            $success = $true
            if ($marker) {
                Write-Host "      PASS - ""$marker""" -ForegroundColor Green
            } else {
                Write-Host "      PASS" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "      FAIL - exit code $exitCode" -ForegroundColor Red
        Write-Host "      Output: $($output.Trim())"
    }

    $script:results += [PSCustomObject]@{
        Test    = $Name
        Result  = if ($success) { "PASS" } else { "FAIL" }
    }
    if ($success) { $script:passed++ } else { $script:failed++ }
}

function Set-RegistryOverride {
    param(
        [string]$ExeName,
        [string]$ConfigPath,
        [int]$OverrideConfig = 0,
        [int]$OverrideFilesystem = -1,
        [int]$OverrideNetwork = -1,
        [int]$OverrideUi = -1
    )
    $keyPath = "$regBase\$ExeName"
    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $keyPath -Name "(Default)" -Value $ConfigPath
    Set-ItemProperty -Path $keyPath -Name "OverrideConfig" -Value $OverrideConfig -Type DWord

    if ($OverrideFilesystem -ge 0) {
        Set-ItemProperty -Path $keyPath -Name "OverrideFilesystemPolicy" -Value $OverrideFilesystem -Type DWord
    }
    if ($OverrideNetwork -ge 0) {
        Set-ItemProperty -Path $keyPath -Name "OverrideNetworkPolicy" -Value $OverrideNetwork -Type DWord
    }
    if ($OverrideUi -ge 0) {
        Set-ItemProperty -Path $keyPath -Name "OverrideUiPolicy" -Value $OverrideUi -Type DWord
    }
    $script:lastRegistryMsg = "Registry: $ExeName -> $(Split-Path $ConfigPath -Leaf) (OverrideConfig=$OverrideConfig)"
}

function Remove-RegistryOverrides {
    if (Test-Path $regBase) {
        Remove-Item -Path $regBase -Recurse -Force
    }
}

# ---------- Test execution ----------

Write-Host "============================================"
Write-Host "MXC Registry Override Tests"
Write-Host "============================================"

# Clean any leftover keys from a previous run
Remove-RegistryOverrides

# ------------------------------------------------------------------
# TEST 1: No registry key - baseline runs normally
# ------------------------------------------------------------------
Run-Test -Name "PS 5.1 baseline (no registry override)" `
    -ConfigPath "$configDir\ps51_baseline.json" `
    -ExpectPattern "baseline config"

# ------------------------------------------------------------------
# TEST 2: Full override (OverrideConfig=1) with PS 5.1
# The baseline says powershell.exe but the registry config also runs
# powershell.exe with different output text. Since OverrideConfig=1,
# the entire registry config replaces the original.
# ------------------------------------------------------------------
Set-RegistryOverride -ExeName "powershell.exe" `
    -ConfigPath "$configDir\ps51_override.json" `
    -OverrideConfig 1
Run-Test -Name "PS 5.1 full override (OverrideConfig=1)" `
    -ConfigPath "$configDir\ps51_baseline.json" `
    -ExpectPattern "Hello from registry override"
Remove-RegistryOverrides

# ------------------------------------------------------------------
# TEST 3: Merge mode (OverrideConfig=0) - execution context from
# original, policies from original (no per-policy overrides set)
# ------------------------------------------------------------------
Set-RegistryOverride -ExeName "powershell.exe" `
    -ConfigPath "$configDir\ps51_override.json" `
    -OverrideConfig 0
Run-Test -Name "PS 5.1 merge mode (policies from original)" `
    -ConfigPath "$configDir\ps51_baseline.json" `
    -ExpectPattern "baseline config"
Remove-RegistryOverrides

# ------------------------------------------------------------------
# TEST 4: Merge mode with OverrideUiPolicy=1 - registry's UI policy
# is used. The restrictive UI config has disable=true which should
# cause PowerShell 5.1 to fail (needs UI).
# ------------------------------------------------------------------
Set-RegistryOverride -ExeName "powershell.exe" `
    -ConfigPath "$configDir\ps51_override_restrictive_ui.json" `
    -OverrideConfig 0 `
    -OverrideUi 1
Run-Test -Name "PS 5.1 merge + OverrideUiPolicy=1 (restrictive UI, expect fail)" `
    -ConfigPath "$configDir\ps51_baseline.json" `
    -ExpectFail
Remove-RegistryOverrides

# ------------------------------------------------------------------
# TEST 5: Merge mode with OverrideUiPolicy=0 (explicit) - original
# UI policy is kept so PS 5.1 should succeed.
# ------------------------------------------------------------------
Set-RegistryOverride -ExeName "powershell.exe" `
    -ConfigPath "$configDir\ps51_override_restrictive_ui.json" `
    -OverrideConfig 0 `
    -OverrideUi 0
Run-Test -Name "PS 5.1 merge + OverrideUiPolicy=0 (original UI kept, expect pass)" `
    -ConfigPath "$configDir\ps51_baseline.json" `
    -ExpectPattern "baseline config"
Remove-RegistryOverrides

# ------------------------------------------------------------------
# TEST 6: Registry key exists but no default value - should proceed
# with original config (no override applied).
# ------------------------------------------------------------------
$keyPath = "$regBase\powershell.exe"
New-Item -Path $keyPath -Force | Out-Null
# Do not set (Default) value
Run-Test -Name "PS 5.1 registry key with no config path (no registry override)" `
    -ConfigPath "$configDir\ps51_baseline.json" `
    -ExpectPattern "baseline config"
Remove-RegistryOverrides

# ---------- Summary ----------

# Restore error mode
[WxcTestNative]::SetErrorMode($script:prevErrorMode) | Out-Null

# Clean up marker directory
if (Test-Path $markerDir) { Remove-Item $markerDir -Recurse -Force }

Write-Host ""
Write-Host "============================================"
Write-Host "Results Summary"
Write-Host "============================================"
$results | Format-Table -AutoSize
Write-Host "Passed: $passed  Failed: $failed  Total: $($passed + $failed)"

if ($failed -gt 0) {
    Write-Host "SOME TESTS FAILED" -ForegroundColor Red
    exit 1
} else {
    Write-Host "ALL TESTS PASSED" -ForegroundColor Green
    exit 0
}
