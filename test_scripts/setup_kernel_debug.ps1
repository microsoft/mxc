# setup_kernel_debug.ps1
# Full setup for capturing BFS deadlocks on the ge_current_winpd VM.
#
# STEP 1 (IN THE VM - Admin PowerShell):
#   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 0 /f
#   bcdedit /debug on
#   bcdedit /dbgsettings net hostip:10.0.1.202 port:50000 key:bfs.debug.test.key1
#   shutdown /r /t 0
#
# STEP 2 (ON THE HOST - Admin PowerShell):
#   .\test_scripts\setup_kernel_debug.ps1
#
# This script:
#   1. Launches WinDbg attached to the VM's kernel debugger
#   2. After you press 'g' in WinDbg and the VM boots, runs the BFS repro
#   3. When the VM freezes, break into WinDbg (Ctrl+Break) and inspect

param(
    [string]$VMName = "ge_current_winpd",
    [string]$HostIP = "10.0.1.202",
    [int]$Port = 50000,
    [string]$Key = "bfs.debug.test.key1",
    [switch]$SkipDebugger
)

$ErrorActionPreference = "Stop"

Write-Host "=== BFS Deadlock Capture for VM: $VMName ===" -ForegroundColor Cyan
Write-Host ""

# Verify VM exists and is running
$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if (-not $vm) {
    Write-Error "VM '$VMName' not found"
    exit 1
}

if (-not $SkipDebugger) {
    Write-Host "Launching WinDbg kernel debugger..." -ForegroundColor Yellow
    Write-Host "  Connection: net:port=$Port,key=$Key" -ForegroundColor White
    Start-Process "WinDbgX.exe" -ArgumentList "-k", "net:port=$Port,key=$Key"
    Write-Host ""
    Write-Host "WinDbg launched. When the VM connects:" -ForegroundColor Green
    Write-Host "  1. Wait for 'Debuggee connected' in WinDbg"
    Write-Host "  2. Press 'g' (Go) to let the VM continue booting"
    Write-Host "  3. Come back here and press Enter to start the BFS repro"
    Write-Host ""
    Read-Host "Press Enter when the VM is booted and ready"
}

# Test connectivity to VM
Write-Host "Testing VM connectivity..." -ForegroundColor Yellow
$secpw = New-Object System.Security.SecureString
$cred = New-Object System.Management.Automation.PSCredential('bbonaby', $secpw)

try {
    $result = Invoke-Command -VMName $VMName -Credential $cred -ErrorAction Stop -ScriptBlock {
        "Connected to $env:COMPUTERNAME"
    }
    Write-Host $result -ForegroundColor Green
} catch {
    Write-Host "Cannot connect with blank password." -ForegroundColor Red
    Write-Host "Run this IN THE VM first (Admin PowerShell):" -ForegroundColor Yellow
    Write-Host '  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 0 /f' -ForegroundColor White
    exit 1
}

# Run BFS repro
Write-Host ""
Write-Host "=== Starting BFS repro ===" -ForegroundColor Cyan
Write-Host "Running wxc-exec with BFS config repeatedly inside the VM..."
Write-Host "If the VM freezes, press Ctrl+Break in WinDbg, then run:" -ForegroundColor Yellow
Write-Host '  !locks' -ForegroundColor White
Write-Host '  !process 0 7 svchost.exe' -ForegroundColor White
Write-Host '  (look for bfs!BfsPreCreateOperation in stacks)' -ForegroundColor White
Write-Host ""

$wxcExe = 'C:\Users\bbonaby\Downloads\mxc\cli\node_modules\@microsoft\mxc-sdk\bin\x86_64-pc-windows-msvc\wxc-exec.exe'
$config = 'C:\Users\bbonaby\Downloads\mxc\test_configs\filesystem_bfs_spaces_test.json'

Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    param($wxcExe, $config)

    if (-not (Test-Path $wxcExe)) {
        Write-Error "wxc-exec.exe not found at: $wxcExe"
        return
    }

    # Ensure test directory exists
    $testDir = 'C:\Users\Public\wxc bfs test'
    if (-not (Test-Path $testDir)) {
        New-Item -Path $testDir -ItemType Directory -Force | Out-Null
    }

    for ($i = 1; $i -le 50; $i++) {
        $ts = Get-Date -Format "HH:mm:ss.fff"
        Write-Host "[$ts] Pass $i/50... " -NoNewline

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $proc = Start-Process -FilePath $wxcExe -ArgumentList "`"$config`"" `
            -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
        $sw.Stop()

        if ($proc.ExitCode -eq 0) {
            Write-Host "OK ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Green
        } else {
            Write-Host "exit=$($proc.ExitCode) ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Red
        }

        Start-Sleep -Milliseconds 200
    }

    Write-Host "Completed 50 iterations." -ForegroundColor Green
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
} -ArgumentList $wxcExe, $config

Write-Host ""
Write-Host "=== Repro complete ===" -ForegroundColor Green
Write-Host "If the VM didn't freeze, try running again or increase iterations."
