# repro_bfs_deadlock.ps1
# Reproduces the BFS deadlock by running wxc-exec with BFS config repeatedly.
# Run this INSIDE the VM (elevated) from the mxc directory.
#
# USAGE:
#   cd C:\Users\bbonaby\Downloads\mxc
#   .\test_scripts\repro_bfs_deadlock.ps1
#
# Before running:
#   1. (HOST) Set up kernel debug: .\test_scripts\setup_kernel_debug.ps1
#   2. (HOST) Reboot VM: Restart-VM -Name 'ge_current_winpd' -Force
#   3. (HOST) Attach WinDbg: WinDbgX.exe -k net:port=50000,key=1.2.3.4
#   4. (HOST) Press 'g' in WinDbg to let VM boot
#   5. (VM)   Run this script
#   6. (HOST) When VM freezes, Ctrl+Break in WinDbg then:
#              !locks
#              !process 0 7 svchost.exe
#              (look for bfs!BfsPreCreateOperation in stacks)

param(
    [int]$Iterations = 50,
    [string]$WxcExe = "cli\node_modules\@microsoft\mxc-sdk\bin\x86_64-pc-windows-msvc\wxc-exec.exe",
    [string]$Config = "test_configs\filesystem_bfs_spaces_test.json"
)

$ErrorActionPreference = "Continue"

# Resolve paths relative to repo root
$repoRoot = Split-Path $PSScriptRoot -Parent
$wxcPath = Join-Path $repoRoot $WxcExe
$configPath = Join-Path $repoRoot $Config

if (-not (Test-Path $wxcPath)) {
    Write-Error "wxc-exec.exe not found at: $wxcPath"
    exit 1
}
if (-not (Test-Path $configPath)) {
    Write-Error "Config not found at: $configPath"
    exit 1
}

# Ensure test directory exists
$testDir = "C:\Users\Public\wxc bfs test"
if (-not (Test-Path $testDir)) {
    New-Item -Path $testDir -ItemType Directory -Force | Out-Null
}

Write-Host "=== BFS Deadlock Repro ===" -ForegroundColor Cyan
Write-Host "Exe:    $wxcPath"
Write-Host "Config: $configPath"
Write-Host "Iterations: $Iterations"
Write-Host ""
Write-Host "Starting in 3 seconds... (Ctrl+C to abort)" -ForegroundColor Yellow
Start-Sleep 3

for ($i = 1; $i -le $Iterations; $i++) {
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    Write-Host "[$timestamp] Pass $i/$Iterations... " -NoNewline -ForegroundColor White

    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $proc = Start-Process -FilePath $wxcPath -ArgumentList "`"$configPath`"" `
            -Wait -PassThru -NoNewWindow -RedirectStandardOutput "NUL" -RedirectStandardError "NUL" `
            -ErrorAction Stop
        $sw.Stop()

        if ($proc.ExitCode -eq 0) {
            Write-Host "OK ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Green
        } else {
            Write-Host "FAIL exit=$($proc.ExitCode) ($($sw.ElapsedMilliseconds)ms)" -ForegroundColor Red
        }
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
    }

    # Small delay between runs
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "Completed $Iterations iterations without deadlock." -ForegroundColor Green

# Cleanup
if (Test-Path $testDir) {
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
}
