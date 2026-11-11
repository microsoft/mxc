# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# WSLC host loopback functional test.
#
# MXC enables host.wslc.internal on every session. A bridged
# container reaches a service bound only to Windows 127.0.0.1 through it; an
# isolated container in such a session reaches it neither by name nor by the
# address the name resolves to. The listener answers with a per-run token, so
# the token in a container's output proves it reached this listener.
#
# Usage:
#   .\run_wslc_host_loopback_test.ps1 -WxcExecPath <path> [-Debug]

param(
    [switch]$Debug,
    [string]$WxcExecPath
)

$ErrorActionPreference = "Stop"
if (-not $WxcExecPath -or -not (Test-Path $WxcExecPath)) {
    Write-Host "ERROR: pass -WxcExecPath with an existing wxc-exec.exe" -ForegroundColor Red
    exit 1
}
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot "wslc_loopback_token_server.ps1")

function Invoke-HostLoopbackFixture {
    param([string]$Name, [hashtable]$Values)

    Write-Host "Running $Name..."
    $text = Get-Content (Join-Path $RepoRoot "tests\configs\$Name") -Raw
    foreach ($key in $Values.Keys) { $text = $text.Replace($key, $Values[$key]) }
    $configPath = Join-Path ([IO.Path]::GetTempPath()) "$([IO.Path]::GetFileNameWithoutExtension($Name))_$PID.json"
    Set-Content -Path $configPath -Value $text -NoNewline

    $wxcArgs = @()
    if ($Debug) { $wxcArgs += "--debug" }
    $wxcArgs += $configPath

    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $WxcExecPath @wxcArgs 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
        Remove-Item $configPath -ErrorAction SilentlyContinue
    }
    Write-Host $output
    @{ Output = $output; ExitCode = $exitCode }
}

$failed = $false
$server = Start-LoopbackTokenServer
try {
    $port = "$($server.Port)"
    $tokenPattern = [regex]::Escape($server.Token)
    Write-Host "Token listener on 127.0.0.1:$port answers with $($server.Token)"

    $bridged = Invoke-HostLoopbackFixture "wslc_network_host_loopback.json" @{ "__HOST_LOOPBACK_PORT__" = $port }
    $address = if ($bridged.Output -match 'HOST_LOOPBACK_ADDR=\[([0-9.]+)\]') { $Matches[1] }
    if ($bridged.ExitCode -ne 0) {
        Write-Host "FAIL: bridged wxc-exec returned non-zero exit $($bridged.ExitCode)" -ForegroundColor Red
        $failed = $true
    } elseif ($bridged.Output -notmatch [regex]::Escape("HOST_LOOPBACK_GOT=[$($server.Token)]")) {
        Write-Host "FAIL: bridged container did not reach the Windows 127.0.0.1:$port listener through host.wslc.internal" -ForegroundColor Red
        $failed = $true
    } elseif (-not $address) {
        Write-Host "FAIL: bridged container did not report the address host.wslc.internal resolves to" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host "PASS: bridged container reached a Windows loopback service through host.wslc.internal ($address)." -ForegroundColor Green
    }

    if ($address) {
        $isolated = Invoke-HostLoopbackFixture "wslc_network_host_loopback_isolated.json" @{
            "__HOST_LOOPBACK_PORT__" = $port
            "__HOST_LOOPBACK_ADDR__" = $address
        }
        if ($isolated.ExitCode -ne 0 -or $isolated.Output -notmatch "HOST_LOOPBACK_PROBE_DONE") {
            Write-Host "FAIL: isolated probe did not complete (exit $($isolated.ExitCode))" -ForegroundColor Red
            $failed = $true
        } elseif ($isolated.Output -match $tokenPattern) {
            Write-Host "FAIL: isolated container reached the Windows 127.0.0.1:$port listener" -ForegroundColor Red
            $failed = $true
        } else {
            Write-Host "PASS: isolated container reached Windows loopback neither by name nor by $address." -ForegroundColor Green
        }
    }
} finally {
    Stop-LoopbackTokenServer $server
}

if ($failed) { exit 1 }
exit 0
