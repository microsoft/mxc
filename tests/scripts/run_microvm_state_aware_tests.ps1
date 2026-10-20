# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

param(
    [string]$WxcExePath,
    [switch]$PrintProvisionPayload
)

$ErrorActionPreference = "Stop"
$ProvisionPayload = @{
    version = "1.1.0-alpha"
    containment = "microvm"
    microvm = @{ image = "mcr.microsoft.com/azurelinux/base/core:3.0" }
}
if ($PrintProvisionPayload) {
    $ProvisionPayload | ConvertTo-Json -Compress -Depth 12
    return
}
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $WxcExePath) {
    $WxcExePath = Join-Path $RepoRoot "src\target\x86_64-pc-windows-msvc\debug\wxc-exec.exe"
}
if (-not (Test-Path $WxcExePath -PathType Leaf)) {
    throw "wxc-exec.exe not found at $WxcExePath"
}
function Invoke-MicroVmPhase {
    param(
        [string]$Phase,
        [hashtable]$Payload,
        [string]$SandboxId
    )

    $json = $Payload | ConvertTo-Json -Compress -Depth 12
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $arguments = @("--operation", $Phase, "--experimental", "--config-base64", $base64)
    if ($SandboxId) {
        $arguments = @(
            "--operation", $Phase,
            "--container-id", $SandboxId,
            "--experimental",
            "--config-base64", $base64
        )
    }
    $stdout = $null
    $stderr = $null
    $process = $null
    try {
        $stdout = [IO.Path]::GetTempFileName()
        $stderr = [IO.Path]::GetTempFileName()
        # Native stderr becomes a terminating error under Windows PowerShell 5.1.
        # Redirect at the process boundary so phase handling retains both streams.
        $process = Start-Process -FilePath $WxcExePath -ArgumentList $arguments `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        @{
            ExitCode = $process.ExitCode
            Stdout = [IO.File]::ReadAllText($stdout)
            Stderr = [IO.File]::ReadAllText($stderr)
        }
    } finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
        if ($null -ne $stdout) {
            Remove-Item $stdout -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $stderr) {
            Remove-Item $stderr -Force -ErrorAction SilentlyContinue
        }
    }
}

$provision = Invoke-MicroVmPhase -Phase "provision" -Payload $ProvisionPayload
if ($provision.ExitCode -ne 0) {
    throw "provision failed: exit=$($provision.ExitCode) stdout=$($provision.Stdout) stderr=$($provision.Stderr)"
}
$sandboxId = ($provision.Stdout | ConvertFrom-Json).result.sandboxId
if ($sandboxId -notlike "microvm:*") {
    throw "unexpected sandbox ID: $sandboxId"
}

try {
    $start = Invoke-MicroVmPhase -Phase "start" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
    }
    if ($start.ExitCode -ne 0) {
        throw "start failed: exit=$($start.ExitCode) stdout=$($start.Stdout) stderr=$($start.Stderr)"
    }

    $exec = Invoke-MicroVmPhase -Phase "exec" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
        process = @{ commandLine = "printf EXECUTOR_NVX_OK" }
    }
    if ($exec.ExitCode -ne 0 -or $exec.Stdout -notmatch "EXECUTOR_NVX_OK") {
        throw "exec failed: exit=$($exec.ExitCode) stdout=$($exec.Stdout) stderr=$($exec.Stderr)"
    }

    $stop = Invoke-MicroVmPhase -Phase "stop" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
    }
    if ($stop.ExitCode -ne 0) {
        throw "stop failed: exit=$($stop.ExitCode) stdout=$($stop.Stdout) stderr=$($stop.Stderr)"
    }
} finally {
    $deprovision = Invoke-MicroVmPhase -Phase "deprovision" -SandboxId $sandboxId -Payload @{
        version = "1.1.0-alpha"
    }
    if ($deprovision.ExitCode -ne 0) {
        throw "deprovision failed: exit=$($deprovision.ExitCode) stdout=$($deprovision.Stdout) stderr=$($deprovision.Stderr)"
    }
}

Write-Host "MicroVM state-aware executor E2E passed: $sandboxId" -ForegroundColor Green
