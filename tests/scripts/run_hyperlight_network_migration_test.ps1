# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Checks that the former Hyperlight hostname policies fail before execution.
.DESCRIPTION
    Uses --dry-run and expects the directional CIDR validator to reject hostnames.
    No Hyperlight guest, proxy, DNS lookup, or sandbox workload is started.
    The original hostname allowlist cannot be converted losslessly to CIDRs;
    these cases must not be "migrated" by granting unrestricted networking.
.PARAMETER WxcExecPath
    Path to the wxc-exec.exe binary under test.
.PARAMETER ConfigDir
    Directory containing the repository request fixtures.
#>
param(
    [Parameter(Mandatory)]
    [string]$WxcExecPath,
    [string]$ConfigDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'configs')
)

$ErrorActionPreference = 'Stop'
foreach ($name in @('hyperlight_networking.json', 'hyperlight_networking_blocked.json')) {
    $path = Join-Path $ConfigDir $name
    $config = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($config.version -ne '1.1.0-alpha' -or $config.containment -ne 'hyperlight' -or
        $null -eq $config.network.egress.allow -or @($config.network.egress.allow).Count -ne 1 -or
        $null -eq $config.network.egress.allow[0].to -or
        @($config.network.egress.allow[0].to).Count -ne 1 -or
        $config.network.egress.allow[0].to[0].cidr -ne 'example.com') {
        throw "$name no longer contains the exact v1.1 hostname migration case"
    }

    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $WxcExecPath
    foreach ($argument in @('--experimental', '--dry-run', $path)) {
        $info.ArgumentList.Add($argument)
    }
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    try {
        $process.StartInfo = $info
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "$name did not finish exact-parser validation within 30 seconds"
        }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 1 -or
            -not $output.Contains('network.egress.allow[0].to[0].cidr') -or
            -not $output.Contains('must be a valid network CIDR')) {
            throw "$name did not reject the hostname CIDR before execution (exit $($process.ExitCode)): $output"
        }
        Write-Host "PASS: $name rejects hostname CIDR before execution"
    } finally {
        $process.Dispose()
    }
}
