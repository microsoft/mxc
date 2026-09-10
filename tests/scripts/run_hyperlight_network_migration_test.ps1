# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Checks that the former Hyperlight hostname policies fail v0.9 migration.
.DESCRIPTION
    Uses --dry-run and expects exact parsing to reject network.allowedHosts.
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
    if ($config.version -ne '0.9.0-alpha' -or $config.containment -ne 'hyperlight' -or
        @($config.network.allowedHosts).Count -ne 1 -or $config.network.allowedHosts[0] -ne 'example.com') {
        throw "$name no longer contains the exact v0.9 hostname migration case"
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
        $process.WaitForExit()
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 1 -or
            -not $output.Contains('network.allowedHosts') -or
            -not $output.Contains('unknown field `allowedHosts`')) {
            throw "$name did not reject network.allowedHosts at exact parsing (exit $($process.ExitCode)): $output"
        }
        Write-Host "PASS: $name rejects network.allowedHosts before execution"
    } finally {
        $process.Dispose()
    }
}
