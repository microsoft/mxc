# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BinDir,
    [string]$PackagedPowerShell
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')
$wxc = Join-Path (Resolve-Path -LiteralPath $BinDir).Path 'wxc-exec.exe'
$scratch = Join-Path $env:TEMP ('mxc-launch-diagnostics-' + [guid]::NewGuid().ToString('N'))
$appDirectory = Join-Path $scratch 'WindowsApps'
$work = Join-Path $scratch 'work'
New-Item -ItemType Directory -Path $appDirectory, $work | Out-Null
Write-Host "Native launch diagnostic artifacts: $scratch"

# Exercise the path heuristic on every PSEC host, without requiring Store provisioning.
$inboxPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0'
foreach ($file in @('powershell.exe', 'powershell.exe.config')) {
    Copy-Item -LiteralPath (Join-Path $inboxPowerShell $file) -Destination $appDirectory
}
$shells = @(@{ Name = 'windowsapps-path'; Path = (Join-Path $appDirectory 'powershell.exe') })
if ($PackagedPowerShell) {
    $packaged = (Resolve-Path -LiteralPath $PackagedPowerShell).Path
    if ($packaged -notmatch '(?i)[\\/]WindowsApps[\\/]') {
        throw 'The additional packaged PowerShell must use its real WindowsApps executable path.'
    }
    $shells += @{ Name = 'packaged-powershell'; Path = $packaged }
}

$probe = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
    -Name 'host-probe' -Arguments @('--probe')
if ($probe.ExitCode -ne 0 -or -not ($probe.Stdout | ConvertFrom-Json).probes.baseContainerApiPresent) {
    throw "Launch diagnostic validation requires native PSEC: $($probe.Stderr)"
}

$passed = 0
foreach ($shell in $shells) {
    foreach ($exitCode in @(0, 7)) {
        $name = "$($shell.Name)-exit-$exitCode"
        $marker = Join-Path $work "$name.executed"
        $code = "[IO.File]::WriteAllText('$($marker.Replace("'", "''"))','EXECUTED');" +
            "[Console]::Out.WriteLine('EXIT_DIAGNOSTIC_STDOUT');" +
            "[Console]::Error.WriteLine('EXIT_DIAGNOSTIC_STDERR');exit $exitCode"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        $request = @{
            version = '1.0.0'
            containment = 'processcontainer'
            process = @{
                commandLine = "`"$($shell.Path)`" -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
                cwd = $work
                timeout = 30000
                env = @("SYSTEMROOT=$env:SystemRoot", "LOCALAPPDATA=$work", "TEMP=$work", "TMP=$work", "USERPROFILE=$work")
            }
            filesystem = @{
                readwritePaths = @($work)
                readonlyPaths = @($env:SystemRoot, (Split-Path -Parent $shell.Path))
            }
            ui = @{ disable = $false }
        }
        $config = Join-Path $scratch "$name.json"
        $request | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $config
        $result = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
            -Name $name -Arguments @($config)
        $hostMarker = if (Test-Path -LiteralPath $marker) { [IO.File]::ReadAllText($marker) } else { $null }
        if ($result.ExitCode -ne $exitCode -or $hostMarker -cne 'EXECUTED' -or
            $result.Stdout.Trim() -cne 'EXIT_DIAGNOSTIC_STDOUT' -or
            $result.Log -notmatch '"tier":"base-container"') {
            throw "$name did not complete in native PSEC: exit=$($result.ExitCode); marker=$hostMarker; stdout=$($result.Stdout); stderr=$($result.Stderr)"
        }
        if ($result.Stderr.Trim() -cne 'EXIT_DIAGNOSTIC_STDERR') {
            throw "$name completed with the expected exit and host file, but MXC added non-workload stderr: $($result.Stderr)"
        }
        $passed++
        Write-Host "PASSED: $name preserved exit, output and host file without a false launch diagnostic"
    }
}
Write-Host "PASSED: all $passed native launch diagnostic cases"
