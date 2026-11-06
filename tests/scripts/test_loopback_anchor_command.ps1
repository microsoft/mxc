# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\LoopbackAnchor.ps1')
$Passed = 0

function Test-LoopbackCommand {
    param([bool]$UseProxyEnvironment, [string[]]$AdditionalArguments)

    # Exercise real curl argument parsing without a network prerequisite.
    $command = Get-LoopbackAnchorCommand -Url '--version' -TimeoutSec 5 `
        -UseProxyEnvironment:$UseProxyEnvironment -AdditionalArguments $AdditionalArguments
    foreach ($wrapped in @($false, $true)) {
        $info = [Diagnostics.ProcessStartInfo]::new()
        if ($wrapped) {
            $info.FileName = $env:ComSpec
            $info.Arguments = "/c $command"
        } elseif ($command.StartsWith('"')) {
            $end = $command.IndexOf('"', 1)
            $info.FileName = $command.Substring(1, $end - 1)
            $info.Arguments = $command.Substring($end + 1).TrimStart()
        } else {
            $program, $arguments = $command -split ' ', 2
            $info.FileName = $program
            $info.Arguments = $arguments
        }
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        try {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(15000)) {
                throw 'Loopback command did not exit within 15 seconds.'
            }
            $drain = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdout, $stderr))
            if (-not $drain.Wait(5000)) { throw 'Loopback command output did not close.' }
            $body = $stdout.GetAwaiter().GetResult()
            $errorText = $stderr.GetAwaiter().GetResult()
            if ($process.ExitCode -ne 0 -or $body -notmatch '^curl \d') {
                throw "Loopback command failed (wrapped=$wrapped, proxy=$UseProxyEnvironment): exit=$($process.ExitCode); stdout=$body; stderr=$errorText"
            }
            Write-Host "PASS: loopback command (wrapped=$wrapped, proxy=$UseProxyEnvironment, extra=$($AdditionalArguments.Count))"
            $script:Passed++
        } finally {
            try {
                if (-not $process.HasExited) {
                    $process.Kill($true)
                    if (-not $process.WaitForExit(5000)) { throw 'Loopback command did not stop.' }
                }
            } finally {
                $process.Dispose()
            }
        }
    }
}

foreach ($useProxyEnvironment in @($false, $true)) {
    Test-LoopbackCommand -UseProxyEnvironment $useProxyEnvironment -AdditionalArguments @()
    Test-LoopbackCommand -UseProxyEnvironment $useProxyEnvironment `
        -AdditionalArguments @('--resolve', 'mxc-quote.invalid:80:127.0.0.1', '--ipv4')
}
if ($Passed -ne 8) { throw "Expected eight loopback command checks, got $Passed." }
