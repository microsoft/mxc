# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-NativeProcessContainer {
    param(
        [Parameter(Mandatory)][string]$WxcExec,
        [Parameter(Mandatory)][string]$ScratchRoot,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Arguments,
        [scriptblock]$Observe,
        [hashtable]$Environment = @{},
        [string]$WorkingDirectory
    )
    $logPath = Join-Path $ScratchRoot "$Name.log"
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $WxcExec
    foreach ($argument in (@('--log-file', $logPath) + $Arguments)) {
        $info.ArgumentList.Add($argument)
    }
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    foreach ($entry in $Environment.GetEnumerator()) { $info.Environment[$entry.Key] = $entry.Value }
    if ($WorkingDirectory) { $info.WorkingDirectory = $WorkingDirectory }
    $process = [System.Diagnostics.Process]::Start($info)
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($Observe) { & $Observe $process }
        $timedOut = -not $process.WaitForExit(45000)
        if ($timedOut) {
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) {
                throw "$Name timed out and executor PID $($process.Id) did not stop."
            }
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Set-Content -LiteralPath (Join-Path $ScratchRoot "$Name.stdout.txt") -Value $stdout
        Set-Content -LiteralPath (Join-Path $ScratchRoot "$Name.stderr.txt") -Value $stderr
        if ($timedOut) { throw "$Name timed out. See $ScratchRoot." }
        [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
            # The probe exits before the executor initializes its diagnostic file sink.
            Log = if ($Arguments -contains '--probe') { '' } else {
                Get-Content -LiteralPath $logPath -Raw
            }
        }
    } finally {
        if (-not $process.HasExited) {
            $process.Kill($true)
            $process.WaitForExit()
        }
        $process.Dispose()
    }
}
