# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')

$scratch = Join-Path ([IO.Path]::GetTempPath()) ("mxc-capture-regression-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$scratch = (Resolve-Path -LiteralPath $scratch).Path
$probe = Join-Path $scratch 'capture-probe.exe'
$pidPath = Join-Path $scratch 'child.pid'
try {
    $compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
        throw "The Windows .NET Framework compiler is required: $compiler"
    }
    & $compiler /nologo /target:exe "/out:$probe" (Join-Path $PSScriptRoot 'lib\native_process_capture_probe.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile the output-capture fixture.' }

    $result = Invoke-NativeProcessContainer -WxcExec $probe -ScratchRoot $scratch `
        -Name 'normal' -Arguments @('capture')
    if ($result.ExitCode -ne 7 -or $result.Stdout -cne 'captured stdout' -or
        $result.Stderr -cne 'captured stderr' -or $result.Log -cne 'capture probe log') {
        throw 'Normal capture did not preserve stdout, stderr, log, and exit code.'
    }
    Write-Host 'PASS: normal native process capture'

    $failure = $null
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-NativeProcessContainer -WxcExec $probe -ScratchRoot $scratch `
            -Name 'inherited-output' -Arguments @('inherited-output', $pidPath) | Out-Null
    } catch [TimeoutException] {
        $failure = $_
    } finally {
        $elapsed.Stop()
    }
    if ($null -eq $failure -or $failure.Exception.Message -notlike '*redirected output did not close*') {
        throw 'An exited executor with inherited output handles must report a stream-drain timeout.'
    }
    if ($elapsed.Elapsed -ge [TimeSpan]::FromSeconds(10)) {
        throw "Stream-drain failure took $($elapsed.Elapsed), exceeding the 10-second regression bound."
    }
    $childPid = [int](Get-Content -LiteralPath $pidPath -Raw)
    $child = Get-Process -Id $childPid -ErrorAction Stop
    try {
        if ($child.ProcessName -ne 'capture-probe') { throw 'The output-holding fixture child was not alive.' }
    } finally {
        $child.Dispose()
    }
    Write-Host "PASS: inherited output fails promptly ($($elapsed.Elapsed.TotalSeconds.ToString('F2')) seconds)"
} finally {
    if (Test-Path -LiteralPath $pidPath) {
        $childPid = [int](Get-Content -LiteralPath $pidPath -Raw)
        $child = Get-Process -Id $childPid -ErrorAction SilentlyContinue
        if ($child) {
            try {
                if ($child.ProcessName -ne 'capture-probe') { throw 'Refusing to stop a reused fixture PID.' }
                Stop-Process -Id $childPid -Force
                if (-not $child.WaitForExit(5000)) { throw 'The fixture child did not stop.' }
            } finally {
                $child.Dispose()
            }
        }
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
