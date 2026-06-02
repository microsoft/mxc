# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# CliOverride-SimulateSandbox.ps1
#
# Windows Sandbox isn't enabled on this dev box, but we know exactly what
# its guest executor does to script_code:
#
#   src/wxc_windows_sandbox_guest/src/executor.rs:163-168
#       let mut cmd = Command::new("cmd.exe");
#       cmd.arg("/C");
#       cmd.raw_arg(script_code);
#
# So we simulate the inside-the-sandbox behavior by running cmd.exe /C
# locally with the same script_code the policy / CLI path would have set.
# This confirms (a) the policy form actually produces the expected effect,
# and (b) where wxc-exec accepts the CLI form, what that form actually
# does in cmd.exe.

[CmdletBinding()]
param([int]$TimeoutMs = 10000)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-CmdSim {
    param([string]$CmdLine)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = "/C $CmdLine"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($TimeoutMs)) {
        try { $p.Kill() } catch {}
        return [pscustomobject]@{ ExitCode = -1; Out = '<timeout>' }
    }
    $combined = (($p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()) -replace "`r?`n", ' / ').Trim()
    if ($combined.Length -gt 90) { $combined = $combined.Substring(0, 87) + '...' }
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Out = $combined }
}

# These mirror rows 1-5 from CliOverride-Divergence.ps1. JsonForm is the
# string the policy puts into commandLine. CliCurrent is what the current
# renderer at HEAD emits for the equivalent argv (already observed via the
# divergence script). Where CliCurrent is '<rejected>' wxc-exec errored
# at parse time and never reached cmd.exe.
$cases = @(
    @{ N=1; Desc='MSBuild %SOLUTION_PATH% expansion';
       JsonForm='msbuild %SOLUTION_PATH%\foo.sln /p:Configuration=Release';
       CliCurrent='<rejected>' },
    @{ N=2; Desc='URL with ! in credential';
       JsonForm='git clone https://user:p!ss@github.com/org/repo.git';
       CliCurrent='<rejected>' },
    @{ N=3; Desc='pwsh -Command with embedded quotes';
       JsonForm='pwsh.exe -Command "Write-Host ''hello, world''"';
       CliCurrent='<rejected>' },
    @{ N=4; Desc='Pipe to filter';
       JsonForm='dir /b | findstr .json';
       CliCurrent='dir /b "|" findstr .json' },
    @{ N=5; Desc='Chained commands';
       JsonForm='echo one && echo two';
       CliCurrent='echo one "&&" echo two' }
)

$rows = foreach ($c in $cases) {
    $modeA = Invoke-CmdSim -CmdLine $c.JsonForm
    $modeB = if ($c.CliCurrent -eq '<rejected>') {
        [pscustomobject]@{ ExitCode = $null; Out = '<wxc-exec rejected; never reached cmd.exe>' }
    } else {
        Invoke-CmdSim -CmdLine $c.CliCurrent
    }

    [pscustomobject]@{
        '#'                = $c.N
        Example            = $c.Desc
        'A (policy form)'  = if ($null -ne $modeA.ExitCode) { ('exit={0} :: {1}' -f $modeA.ExitCode, $modeA.Out) } else { $modeA.Out }
        'B (CLI current)'  = if ($null -ne $modeB.ExitCode) { ('exit={0} :: {1}' -f $modeB.ExitCode, $modeB.Out) } else { $modeB.Out }
    }
}

Write-Host ''
Write-Host 'cmd.exe /C simulation of windows_sandbox guest executor' -ForegroundColor Cyan
Write-Host ('=' * 90) -ForegroundColor Cyan
foreach ($r in $rows) {
    Write-Host ''
    Write-Host ("[{0}] {1}" -f $r.'#', $r.Example) -ForegroundColor Yellow
    Write-Host ("    A (policy form):  {0}" -f $r.'A (policy form)')
    Write-Host ("    B (CLI current):  {0}" -f $r.'B (CLI current)')
}
Write-Host ''
