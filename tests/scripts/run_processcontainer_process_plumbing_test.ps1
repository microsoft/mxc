# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Exit codes, stdio, cwd, timeouts, and orphan reaping.
#
# Runs standalone, or under run_processcontainer_all_tests.ps1.

[CmdletBinding()]
param(
    [string]$ContextJson,

    [string]$ResultsJson,
    [string]$RequireTier,
    [switch]$SkipNetwork,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

Initialize-WpcContext @PSBoundParameters


# Phase 11 — process plumbing.
#
# Cheap properties that nothing asserted. Each is a silent-drop failure mode:
# a config field that never reaches the child looks identical to one that was
# honored, from outside.
function Phase-ProcessPlumbing {
    Section 'Phase 11: process plumbing (env / cwd / exit code / timeout / teardown)'

    $rw = Join-Path $ScratchRoot 'rw'
    $ro = Join-Path $ScratchRoot 'ro'

    # --- env delivery. process.env replaces the environment outright, so the
    # block must stay viable; values with spaces and an embedded `=` catch the
    # two classic parse bugs.
    $envCfg = New-Config -Name 'plumb-env' `
        -CommandLine "$env:SystemRoot\System32\cmd.exe /c echo FOO=[%MXC_TEST_FOO%] EQ=[%MXC_TEST_EQ%]" `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) `
        -Env (Get-MinimalEnv -Extra @('MXC_TEST_FOO=a b c', 'MXC_TEST_EQ=k=v')) -TimeoutMs 20000
    $envLog = Join-Path $ScratchRoot 'logs\plumb-env.log'
    $rEnv = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $envCfg -LogPath $envLog -TimeoutSec 40
    Record-Result -Phase 'P11' -Name 'process.env value with spaces reaches the child intact' `
        -Pass ([bool]($rEnv.Stdout -match '\[a b c\]')) -Detail "exit=$($rEnv.ExitCode); stdout=$(Format-Snippet $rEnv.Stdout)"
    Record-Result -Phase 'P11' -Name 'process.env value with an embedded = reaches the child intact' `
        -Pass ([bool]($rEnv.Stdout -match '\[k=v\]')) -Detail "exit=$($rEnv.ExitCode); stdout=$(Format-Snippet $rEnv.Stdout)"

    # --- cwd. Explicit process.cwd must be honored.
    $cwdCfg = New-Config -Name 'plumb-cwd' `
        -CommandLine (New-ProbeCommand -Body 'cd') `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -Cwd $rw -TimeoutMs 20000
    $cwdLog = Join-Path $ScratchRoot 'logs\plumb-cwd.log'
    $rCwd = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cwdCfg -LogPath $cwdLog -TimeoutSec 40
    $cwdRan = Test-WorkloadRan $rCwd
    Record-Result -Phase 'P11' -Name 'explicit process.cwd is honored' `
        -Pass ($cwdRan -and ($rCwd.Stdout -match [regex]::Escape((Split-Path -Leaf $rw)))) `
        -Detail "ran=$cwdRan; requested=$rw; stdout=$(Format-Snippet $rCwd.Stdout)"

    # --- omitted cwd. docs/schema.md (revised this month) documents the
    # substitution precedence: first readwritePaths entry that is an existing
    # directory, else the first such readonlyPaths entry, else the system
    # drive root. Never the launcher's cwd.
    $cwdDefaultCfg = New-Config -Name 'plumb-cwd-default' `
        -CommandLine (New-ProbeCommand -Body 'cd') `
        -ReadWrite @($rw) -ReadOnly @($ro, $env:SystemRoot) -TimeoutMs 20000
    $cwdDefaultLog = Join-Path $ScratchRoot 'logs\plumb-cwd-default.log'
    $rCwdDefault = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cwdDefaultCfg -LogPath $cwdDefaultLog -TimeoutSec 40
    $cwdDefaultRan = Test-WorkloadRan $rCwdDefault
    Record-Result -Phase 'P11' -Name 'omitted process.cwd falls back to the first readwritePaths entry' `
        -Pass ($cwdDefaultRan -and ($rCwdDefault.Stdout -match [regex]::Escape((Split-Path -Leaf $rw)))) `
        -Detail "ran=$cwdDefaultRan; expected leaf=$(Split-Path -Leaf $rw); stdout=$(Format-Snippet $rCwdDefault.Stdout)"
    # The guard here cannot be "stdout is non-empty": wxc-exec prints a JSON
    # error envelope to stdout when the launch fails, so a run in which nothing
    # executed still has non-whitespace stdout that trivially fails to contain
    # the launcher's path, scoring this green for the wrong reason.
    Record-Result -Phase 'P11' -Name 'omitted process.cwd does NOT inherit the launcher cwd' `
        -Pass ($cwdDefaultRan -and -not ($rCwdDefault.Stdout -match [regex]::Escape($PWD.Path))) `
        -Detail "ran=$cwdDefaultRan; launcher cwd=$($PWD.Path); stdout=$(Format-Snippet $rCwdDefault.Stdout)"

    # --- exit-code propagation. Nothing asserted this; `Invoke-Wxc` even
    # carried an unused $ExpectExitCode parameter.
    foreach ($code in @(0, 1, 42)) {
        $ecCfg = New-Config -Name "plumb-exit-$code" `
            -CommandLine "$env:SystemRoot\System32\cmd.exe /c exit $code" `
            -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -TimeoutMs 20000
        $ecLog = Join-Path $ScratchRoot "logs\plumb-exit-$code.log"
        $rEc = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $ecCfg -LogPath $ecLog -TimeoutSec 40
        Record-Result -Phase 'P11' -Name "child exit code $code propagates to wxc-exec" `
            -Pass ($rEc.ExitCode -eq $code) -Detail "got=$($rEc.ExitCode)"
    }

    # --- timeout enforcement plus the survivor check. The workload
    # backgrounds a uniquely-named sleep that far outlasts the deadline: if it
    # is still running afterwards, teardown left a survivor.
    #
    # Identified by PROCESS NAME, via a copy of powershell.exe renamed to a
    # unique token. MainWindowTitle is always empty for a sandboxed child, so
    # that check would be tautologically green; Win32_Process.CommandLine is
    # CIM-backed and unavailable on locked-down hosts.
    # The blocker must outlast the deadline using nothing but cmd.exe: `ping -n`
    # dies instantly inside the container ("Unable to contact IP driver"), which
    # made this whole block pass on a child that never blocked at all.
    $unique = "MXCLEAK$((Get-Random -Maximum 99999))"
    $survivorExe = Join-Path $rw "$unique.exe"
    Copy-Item -LiteralPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Destination $survivorExe -Force
    $spin = 'for /l %i in (1,1,2000000000) do @ver > nul'
    $timeoutCfg = New-Config -Name 'plumb-timeout' `
        -CommandLine (New-ProbeCommand -Body (
            "start /b `"`" `"$survivorExe`" -NoProfile -Command `"Start-Sleep -Seconds 120`" & $spin")) `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -TimeoutMs 4000
    $timeoutLog = Join-Path $ScratchRoot 'logs\plumb-timeout.log'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rTimeout = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $timeoutCfg -LogPath $timeoutLog -TimeoutSec 60
    $sw.Stop()
    $timeoutRan = Test-WorkloadRan $rTimeout

    # Every assertion below is AND-ed with $timeoutRan: a sandbox that never
    # launched also exits non-zero, finishes fast, and leaves no survivor, so
    # without the guard this whole block scores green on a broken host.
    Record-Result -Phase 'P11' -Name 'process.timeout kills a runaway child' `
        -Pass ($timeoutRan -and ($rTimeout.ExitCode -ne 0)) `
        -Detail "ran=$timeoutRan; exit=$($rTimeout.ExitCode)"
    # Bounded on BOTH sides. Without the lower bound a child that dies on its own
    # scores green here, which is exactly what the ping-based workload used to do.
    Record-Result -Phase 'P11' -Name 'process.timeout fires near the deadline (not before, not after the workload finishes)' `
        -Pass ($timeoutRan -and ($sw.Elapsed.TotalSeconds -ge 3) -and ($sw.Elapsed.TotalSeconds -lt 45)) `
        -Detail ("ran={0}; elapsed={1:N1}s; timeout=4s; workload=120s" -f $timeoutRan, $sw.Elapsed.TotalSeconds)
    # Match the runner's own message, not the bare word: the config carries
    # `"timeout": 4000` and the request dump prints `Script timeout: 4000`,
    # which a loose /timed?\s*out/ would match without anything being killed.
    # Both spellings count -- the ScriptRunner bridge says "script timed out
    # after Nms", the engine's streaming completion says "sandbox execution
    # timed out". Streams are cleaned individually; joining first would
    # truncate at the first echo boundary.
    $timeoutSignal = @(
        (Remove-ConfigEcho "$($rTimeout.Stdout)"),
        (Remove-ConfigEcho "$($rTimeout.Stderr)"),
        (Remove-ConfigEcho (Read-Log $timeoutLog))
    ) -join "`n"

    Record-Result -Phase 'P11' -Name 'timeout is reported, not silent' `
        -Pass ($timeoutRan -and ($timeoutSignal -match '(?i)(script timed out after \d+\s*ms|sandbox execution timed out)')) `
        -Detail "ran=$timeoutRan; exit=$($rTimeout.ExitCode); tail=$(Format-Snippet $timeoutSignal)"

    Start-Sleep -Seconds 2
    $survivors = @(Get-Process -Name $unique -ErrorAction SilentlyContinue)
    Record-Result -Phase 'P11' -Name 'no descendant survives teardown after a timeout' `
        -Pass ($timeoutRan -and ($survivors.Count -eq 0)) `
        -Detail "ran=$timeoutRan; survivors=$($survivors.Count); marker=$unique"
    foreach ($s in $survivors) { try { Stop-Process -Id $s.Id -Force -ErrorAction SilentlyContinue } catch {} }
    Remove-Item -LiteralPath $survivorExe -Force -ErrorAction SilentlyContinue
}

Invoke-WpcPhase -Key 'ProcessPlumbing' -Body { Phase-ProcessPlumbing }
Complete-WpcChild

