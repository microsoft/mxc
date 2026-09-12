# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_process_plumbing_test.ps1
#
# Exit codes, stdio, cwd, timeouts, and orphan reaping.
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_process_plumbing_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = every assertion passed, 1 = at least one failed (or none
# ran), 78 = MXC-FATAL safety abort, which stops the whole suite.

[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$CargoRoot,
    [string]$WxcDebug,
    [string]$WxcRelease,
    [string]$UiProbeDebug,
    [string]$UiProbeRelease,
    [string]$ScratchRoot,
    [string]$ResultsJson,
    [string]$CargoLog,
    # Host capabilities probed once by the entry script and handed down, so
    # nineteen child processes do not each re-run --probe. Absent (a standalone
    # run) means probe the host here.
    [string]$CapsJson,
    # Not [ValidateSet]-decorated: the attribute binds to the variable, and
    # Initialize-WpcContext assigns through it. It validates the value instead.
    [string]$RequireTier,
    [string]$ExternalAnchorUrl,
    [string]$UnlistedDestinationUrl,
    [switch]$SkipNetwork,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts,
    # Set by the entry script, which owns the scratch tree and has already
    # populated it. A standalone run leaves this off and gets a freshly wiped
    # tree of its own.
    [switch]$ReuseScratch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 11 — process plumbing.
#
# Cheap properties that nothing asserted. Each is a silent-drop failure mode:
# a config field that never reaches the child looks identical to one that was
# honored, from outside.
# -----------------------------------------------------------------------
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
    # The survivor is identified by PROCESS NAME, via a copy of powershell.exe
    # renamed to a unique token. Matching on MainWindowTitle does not work —
    # the child is started by a sandboxed parent with no window and redirected
    # handles, so MainWindowTitle is always empty and the check can never find
    # a survivor (it would be tautologically green). Win32_Process.CommandLine
    # would work but is CIM-backed, and CIM is unavailable on locked-down
    # hosts. A renamed copy needs neither.
    $unique = "MXCLEAK$((Get-Random -Maximum 99999))"
    $survivorExe = Join-Path $rw "$unique.exe"
    Copy-Item -LiteralPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Destination $survivorExe -Force
    $timeoutCfg = New-Config -Name 'plumb-timeout' `
        -CommandLine (New-ProbeCommand -Body (
            "start /b `"`" `"$survivorExe`" -NoProfile -Command `"Start-Sleep -Seconds 120`" & ping -n 120 127.0.0.1")) `
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
    # 4s deadline; allow generous teardown headroom but still catch "ran to
    # completion" (the workload would take 120s).
    Record-Result -Phase 'P11' -Name 'process.timeout fires near the deadline (not after the workload finishes)' `
        -Pass ($timeoutRan -and ($sw.Elapsed.TotalSeconds -lt 45)) `
        -Detail ("ran={0}; elapsed={1:N1}s; timeout=4s; workload=120s" -f $timeoutRan, $sw.Elapsed.TotalSeconds)
    # Match the runner's own message, not the bare word: the config carries
    # `"timeout": 4000` and the request dump prints `Script timeout: 4000`,
    # which a loose /timed?\s*out/ would match without anything being killed.
    # Streams are cleaned individually; joining first would truncate at the
    # first echo boundary.
    $timeoutSignal = @(
        (Remove-ConfigEcho "$($rTimeout.Stdout)"),
        (Remove-ConfigEcho "$($rTimeout.Stderr)"),
        (Remove-ConfigEcho (Read-Log $timeoutLog))
    ) -join "`n"

    Record-Result -Phase 'P11' -Name 'timeout is reported, not silent' `
        -Pass ($timeoutRan -and ($timeoutSignal -match '(?i)(script )?timed out after \d+\s*ms')) `
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

