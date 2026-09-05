# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs IsolationSession E2E tests. Requires a Windows host with the
    in-proc IsolationSession service available.

.DESCRIPTION
    - Locates wxc-exec.exe (built with --features isolation_session)
    - Runs each automated test config via wxc-exec, validates exit codes
      and stdout content
    - Reports pass/fail summary

    This script must run INTERACTIVELY on the test host. The OS-side service
    calling-process identity check rejects network-logon tokens, so
    PSSession-driven invocations fail with Access Denied. Copy wxc-exec.exe,
    the test configs, and this script to the host, then run it directly in
    cmd.exe or PowerShell on that host.

    Assumes the system drive is C:. The scratch directories this script
    creates and the paths hardcoded in the test configs must name the same
    location, so the two sides have to change together — making only this
    script `$env:SystemDrive`-aware would point it at a directory the configs
    never reference.

    Automated configs (asserted by this script):
      - isolation_session_hello.json --env vars + working dir + agent name
      - isolation_session_exit42.json --exit code propagation
      - isolation_session_stderr.json --separate stderr in non-ConPTY mode
      - isolation_session_stdout_stderr_interleaved.json --interleaved streams
      - isolation_session_timeout.json --OS-side timeout terminates with exit code 1

    Manual smoke configs (NOT asserted --observe the output yourself):
      - isolation_session_streaming_smoke.json --output appears with delays
        rather than a burst at exit; verifies Commit 1 streaming.
        Run from cmd.exe directly (not redirected) so wxc-exec sees a TTY:
            wxc-exec.exe --experimental isolation_session_streaming_smoke.json
      - isolation_session_powershell_interactive.json --launches
        powershell.exe in the isolation session; type commands at the prompt
        (e.g. `Get-Date`, `whoami`, `exit 7`) and verify input forwarding +
        ConPTY rendering + exit-code propagation. Requires a real cmd.exe
        console (interactive on the VM desktop):
            wxc-exec.exe --experimental isolation_session_powershell_interactive.json

.PARAMETER WxcExePath
    Path to wxc-exec.exe. Default probes target-specific then default
    release dirs relative to the repo root.

.PARAMETER ConfigDir
    Path to the tests/configs directory. Defaults to ..\configs.

.EXAMPLE
    .\run_isolation_session_tests.ps1
    .\run_isolation_session_tests.ps1 -WxcExePath C:\test\wxc-exec.exe -ConfigDir C:\test
#>

param(
    [string]$WxcExePath,
    [string]$ConfigDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $ConfigDir) {
    $ConfigDir = Join-Path $RepoRoot "tests\configs"
}

# Locate wxc-exec.exe --explicit path > host-arch target dir > other-arch
# target dir > default release dir. Detect the host arch so we look for the
# matching build first, but also probe the other Windows target so a
# cross-built binary is still discoverable.
$HostTarget = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    'aarch64-pc-windows-msvc'
} else {
    'x86_64-pc-windows-msvc'
}
$OtherTarget = if ($HostTarget -eq 'aarch64-pc-windows-msvc') {
    'x86_64-pc-windows-msvc'
} else {
    'aarch64-pc-windows-msvc'
}

if ($WxcExePath) {
    $WxcExec = $WxcExePath
} else {
    # Probe release first so a release build is preferred when both flavors exist.
    $CandidatePaths = @(
        (Join-Path $RepoRoot "src\target\$HostTarget\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$OtherTarget\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\release\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$HostTarget\debug\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$OtherTarget\debug\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\debug\wxc-exec.exe")
    )
    $WxcExec = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found." -ForegroundColor Red
    Write-Host "Searched:" -ForegroundColor Yellow
    foreach ($p in $CandidatePaths) { Write-Host "  - $p" -ForegroundColor Yellow }
    Write-Host "Build with: cargo build --release --features isolation_session --target $HostTarget" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExecPath explicitly." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nIsolationSession E2E Tests" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host "Binary: $WxcExec" -ForegroundColor Gray
Write-Host "Configs: $ConfigDir`n" -ForegroundColor Gray

# ---------------- Backend-availability probe ----------------
#
# Availability is decided by a single call to `wxc-exec --probe`, which reports
# `probes.isolationSessionAvailable`.
#
# This deliberately replaces the earlier checks for a specific DLL and a
# hard-coded WinRT activatable-class registry key. Those named a runtime class
# directly, so they silently stopped tracking what the code actually activates
# when the backend moved to the Preview API — leaving a gate that could pass or
# skip for reasons unrelated to whether the suite can run. Probing the binary
# under test cannot drift, because it asks that binary what it can do.
#
# `--probe` is read-only: it cannot provision anything and cannot leak.
#
# Returns one of three statuses, because collapsing them loses the distinction
# that matters:
#
#   available   -> run the suite
#   unavailable -> the probe answered, and the answer is "no": a clean skip
#   error       -> the probe did not answer at all. That is an infrastructure
#                  failure, NOT a statement about the backend, so it must not
#                  be reported as a skip.
#
# stdout and stderr are captured SEPARATELY. Merging them would let any stderr
# line corrupt the JSON, and stderr is not hypothetical here: wxc-exec runs a
# best-effort DACL-recovery pass BEFORE the `--probe` arm and reports it on
# stderr (`core/wxc/src/main.rs`), so a host carrying leftover state from a
# crashed prior run would emit unparseable output and be judged "unavailable"
# while being perfectly capable. That failure mode is inverted with respect to
# risk — the dirtier the host, the likelier the false skip — which is exactly
# the kind of silent green this gate exists to prevent.
function Get-IsolationSessionProbe {
    param([string]$Exe)

    $errFile = [System.IO.Path]::GetTempFileName()
    $prevPref = $ErrorActionPreference
    try {
        # This script runs under `$ErrorActionPreference = "Stop"`, which turns
        # a native command's stderr output into a terminating error. The probe
        # is expected to write to stderr on a host carrying leftover state, so
        # relax it for the duration of the call — the same idiom used around
        # the wxc-exec invocation in Run-IsolationSessionTest below.
        $ErrorActionPreference = "Continue"
        $stdout = (& $Exe --probe 2>$errFile) | Out-String
        $exitCode = $LASTEXITCODE
        $stderr = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
    } catch {
        return @{ Status = 'error'; Detail = "could not run '$Exe --probe': $($_.Exception.Message)" }
    } finally {
        $ErrorActionPreference = $prevPref
        Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
    }

    $stderrNote = if ([string]::IsNullOrWhiteSpace($stderr)) { '' } else { " stderr: $($stderr.Trim())" }

    if ($exitCode -ne 0) {
        return @{ Status = 'error'; Detail = "wxc-exec --probe exited $exitCode.$stderrNote" }
    }
    $parsed = $null
    try { $parsed = $stdout | ConvertFrom-Json } catch {
        return @{ Status = 'error'; Detail = "wxc-exec --probe did not emit valid JSON.$stderrNote" }
    }
    if ($null -eq $parsed -or $null -eq $parsed.probes) {
        return @{ Status = 'error'; Detail = "wxc-exec --probe output has no 'probes' object.$stderrNote" }
    }
    if ($parsed.probes.PSObject.Properties.Name -notcontains 'isolationSessionAvailable') {
        return @{ Status = 'error'; Detail = "wxc-exec --probe output has no 'probes.isolationSessionAvailable' field.$stderrNote" }
    }
    # Only a literal boolean is meaningful. Treating anything else as `false`
    # would recreate the conflation this function exists to remove: a value of
    # `null`, a string, or a number is a malformed answer, not a statement that
    # the backend is unavailable, and it gets the same infrastructure-failure
    # treatment as a missing field.
    $value = $parsed.probes.isolationSessionAvailable
    if ($value -is [bool]) {
        if ($value) { return @{ Status = 'available' } }
        return @{ Status = 'unavailable' }
    }
    return @{ Status = 'error'; Detail = "wxc-exec --probe reported a non-boolean 'probes.isolationSessionAvailable' ($(if ($null -eq $value) { 'null' } else { "'$value'" })).$stderrNote" }
}

$probeResult = Get-IsolationSessionProbe -Exe $WxcExec
if ($probeResult.Status -eq 'unavailable') {
    Write-Host "SKIPPED: wxc-exec --probe reports isolationSessionAvailable=false" -ForegroundColor Yellow
    exit 0
}
if ($probeResult.Status -ne 'available') {
    Write-Host "FAILED: could not determine whether the isolation session backend is available." -ForegroundColor Red
    Write-Host "  $($probeResult.Detail)" -ForegroundColor Red
    Write-Host "  This is an infrastructure failure, not an unsupported host, so it is not a skip." -ForegroundColor Red
    exit 1
}

# Helper: run one IsolationSession test config.
#
# The wxc-exec invocation is wrapped in try-catch so an unexpected
# PowerShell error (e.g., a parameter-binding mistake) fails THIS test
# only -- the suite keeps going. The output checks use String.Contains()
# rather than -match/-notmatch to avoid the array-return edge case those
# operators have when the LHS is unexpectedly null or array-typed.
function Run-IsolationSessionTest {
    param(
        [string]$ConfigFile,
        [int]$ExpectedExit = 0,
        [string[]]$OutputContains = @(),
        [string[]]$OutputLineNotEqual = @()
    )

    $configPath = Join-Path $ConfigDir $ConfigFile
    if (-not (Test-Path $configPath)) {
        Write-Host "  $ConfigFile ... " -NoNewline
        Write-Host "SKIP (file not found)" -ForegroundColor Yellow
        return @{ Name = $ConfigFile; Pass = $true; Skipped = $true; Reason = "File not found" }
    }

    Write-Host "  $ConfigFile ... " -NoNewline

    $output = ""
    $exitCode = -1
    try {
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        # --debug flips wxc-exec's Logger into Mode::Console so its output
        # (including "Isolation Session: agent user = <name>") goes to
        # stdout. Without --debug, one-shot keeps Logger in Mode::Buffer
        # and never flushes the buffer, so the agent name is lost and
        # leaks cannot be correlated to a specific test.
        $output = & $WxcExec --debug --experimental $configPath 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
    } catch {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host "    Reason: invocation threw: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Name = $ConfigFile; Pass = $false; Skipped = $false; Reason = "invocation threw: $($_.Exception.Message)" }
    }

    $output = if ($null -eq $output) { "" } else { [string]$output }

    $pass = $true
    $reason = ""

    if ($exitCode -ne $ExpectedExit) {
        $pass = $false
        $reason = "Expected exit $ExpectedExit, got $exitCode"
    }

    if ($pass -and $OutputContains) {
        foreach ($needle in $OutputContains) {
            if (-not $output.Contains($needle)) {
                $pass = $false
                $reason = "Output missing '$needle'"
                break
            }
        }
    }

    if ($pass -and $OutputLineNotEqual) {
        $lines = $output -split "`r?`n" | ForEach-Object { $_.Trim() }
        foreach ($needle in $OutputLineNotEqual) {
            $needleLower = $needle.ToLower()
            $hit = $lines | Where-Object { $_.ToLower() -eq $needleLower } | Select-Object -First 1
            if ($hit) {
                $pass = $false
                $reason = "Output has line equal to '$needle'"
                break
            }
        }
    }

    if ($pass) {
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host "    Reason: $reason" -ForegroundColor Red
        $meaningful = $output -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -Last 5
        foreach ($line in $meaningful) {
            Write-Host "    > $($line.TrimEnd())" -ForegroundColor Gray
        }
    }

    # Log the OS-assigned agent user name from wxc-exec's stderr (relayed
    # via 2>&1 into $output). The runner prints "Isolation Session: agent
    # user = <name>" once per provision. Correlates leftover local users
    # back to specific tests during post-run inspection.
    $agentMatch = [regex]::Match($output, 'Isolation Session: agent user = (\S+)')
    if ($agentMatch.Success) {
        Write-Host "    agent: $($agentMatch.Groups[1].Value)" -ForegroundColor DarkGray
    }

    return @{ Name = $ConfigFile; Pass = $pass; Skipped = $false; Reason = $reason }
}

[System.Collections.ArrayList]$results = @()

Write-Host "--- Tests ---" -ForegroundColor Cyan
# Setup for isolation_session_hello.json: cwd must exist before agent start.
# Removed first — the same idiom the concurrent dirs below use — because a run
# that dies before the scratch cleanup leaves this behind, and a stale directory
# must not outlive the run that created it.
Remove-Item -Recurse -Force 'C:\mxc_workdir_test' -ErrorAction SilentlyContinue
New-Item -Path 'C:\mxc_workdir_test' -ItemType Directory -Force | Out-Null
$HostWhoami = (& whoami).Trim()
$null = $results.Add((Run-IsolationSessionTest "isolation_session_hello.json" `
    -OutputContains @("MYVAR=IsolationSessionTest", "CWD=C:\mxc_workdir_test") `
    -OutputLineNotEqual @($HostWhoami)))
# Exact one-shot contracts are recursively closed, so backend configuration
# that the IsolationSession one-shot surface does not define is rejected.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_configid_rejected.json" `
    -ExpectedExit 1 `
    -OutputContains @("unknown field ``isolation_session``")))
$null = $results.Add((Run-IsolationSessionTest "isolation_session_exit42.json" `
    -ExpectedExit 42))
# stderr separation: agent writes MARKER_STDOUT to stdout and MARKER_STDERR to stderr.
# Both reach this script's captured output via wxc-exec's `2>&1` merge above; the assertion
# proves stderr is being relayed (not dropped) on the non-ConPTY plain-pipes path.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_stderr.json" `
    -OutputContains @("MARKER_STDOUT", "MARKER_STDERR")))
# Interleaved streams: agent writes alternating stdout/stderr lines. All five markers
# must appear in the captured output (proves streams aren't crossed or dropped mid-run).
$null = $results.Add((Run-IsolationSessionTest "isolation_session_stdout_stderr_interleaved.json" `
    -OutputContains @("OUT_A", "ERR_A", "OUT_B", "ERR_B", "OUT_C")))
# Timeout: ping runs ~30s; OS-side per-process timer set to 1500ms forces
# the agent to exit with code 1.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_timeout.json" `
    -ExpectedExit 1))

# A nested unknown backend payload is rejected at the same closed exact
# contract boundary, before the command can run.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_stray_config_rejected.json" `
    -ExpectedExit 1 `
    -OutputContains @("unknown field ``isolation_session``")))

# One-shot network rejection: the isolation session container's network is
# unrestricted and cannot be filtered or denied, so a non-canonical network
# policy (here defaultPolicy=block) is refused at provision. Only the canonical
# acknowledgment (defaultPolicy=allow + allowLocalNetwork=true) is accepted.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_network_rejected.json" `
    -ExpectedExit -1 `
    -OutputContains @("network is unrestricted")))

# Inbound axis: `allow` outbound without `allowLocalNetwork` is still refused --
# a process inside CAN listen on a localhost-reachable port, so the caller must
# acknowledge inbound too. Both axes must be the unrestricted form.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_network_rejected_no_local.json" `
    -ExpectedExit -1 `
    -OutputContains @("network is unrestricted")))

# Host rules: even with the canonical allow + allowLocalNetwork base, any
# allowedHosts/blockedHosts entry is refused -- the backend cannot filter hosts.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_network_rejected_hosts.json" `
    -ExpectedExit -1 `
    -OutputContains @("network is unrestricted")))

# One-shot UI rejection: the isolation session is a separate OS session, which
# isolates the host's UI from the contained code but does not deny it UI
# capabilities -- window creation, GDI and the session's own clipboard all work
# inside it. A `ui` policy therefore cannot be honored and is refused rather
# than accepted and dropped. Presence drives the refusal (UiPolicy's default is
# full lockdown, so an explicit lockdown `ui` is indistinguishable by value).
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_ui_rejected.json" `
    -ExpectedExit -1 `
    -OutputContains @("UI policy is not supported")))

# One-shot lifecycle rejection: the in-proc API exposes no session-lifetime
# knob, so one-shot always stops the session and removes the agent user before
# returning. `destroyOnExit: true` (the default) matches that and is accepted;
# `false` asks for something the backend cannot deliver.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_lifecycle_rejected.json" `
    -ExpectedExit -1 `
    -OutputContains @("lifecycle.destroyOnExit=false")))

# ---------------- Concurrent one-shot test ----------------
#
# Three wxc-exec processes (A, B, C) run a per-agent PowerShell script
# from a shared host directory that grants Authenticated Users write access.
# Each script writes timestamped lines to its own X.log file: "X-started",
# "X-still-alive-1" .. "X-still-alive-N", "X-done", with one second
# between iterations. After all three wxc-execs exit, the test reads each
# agent's log file and asserts (a) the wxc-exec exited 0, (b) the log
# contains start / final-still-alive / done markers, (c) timestamps are
# monotonic. If any isolation session is torn down mid-run its log is
# truncated, and if cleanup fails its wxc-exec exit code is non-zero. A
# fresh fourth process (D) then proves subsequent sandboxes still work.
#
# Each launch is gated on the previously-launched agent's "X-started"
# line appearing in its log file. Polling the log file (not wxc-exec's
# stdout) avoids matching the --debug Logger's command-line echo. The
# barrier prevents the OS-side per-StartSessionAsync setup race where
# two StartSessionAsync calls landing within ~1-2s of each other leave
# the second isolation session unusable.

Write-Host ""
Write-Host "--- Concurrent one-shot ---" -ForegroundColor Cyan

# Shared host directory the three agent PS1 scripts and X.log files live in.
# The backend does not accept filesystem policy, so grant write access at
# the host ACL layer to Authenticated Users (S-1-5-11). Agent users are local
# accounts and are members of that group.
$concurrentLogDir = 'C:\mxc_concurrent_log'
Remove-Item -Recurse -Force $concurrentLogDir -ErrorAction SilentlyContinue
New-Item -Path $concurrentLogDir -ItemType Directory -Force | Out-Null
$aclOutput = & icacls $concurrentLogDir /grant '*S-1-5-11:(OI)(CI)M' 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to grant Authenticated Users write access to ${concurrentLogDir}: $aclOutput"
}

# wxc-exec stdout/stderr capture dir. Cleared at the start of every run, and
# removed again at the end of a green one; a failing run leaves it for inspection.
$concurrentTempRoot = Join-Path $env:TEMP 'mxc_concurrent_oneshot'
Remove-Item -Recurse -Force $concurrentTempRoot -ErrorAction SilentlyContinue
New-Item -Path $concurrentTempRoot -ItemType Directory -Force | Out-Null
$stdoutA = Join-Path $concurrentTempRoot 'A.stdout.txt'
$stderrA = Join-Path $concurrentTempRoot 'A.stderr.txt'
$stdoutB = Join-Path $concurrentTempRoot 'B.stdout.txt'
$stderrB = Join-Path $concurrentTempRoot 'B.stderr.txt'
$stdoutC = Join-Path $concurrentTempRoot 'C.stdout.txt'
$stderrC = Join-Path $concurrentTempRoot 'C.stderr.txt'

# Generate one PS1 script per agent. Each writes timestamped lines to
# its own X.log file. Backtick-escaped expressions (`$(Get-Date), `$_)
# survive this here-string verbatim so they're evaluated by the inner
# PowerShell when the agent runs the script.
function Write-AgentScript {
    param([string]$Label, [int]$IterCount)
    $logPath = Join-Path $concurrentLogDir "$Label.log"
    $body = @"
Add-Content -Path '$logPath' -Value "`$(Get-Date -Format 'HH:mm:ss.fff') $Label-started"
1..$IterCount | ForEach-Object {
    Add-Content -Path '$logPath' -Value "`$(Get-Date -Format 'HH:mm:ss.fff') $Label-still-alive-`$_"
    Start-Sleep -Seconds 1
}
Add-Content -Path '$logPath' -Value "`$(Get-Date -Format 'HH:mm:ss.fff') $Label-done"
"@
    Set-Content -Path (Join-Path $concurrentLogDir "$Label.ps1") -Value $body -Encoding UTF8
}

Write-AgentScript -Label 'A' -IterCount 15
Write-AgentScript -Label 'B' -IterCount 5
Write-AgentScript -Label 'C' -IterCount 30

# Launch helper: route wxc-exec through `cmd /c` with cmd-managed shell
# redirects (`1>` / `2>`). PowerShell's Start-Process -RedirectStandardOutput
# combined with -NoNewWindow has known issues under concurrent launches.
# -WindowStyle Hidden gives each cmd.exe its own (invisible) console
# session. --debug routes wxc-exec's Logger to stdout so the per-process
# "agent user = <name>" line lands in the capture file (otherwise the
# Logger buffer is silently dropped on one-shot exit).
function Start-ConcurrentWxc {
    param([string]$Exec, [string]$ConfigPath, [string]$StdoutFile, [string]$StderrFile)
    $cmdLine = "/c $Exec --debug --experimental $ConfigPath 1>$StdoutFile 2>$StderrFile"
    Start-Process -FilePath cmd.exe -ArgumentList $cmdLine -WindowStyle Hidden -PassThru
}

# Block until "X-started" appears in $LogPath (the agent's own log file,
# not the wxc-exec stdout capture). Reading with FileShare.ReadWrite lets
# us peek while the agent's PowerShell holds the file open for Add-Content.
function Wait-AgentLogStart {
    param([string]$Label, [string]$LogPath, [int]$TimeoutSeconds = 30)
    $pattern = [regex]::new("\b$Label-started\b")
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $TimeoutSeconds) {
        if (Test-Path $LogPath) {
            try {
                $fs = [System.IO.File]::Open($LogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $sr = New-Object System.IO.StreamReader($fs)
                $text = $sr.ReadToEnd()
                $sr.Close(); $fs.Close()
                if ($pattern.IsMatch($text)) {
                    $elapsed = ((Get-Date) - $start).TotalMilliseconds
                    Write-Host "  $Label-started in log after $([int]$elapsed) ms" -ForegroundColor DarkGray
                    return $true
                }
            } catch { }
        }
        Start-Sleep -Milliseconds 100
    }
    Write-Host "  WARN: $Label-started did not appear in log within ${TimeoutSeconds}s -- launching next anyway" -ForegroundColor Yellow
    return $false
}

$pA = $null; $pB = $null; $pC = $null

# Scratch directories this script creates that must not outlive the run.
# Removal of each is attempted quietly, since an already-absent directory is the
# normal case, then asserted — a directory held by a scanner or blocked by an
# ACL would otherwise survive a green run, which is the state this cleanup
# exists to prevent. Declared here so the cleanup in the finally below and the
# post-summary cleanup both record into it.
$scratchLeft = @()

try {
    Write-Host "  starting A (15 still-alive iters), B (5), C (30) with log-file barriers..." -ForegroundColor Gray
    $pA = Start-ConcurrentWxc -Exec $WxcExec `
        -ConfigPath (Join-Path $ConfigDir 'isolation_session_concurrent_A.json') `
        -StdoutFile $stdoutA -StderrFile $stderrA
    [void](Wait-AgentLogStart -Label 'A' -LogPath (Join-Path $concurrentLogDir 'A.log'))
    $pB = Start-ConcurrentWxc -Exec $WxcExec `
        -ConfigPath (Join-Path $ConfigDir 'isolation_session_concurrent_B.json') `
        -StdoutFile $stdoutB -StderrFile $stderrB
    [void](Wait-AgentLogStart -Label 'B' -LogPath (Join-Path $concurrentLogDir 'B.log'))
    $pC = Start-ConcurrentWxc -Exec $WxcExec `
        -ConfigPath (Join-Path $ConfigDir 'isolation_session_concurrent_C.json') `
        -StdoutFile $stdoutC -StderrFile $stderrC
    [void](Wait-AgentLogStart -Label 'C' -LogPath (Join-Path $concurrentLogDir 'C.log'))

    # Wait for all three to exit. Generous per-process timeout because
    # OS-side teardown can take tens of seconds.
    Write-Host "  waiting for all three wxc-execs to exit..." -ForegroundColor Gray
    $aFinished = $pA.WaitForExit(120000)
    $bFinished = $pB.WaitForExit(120000)
    $cFinished = $pC.WaitForExit(120000)
    Write-Host "  A finished=$aFinished exit=$($pA.ExitCode)" -ForegroundColor Gray
    Write-Host "  B finished=$bFinished exit=$($pB.ExitCode)" -ForegroundColor Gray
    Write-Host "  C finished=$cFinished exit=$($pC.ExitCode)" -ForegroundColor Gray

    # Agent-user-name extraction (from wxc-exec --debug stdout) for leak
    # attribution if any deprovision silently fails downstream.
    foreach ($pair in @(
            @{ Label = 'A'; Stdout = $stdoutA; Stderr = $stderrA },
            @{ Label = 'B'; Stdout = $stdoutB; Stderr = $stderrB },
            @{ Label = 'C'; Stdout = $stdoutC; Stderr = $stderrC }
        )) {
        $combined = ''
        if (Test-Path $pair.Stdout) { $combined += [string](Get-Content $pair.Stdout -Raw) }
        if (Test-Path $pair.Stderr) { $combined += [string](Get-Content $pair.Stderr -Raw) }
        $m = [regex]::Match($combined, 'Isolation Session: agent user = (\S+)')
        $agentName = if ($m.Success) { $m.Groups[1].Value } else { '<not found>' }
        Write-Host "  $($pair.Label) agent: $agentName" -ForegroundColor DarkGray
    }

    # Per-agent assertions from log file. Each X.log line is prefixed
    # with HH:mm:ss.fff so we can also check monotonicity.
    $tsPattern = [regex]::new('^(\d\d):(\d\d):(\d\d)\.(\d\d\d)\s')
    foreach ($spec in @(
            @{ Label = 'A'; Process = $pA; Iters = 15 },
            @{ Label = 'B'; Process = $pB; Iters = 5 },
            @{ Label = 'C'; Process = $pC; Iters = 30 }
        )) {
        $label = $spec.Label
        $proc = $spec.Process
        $iters = $spec.Iters
        $logPath = Join-Path $concurrentLogDir "$label.log"
        $log = if (Test-Path $logPath) { [string](Get-Content $logPath -Raw) } else { '' }
        if ($null -eq $log) { $log = '' }

        $reasons = New-Object System.Collections.ArrayList
        if ($proc.ExitCode -ne 0) { [void]$reasons.Add("wxc-exec exit=$($proc.ExitCode)") }
        if (-not ($log -match "\b$label-started\b")) { [void]$reasons.Add("$label-started missing") }
        if (-not ($log -match "\b$label-still-alive-$iters\b")) { [void]$reasons.Add("$label-still-alive-$iters missing (truncated?)") }
        if (-not ($log -match "\b$label-done\b")) { [void]$reasons.Add("$label-done missing") }

        # Monotonicity check: every line is "HH:mm:ss.fff <message>";
        # successive timestamps must not regress. Cheap defense against
        # pathological scheduling weirdness inside the isolation session.
        $prevTicks = [int64]-1
        $lineNum = 0
        foreach ($line in ($log -split "`r?`n")) {
            $lineNum++
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $m = $tsPattern.Match($line)
            if (-not $m.Success) { continue }
            $ticks = ([int]$m.Groups[1].Value * 3600000) +
                     ([int]$m.Groups[2].Value * 60000) +
                     ([int]$m.Groups[3].Value * 1000) +
                     ([int]$m.Groups[4].Value)
            if ($prevTicks -ge 0 -and $ticks -lt $prevTicks) {
                [void]$reasons.Add("timestamp regression at line $lineNum")
                break
            }
            $prevTicks = $ticks
        }

        $pass = ($reasons.Count -eq 0)
        $reasonStr = ($reasons -join '; ')
        Write-Host "  concurrent: $label ran full sequence ... $(if ($pass) { 'PASS' } else { 'FAIL: ' + $reasonStr })" `
            -ForegroundColor $(if ($pass) { 'Green' } else { 'Red' })
        $null = $results.Add(@{ Name = "concurrent: $label ran full sequence"; Pass = $pass; Skipped = $false; Reason = $reasonStr })
    }

    # Fresh D after A/B/C: verifies the leak does not poison subsequent
    # sandboxes. D uses the original ping-based simple form (no shared log
    # dir), exercising the unmodified one-shot path.
    $null = $results.Add((Run-IsolationSessionTest "isolation_session_concurrent_D.json" `
        -OutputContains @("D-start", "D-done")))
} finally {
    foreach ($p in @($pA, $pB, $pC)) {
        if ($null -ne $p -and -not $p.HasExited) {
            try { $p.Kill() } catch { }
        }
    }
    # Clean up the shared agent log dir. The wxc-exec stdout/stderr capture
    # dir is handled after the summary, where the pass/fail outcome is known.
    Remove-Item -Recurse -Force $concurrentLogDir -ErrorAction SilentlyContinue
    if (Test-Path $concurrentLogDir) { $scratchLeft += $concurrentLogDir }
}


# Summary -- wrap each filtered pipeline in @(...) to force array context.
# Without @(), a Where-Object that returns a single hashtable is unwrapped
# to the bare hashtable; calling .Count on a single hashtable returns its
# KEY count (4 for the {Name,Pass,Skipped,Reason} shape), not 1, making
# the failure tally wildly wrong when exactly one test fails.
$passed = @($results | Where-Object { $_.Pass -and -not $_.Skipped }).Count
$failed = @($results | Where-Object { -not $_.Pass -and -not $_.Skipped }).Count
$skipped = @($results | Where-Object { $_.Skipped }).Count
$total = $results.Count
$executed = $passed + $failed

# Scratch cleanup. Neither directory below is a product artifact, so neither
# should outlive the run.
#
# `C:\mxc_workdir_test` only ever serves as the agent process's working
# directory, so it is always empty and always safe to remove.
#
# The concurrent capture dir holds each agent's wxc-exec stdout/stderr, which is
# worth keeping when something failed and is litter when nothing did — and it
# sits under the invoking user's %TEMP%, where it would accumulate unnoticed.
#
# Leftovers are counted separately from the test tally so the summary keeps
# reporting test outcomes rather than housekeeping.
Remove-Item -Recurse -Force 'C:\mxc_workdir_test' -ErrorAction SilentlyContinue
if (Test-Path 'C:\mxc_workdir_test') { $scratchLeft += 'C:\mxc_workdir_test' }
if ($failed -eq 0) {
    Remove-Item -Recurse -Force $concurrentTempRoot -ErrorAction SilentlyContinue
    if (Test-Path $concurrentTempRoot) { $scratchLeft += $concurrentTempRoot }
} else {
    Write-Host "  (concurrent stdout/stderr preserved at: $concurrentTempRoot)" -ForegroundColor DarkGray
}
foreach ($leftover in $scratchLeft) {
    Write-Host "FAILED: could not remove scratch directory $leftover" -ForegroundColor Red
}

Write-Host "`n==========================" -ForegroundColor Cyan
# A suite that collected tests but executed none of them is not a pass:
# without this, an aggregator reading only the exit code cannot tell
# "everything passed" from "nothing ran".
#
# This deliberately cannot fire on an unsupported host. That case exits at the
# availability probe near the top of the script, long before the summary, and
# remains a clean skip — graceful degradation on an OS that cannot run these
# tests is not a failure. Reaching this line means the backend *was* available,
# so a zero execution count is anomalous rather than environmental.
if ($executed -eq 0) {
    Write-Host "FAILED: backend was available but no tests executed ($total collected, $skipped skipped)" -ForegroundColor Red
    Write-Host "  A zero-execution run cannot substantiate anything; treating it as a failure." -ForegroundColor Red
    exit 1
}
if ($failed -eq 0) {
    Write-Host "$passed/$total passed$(if ($skipped -gt 0) { ", $skipped skipped" })" -ForegroundColor Green
} else {
    Write-Host "$passed/$executed passed, $failed FAILED$(if ($skipped -gt 0) { " ($skipped skipped)" }):" -ForegroundColor Red
    $results | Where-Object { -not $_.Pass -and -not $_.Skipped } | ForEach-Object {
        Write-Host "  FAIL: $($_.Name) - $($_.Reason)" -ForegroundColor Red
    }
}

exit $(if ($failed -gt 0 -or $scratchLeft.Count -gt 0) { 1 } else { 0 })
