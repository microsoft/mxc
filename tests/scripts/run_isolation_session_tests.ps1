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
      - isolation_session_timeout.json --timeout enforcement
      - isolation_session_stdin_line.json --pipe/file line delivery with console stdout
      - isolation_session_streaming_smoke.json --output arrives incrementally
        rather than as a burst at exit
      - isolation_session_post_exit_output.json --stdout/stderr keep arriving
        after the workload exits

    Manual smoke configs (NOT asserted --observe the output yourself):
      - isolation_session_powershell_interactive.json --launches
        powershell.exe in the isolation session; type commands at the prompt
        (e.g. `Get-Date`, `whoami`, `exit 7`) and verify input forwarding +
        ConPTY rendering + exit-code propagation. Requires a real cmd.exe
        console (interactive on the VM desktop):
            wxc-exec.exe isolation_session_powershell_interactive.json

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

# Host-side loopback anchor used by the positive network oracle.
. (Join-Path $PSScriptRoot 'lib\LoopbackAnchor.ps1')

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
# line corrupt the JSON. A native-command diagnostic on stderr must not turn
# a valid probe response into an "unavailable" result or hide an infrastructure
# failure behind a skip.
function Get-IsolationSessionProbe {
    param([string]$Exe)

    $errFile = [System.IO.Path]::GetTempFileName()
    $prevPref = $ErrorActionPreference
    try {
        # This script runs under `$ErrorActionPreference = "Stop"`, which turns
        # a native command's stderr output into a terminating error. The probe
        # may write diagnostics to stderr, so
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

# Peek at a file a child process still holds open for writing. FileShare.ReadWrite
# is required: the default share mode fails against a live writer. Returns ''
# when the file is absent or not yet readable.
function Read-LiveFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return '' }
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $sr = New-Object System.IO.StreamReader($fs)
            [string]$sr.ReadToEnd()
        } finally { $fs.Close() }
    } catch { '' }
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
        [string[]]$OutputLineNotEqual = @(),
        [string]$ExpectedErrorCode,
        [string]$ExpectedErrorMessageContains,
        [hashtable]$Request,
        [switch]$DryRun
    )

    if ($null -ne $Request) {
        $json = $Request | ConvertTo-Json -Compress -Depth 12
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
        $configArgs = @('--config-base64', $encoded)
    } else {
        $configPath = Join-Path $ConfigDir $ConfigFile
        if (-not (Test-Path $configPath)) {
            Write-Host "  $ConfigFile ... " -NoNewline
            Write-Host "SKIP (file not found)" -ForegroundColor Yellow
            return @{ Name = $ConfigFile; Pass = $true; Skipped = $true; Reason = "File not found" }
        }
        $configArgs = @($configPath)
    }
    if ($DryRun) { $configArgs += '--dry-run' }

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
        $output = & $WxcExec --debug @configArgs 2>&1 | Out-String
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

    if ($pass -and $ExpectedErrorCode) {
        $envelope = $null
        foreach ($line in ($output -split "`r?`n")) {
            if (-not $line.Trim().StartsWith('{"error"')) { continue }
            try { $envelope = $line | ConvertFrom-Json } catch { $envelope = $null }
        }
        if ($null -eq $envelope) {
            $pass = $false
            $reason = "No error envelope in output"
        } elseif ($envelope.error.code -ne $ExpectedErrorCode) {
            $pass = $false
            $reason = "Expected error code '$ExpectedErrorCode', got '$($envelope.error.code)'"
        } elseif ($ExpectedErrorMessageContains -and
                  -not ([string]$envelope.error.message).Contains($ExpectedErrorMessageContains)) {
            $pass = $false
            $reason = "Error message missing '$ExpectedErrorMessageContains': $($envelope.error.message)"
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

function Run-StdinRoutingTest {
    param([ValidateSet('pipe', 'file')][string]$InputKind)

    $name = "$InputKind stdin with console stdout"
    $root = Join-Path $env:TEMP ("mxc_stdin_routing_" + [guid]::NewGuid().ToString('N'))
    $process = $null
    $pass = $false
    $reason = ''
    Write-Host "  $name ... " -NoNewline
    try {
        New-Item -Path $root -ItemType Directory | Out-Null
        $inputPath = Join-Path $root 'input.txt'
        $requestPath = Join-Path $ConfigDir 'isolation_session_stdin_line.json'
        $batchPath = Join-Path $root 'run.cmd'
        $stderrPath = Join-Path $root 'stderr.txt'
        Set-Content -LiteralPath $inputPath -Value 'MXC_STDIN_ROUTING' -Encoding Ascii

        # cmd supplies either a real pipe or a file handle. Do not redirect stdout:
        # that would bypass the console-output routing regression.
        $invocation = '"{0}" "{1}" 2>"{2}"' -f $WxcExec, $requestPath, $stderrPath
        $command = if ($InputKind -eq 'pipe') {
            'type "{0}" | {1}' -f $inputPath, $invocation
        } else {
            '{0} <"{1}"' -f $invocation, $inputPath
        }
        Set-Content -LiteralPath $batchPath -Encoding Ascii -Value @(
            '@echo off'
            $command
            'exit /b %errorlevel%'
        )
        # Start-Process gives cmd its own console even when CI captures the suite's stdout.
        $process = Start-Process -FilePath $env:ComSpec -ArgumentList "/d /c `"$batchPath`"" `
            -WindowStyle Hidden -PassThru
        if (-not $process.WaitForExit(120000)) {
            throw 'Executor did not finish within 120 seconds.'
        }
        # exit code established in isolation_session_stdin_line.json commandLine.
        if ($process.ExitCode -ne 42) {
            $stderr = if (Test-Path -LiteralPath $stderrPath) {
                Get-Content -LiteralPath $stderrPath -Raw
            } else { 'Executor stderr was not created; console launcher may have failed.' }
            throw "Expected exit 42 after reading the input line, got $($process.ExitCode). $stderr"
        }
        $pass = $true
    } catch {
        $reason = $_.Exception.Message
    } finally {
        try {
            if ($null -ne $process -and -not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(10000)) {
                    throw "Could not stop stdin routing launcher $($process.Id)."
                }
            }
            if ($pass) {
                Remove-Item -LiteralPath $root -Recurse -Force
            }
        } catch {
            $pass = $false
            $reason = "$reason Cleanup failed: $($_.Exception.Message)"
        } finally {
            if ($null -ne $process) {
                $process.Dispose()
            }
        }
    }
    if ($pass) {
        Write-Host 'PASS' -ForegroundColor Green
    } else {
        Write-Host 'FAIL' -ForegroundColor Red
        Write-Host "    Reason: $reason" -ForegroundColor Red
        Write-Host "    Diagnostics: $root" -ForegroundColor Gray
    }
    return @{ Name = $name; Pass = $pass; Skipped = $false; Reason = $reason }
}

[System.Collections.ArrayList]$results = @()

Write-Host "--- Tests ---" -ForegroundColor Cyan
# Setup for isolation_session_hello.json: cwd must exist before agent start.
# Removed first — the same idiom the concurrent dir below uses — because a run
# that dies before the scratch cleanup leaves this behind, and a stale directory
# must not outlive the run that created it.
Remove-Item -Recurse -Force 'C:\mxc_workdir_test' -ErrorAction SilentlyContinue
New-Item -Path 'C:\mxc_workdir_test' -ItemType Directory -Force | Out-Null
$HostWhoami = (& whoami).Trim()
$null = $results.Add((Run-IsolationSessionTest "isolation_session_hello.json" `
    -OutputContains @("MYVAR=IsolationSessionTest", "CWD=C:\mxc_workdir_test") `
    -OutputLineNotEqual @($HostWhoami)))
# The exact one-shot contract has no IsolationSession-specific configuration
# object, so the unsupported object is rejected at its root.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_configid_rejected.json" `
    -ExpectedExit 1 `
    -OutputContains @("at ``isolationSession``", "unknown field ``isolationSession``")))
$null = $results.Add((Run-IsolationSessionTest "isolation_session_exit42.json" `
    -ExpectedExit 42))
$null = $results.Add((Run-StdinRoutingTest -InputKind pipe))
$null = $results.Add((Run-StdinRoutingTest -InputKind file))
# stderr separation: agent writes MARKER_STDOUT to stdout and MARKER_STDERR to stderr.
# Both reach this script's captured output via wxc-exec's `2>&1` merge above; the assertion
# proves stderr is being relayed (not dropped) on the non-ConPTY plain-pipes path.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_stderr.json" `
    -OutputContains @("MARKER_STDOUT", "MARKER_STDERR")))
# Interleaved streams: agent writes alternating stdout/stderr lines. All five markers
# must appear in the captured output (proves streams aren't crossed or dropped mid-run).
$null = $results.Add((Run-IsolationSessionTest "isolation_session_stdout_stderr_interleaved.json" `
    -OutputContains @("OUT_A", "ERR_A", "OUT_B", "ERR_B", "OUT_C")))
# Timeout: ping runs ~30s against a 1500ms deadline. The service timer is armed
# with a grace margin, so the local wait ends the run and reports the timeout.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_timeout.json" `
    -ExpectedExit -1 `
    -ExpectedErrorCode "backend_error" `
    -ExpectedErrorMessageContains "script timed out after 1500ms"))

# Any IsolationSession-specific object is rejected at the same closed exact
# contract boundary, before the command can run.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_stray_config_rejected.json" `
    -ExpectedExit 1 `
    -OutputContains @("at ``isolationSession``", "unknown field ``isolationSession``")))

# IsolationSession requires the exact all-allow directional network posture.
# A directional deny policy is therefore rejected during request validation.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_network_rejected.json" `
    -ExpectedExit 1 `
    -OutputContains @("IsolationSession requires an explicit network policy")))

# Inbound axis: allowing egress does not make an ingress/host-loopback deny
# enforceable. A process inside can listen on a localhost-reachable port.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_network_rejected_no_local.json" `
    -ExpectedExit 1 `
    -OutputContains @("IsolationSession requires an explicit network policy")))

# Per-destination rules remain unsupported.
# The fixture uses a documentation CIDR, not a DNS-derived hostname mapping.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_network_rejected_hosts.json" `
    -ExpectedExit 1 `
    -OutputContains @("IsolationSession requires an explicit network policy")))

# Every legacy Network member is rejected by exact v0.9 parsing, including
# semantically neutral values. These requests must never launch their command.
$legacyNetworkFields = [ordered]@{
    defaultPolicy = 'allow'
    enforcementMode = 'capabilities'
    allowedHosts = @()
    blockedHosts = @()
    allowLocalNetwork = $true
    proxy = @{ url = 'http://127.0.0.1:8888' }
}
foreach ($field in $legacyNetworkFields.Keys) {
    $request = @{
        version = '1.0.0'
        containment = 'isolation_session'
        process = @{ commandLine = 'echo LEGACY_NETWORK_MUST_NOT_RUN' }
        network = @{ $field = $legacyNetworkFields[$field] }
    }
    $null = $results.Add((Run-IsolationSessionTest "legacy network.$field rejected" `
        -Request $request -DryRun -ExpectedExit 1 `
        -OutputContains @("network.$field", "unknown field ``$field``")))
}

$legacyNetworkRequest = @{
    version = '1.0.0'
    containment = 'isolation_session'
    process = @{ commandLine = 'echo LEGACY_NETWORK_MUST_NOT_RUN' }
    network = [ordered]@{ defaultPolicy = 'allow'; allowLocalNetwork = $true }
}
$null = $results.Add((Run-IsolationSessionTest "legacy network posture rejected" `
    -Request $legacyNetworkRequest -DryRun -ExpectedExit 1 `
    -OutputContains @("network.defaultPolicy", "unknown field ``defaultPolicy``")))

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

$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_env_rejected.json" `
    -ExpectedExit -1 `
    -OutputContains @("process.env without process.inheritDefaultEnv=true is not supported")))

# ---------------- Concurrent one-shot test ----------------
#
# Overlapping one-shot sessions must each run to completion: one session's
# start-up or teardown must not cut a sibling short.
#
# Each workload (isolation_session_concurrent_A/B/C.json) prints "X-started",
# waits in `set /p` for a line on stdin, and echoes it as "X-released-<line>".
# A, B and C start one at a time, each after the previous one has printed
# "X-started", so every start-up happens while the earlier sessions are
# running. The harness then releases B, A and C in turn, waiting for each
# wxc-exec to exit before the next release. wxc-exec returns only after its
# session's stop and account removal have completed, so A runs through B's
# whole teardown, and C through B's and A's.
#
# A session passes when it printed "X-started", outlived every session released
# before it, echoed its own release token "PROCEED-X" exactly, and its wxc-exec
# exited 0, so a token delivered to the wrong session fails that session. The
# exit code reports the workload, not the teardown: an account left behind
# fails the account check around the isolation-session suites in
# scripts/ci/run_backend_validation_tests.ps1.
#
# Markers are matched as whole lines because --debug echoes the command line,
# which contains them. On any failure, every session still held is sent ABORT:
# closing its stdin does not release it (see
# a_workload_reading_stdin_to_eof_terminates_when_the_writer_drops in
# src/mxc-sdk/tests/isolation_session.rs).

Write-Host ""
Write-Host "--- Concurrent one-shot ---" -ForegroundColor Cyan

# wxc-exec stdout/stderr capture dir. Cleared at the start of every run, and
# removed again at the end of a green one; a failing run leaves it for inspection.
$concurrentTempRoot = Join-Path $env:TEMP 'mxc_concurrent_oneshot'
Remove-Item -Recurse -Force $concurrentTempRoot -ErrorAction SilentlyContinue
New-Item -Path $concurrentTempRoot -ItemType Directory -Force | Out-Null

# The A, B and C configs' process.timeout must stay above 120 s, the longest
# these waits can hold a session.
$concurrentStartWaitSec = 30
$concurrentExitWaitSec = 60

# Start-Process does not pass this script's stdout and stderr on to cmd.exe, as
# Process.Start with a redirected stream does, so a wxc-exec left running after
# a timeout cannot keep the script's output open. Stdin therefore comes from a
# named pipe, buffered so that a write returns without waiting for wxc-exec to
# read it.
function Start-HeldSession {
    param([string]$Label)
    $stdout = Join-Path $concurrentTempRoot "$Label.stdout.txt"
    $stderr = Join-Path $concurrentTempRoot "$Label.stderr.txt"
    $config = Join-Path $ConfigDir "isolation_session_concurrent_$Label.json"
    $pipeName = "mxc-concurrent-$PID-$Label"
    $stdin = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::Out, 1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous, 0, 4096)
    $command = '/d /s /c ""{0}" --debug "{1}" 0<"\\.\pipe\{2}" 1>"{3}" 2>"{4}""' -f $WxcExec, $config, $pipeName, $stdout, $stderr
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $env:ComSpec -ArgumentList $command -WindowStyle Hidden -PassThru
    $connecting = $stdin.BeginWaitForConnection($null, $null)
    $held = $connecting.AsyncWaitHandle.WaitOne($concurrentStartWaitSec * 1000)
    if ($held) { $stdin.EndWaitForConnection($connecting) } else { $stdin.Dispose() }
    return @{
        Label = $Label; Process = $process; Stdin = $stdin; Clock = $clock
        Held = $held; Passed = $false; Failure = ''; Stdout = $stdout; Stderr = $stderr
    }
}

function Test-CaptureLine {
    param([string]$Path, [string]$Line)
    foreach ($captured in ((Read-LiveFile $Path) -split "`r?`n")) {
        if ($captured.Trim() -ceq $Line) { return $true }
    }
    return $false
}

# Milliseconds from launch until the session printed "X-started", or -1 if it
# did not within the start wait.
function Wait-SessionStarted {
    param($Session)
    $marker = "$($Session.Label)-started"
    $clock = $Session.Clock
    while ($clock.Elapsed.TotalSeconds -lt $concurrentStartWaitSec -and -not $Session.Process.HasExited) {
        if (Test-CaptureLine $Session.Stdout $marker) { return [int]$clock.Elapsed.TotalMilliseconds }
        Start-Sleep -Milliseconds 100
    }
    if (Test-CaptureLine $Session.Stdout $marker) { return [int]$clock.Elapsed.TotalMilliseconds }
    return -1
}

function Send-SessionLine {
    param($Session, [string]$Line)
    if (-not $Session.Held) { return }
    $Session.Held = $false
    try {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes("$Line`r`n")
        $Session.Stdin.Write($bytes, 0, $bytes.Length)
        $Session.Stdin.Flush()
    } catch {
        # Writing fails if the session has ended; its checks report that.
    }
    try { $Session.Stdin.Close() } catch { }
}

# On timeout this kills cmd.exe but leaves wxc-exec running: killing wxc-exec
# would skip the teardown that removes the session's account.
function Wait-SessionExit {
    param($Session)
    if ($Session.Process.WaitForExit($concurrentExitWaitSec * 1000)) { return $true }
    try { $Session.Process.Kill() } catch { }
    return $false
}

# The digest is capped so that the summary's failure lines stay short for
# runners that keep only the tail of the output.
function Get-SessionDigest {
    param($Session)
    $stdout = @((Read-LiveFile $Session.Stdout) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 5)
    $stderr = @((Read-LiveFile $Session.Stderr) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 2)
    $digest = (@($stdout + $stderr) | ForEach-Object { $_.Trim() }) -join ' | '
    if ($digest.Length -gt 400) { $digest = $digest.Substring(0, 397) + '...' }
    return $digest
}

# Scratch directories this script creates that must not outlive the run.
# Removal of each is attempted quietly, since an already-absent directory is the
# normal case, then asserted — a directory held by a scanner or blocked by an
# ACL would otherwise survive a green run, which is the state this cleanup
# exists to prevent.
$scratchLeft = @()

$concurrentSessions = [ordered]@{}
$concurrentAbort = ''
try {
    foreach ($label in 'A', 'B', 'C') {
        $session = Start-HeldSession $label
        $concurrentSessions[$label] = $session
        if (-not $session.Held) {
            $session.Failure = "$label's cmd.exe did not open its stdin pipe within $concurrentStartWaitSec s"
        } else {
            $startedMs = Wait-SessionStarted $session
            if ($startedMs -lt 0) { $session.Failure = "no $label-started line within $concurrentStartWaitSec s" }
        }
        if ($session.Failure) {
            $concurrentAbort = $session.Failure
            break
        }
        Write-Host "  $label started after $startedMs ms" -ForegroundColor DarkGray
    }

    $releaseOrder = @('B', 'A', 'C')
    for ($i = 0; $i -lt $releaseOrder.Count -and -not $concurrentAbort; $i++) {
        $session = $concurrentSessions[$releaseOrder[$i]]
        $label = $session.Label
        $token = "PROCEED-$label"
        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        Send-SessionLine $session $token
        if (-not (Wait-SessionExit $session)) {
            $session.Failure = "still running $concurrentExitWaitSec s after its release"
            $concurrentAbort = "$label $($session.Failure)"
            break
        }
        $exitCode = $session.Process.ExitCode
        Write-Host "  $label released; wxc-exec exited $exitCode after $([int]$clock.Elapsed.TotalMilliseconds) ms" -ForegroundColor DarkGray

        $problems = @()
        if ($exitCode -ne 0) { $problems += "wxc-exec exit $exitCode" }
        if (-not (Test-CaptureLine $session.Stdout "$label-released-$token")) {
            $problems += "no $label-released-$token line"
        }
        if ($problems.Count -gt 0) {
            $session.Failure = $problems -join '; '
            $concurrentAbort = "$label failed its checks"
        } else {
            $session.Passed = $true
        }
        # Every session released later must have outlived this one's teardown.
        for ($j = $i + 1; $j -lt $releaseOrder.Count; $j++) {
            $later = $concurrentSessions[$releaseOrder[$j]]
            if ($later.Process.HasExited) {
                $later.Failure = "not running after $label's wxc-exec exited"
                if (-not $concurrentAbort) { $concurrentAbort = "$($later.Label) ended early" }
            }
        }
    }
} catch {
    $concurrentAbort = "harness error: $($_.Exception.Message)"
} finally {
    foreach ($session in $concurrentSessions.Values) { Send-SessionLine $session 'ABORT' }
    foreach ($session in $concurrentSessions.Values) {
        if (-not $session.Process.HasExited -and -not (Wait-SessionExit $session)) {
            if (-not $session.Failure) { $session.Failure = "aborted: $concurrentAbort" }
            $session.Failure += "; still running $concurrentExitWaitSec s after ABORT"
        }
    }
}

$concurrentNames = [ordered]@{
    A = "concurrent: A held across B's and C's starts and B's teardown"
    B = "concurrent: B held across C's start"
    C = "concurrent: C held across B's and A's teardowns"
}
foreach ($label in $concurrentNames.Keys) {
    $session = $concurrentSessions[$label]
    $reason = ''
    if ($null -ne $session -and $session.Failure) {
        $digest = Get-SessionDigest $session
        $reason = if ($digest) { "$($session.Failure); last output: $digest" } else { $session.Failure }
    } elseif ($null -eq $session -or -not $session.Passed) {
        $reason = "aborted: $concurrentAbort"
    }
    $pass = ($reason -eq '')
    Write-Host "  $($concurrentNames[$label]) ... $(if ($pass) { 'PASS' } else { 'FAIL: ' + $reason })" `
        -ForegroundColor $(if ($pass) { 'Green' } else { 'Red' })
    $null = $results.Add(@{ Name = $concurrentNames[$label]; Pass = $pass; Skipped = $false; Reason = $reason })
}

# A session started after A, B and C have ended must still work.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_concurrent_D.json" `
    -OutputContains @("D-start", "D-done")))


# ---------------- Positive network oracle ----------------
#
# Every other network test here is a rejection, so nothing proved the mandated
# all-allow posture actually carries traffic. The anchor runs on host loopback,
# which an isolated session can reach because it is a separate logon session on
# the same machine -- so this asserts the session's posture rather than the
# runner's outbound internet access. The harness fetches the anchor first with
# the same tool, making "the anchor never came up" distinguishable from "the
# session could not reach it".

Write-Host ""
Write-Host "--- Network ---" -ForegroundColor Cyan

$anchor = Start-LoopbackAnchor
try {
    $anchorLive = $false
    if ($null -eq $anchor) {
        $null = $results.Add(@{ Name = 'network: host loopback anchor'; Pass = $false; Skipped = $false
            Reason = 'Could not bind a host loopback anchor port' })
    } else {
        # `Stop` turns curl's stderr into a terminating error once 2>&1 merges
        # it into the output stream, so flip it for the fetch.
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $hostProbe = & curl.exe --silent --show-error --noproxy "*" --max-time 15 $anchor.Url 2>&1 | Out-String
        $ErrorActionPreference = $prevPref
        $anchorLive = "$hostProbe" -match [regex]::Escape($anchor.Body)
        if (-not $anchorLive) {
            $null = $results.Add(@{ Name = 'network: host loopback anchor'; Pass = $false; Skipped = $false
                Reason = "The anchor did not answer the harness itself: $hostProbe" })
        }
    }

    if ($anchorLive) {
        $anchorRequest = @{
            version     = '1.0.0'
            containment = 'isolation_session'
            process     = @{
                commandLine = (Get-LoopbackAnchorCommand -Url $anchor.Url)
                timeout     = 60000
            }
            network     = @{
                egress  = @{ default = 'allow' }
                ingress = @{ default = 'allow'; hostLoopback = 'allow' }
            }
        }
        $null = $results.Add((Run-IsolationSessionTest "network reaches the host loopback anchor" `
            -Request $anchorRequest -OutputContains @($anchor.Body)))
    }
} finally {
    Stop-LoopbackAnchor -Anchor $anchor
}


# ---------------- Streaming ----------------
#
# The streaming config was previously observed by hand. Reading the first line
# off the live capture file while wxc-exec is still running is what separates
# streamed output from a single burst at exit, so the assertion has to peek at
# a running process rather than inspect its final output.

Write-Host ""
Write-Host "--- Streaming ---" -ForegroundColor Cyan

$streamingRoot = Join-Path $env:TEMP 'mxc_oneshot_streaming'
Remove-Item -Recurse -Force $streamingRoot -ErrorAction SilentlyContinue
New-Item -Path $streamingRoot -ItemType Directory -Force | Out-Null
$streamingStdout = Join-Path $streamingRoot 'stdout.txt'
$streamingStderr = Join-Path $streamingRoot 'stderr.txt'
$streamingConfig = Join-Path $ConfigDir 'isolation_session_streaming_smoke.json'

Write-Host "  isolation_session_streaming_smoke.json ... " -NoNewline
if (-not (Test-Path $streamingConfig)) {
    Write-Host "SKIP (file not found)" -ForegroundColor Yellow
    $null = $results.Add(@{ Name = 'streaming'; Pass = $true; Skipped = $true; Reason = 'File not found' })
} else {
    # Routed through cmd.exe with cmd-managed redirects, matching the
    # concurrent launcher above. Deliberately without --debug: the Logger
    # echoes the command line, and that echo contains line_1/2/3 itself, which
    # would satisfy both the early-read and the ordering checks without any
    # streaming happening.
    $streamingCmd = "/c $WxcExec $streamingConfig 1>$streamingStdout 2>$streamingStderr"
    $streamingProc = Start-Process -FilePath cmd.exe -ArgumentList $streamingCmd `
        -WindowStyle Hidden -PassThru

    # The config prints line_1, waits, prints line_2, waits, prints line_3.
    # line_1 must be readable long before the process exits.
    $sawEarly = $false
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline -and -not $streamingProc.HasExited) {
        if ((Read-LiveFile $streamingStdout) -match 'line_1') { $sawEarly = $true; break }
        Start-Sleep -Milliseconds 50
    }
    if (-not $streamingProc.WaitForExit(60000)) {
        try { $streamingProc.Kill() } catch { }
        $null = $streamingProc.WaitForExit(5000)
    }

    $streamingOutput = Read-LiveFile $streamingStdout
    $streamingPass = $true
    $streamingReason = ''
    if ($streamingProc.ExitCode -ne 0) {
        $streamingPass = $false
        $streamingReason = "Expected exit 0, got $($streamingProc.ExitCode)"
    } elseif (-not $sawEarly) {
        $streamingPass = $false
        $streamingReason = "line_1 was not readable before the command exited (output buffered to exit)"
    } else {
        # Ordering as well as presence: a relay that reorders or drops a stream
        # chunk is a streaming bug even when every line eventually arrives.
        $i1 = $streamingOutput.IndexOf('line_1')
        $i2 = $streamingOutput.IndexOf('line_2')
        $i3 = $streamingOutput.IndexOf('line_3')
        if ($i1 -lt 0 -or $i2 -lt 0 -or $i3 -lt 0) {
            $streamingPass = $false
            $streamingReason = "Output missing one of line_1/line_2/line_3"
        } elseif (-not ($i1 -lt $i2 -and $i2 -lt $i3)) {
            $streamingPass = $false
            $streamingReason = "Output lines arrived out of order"
        }
    }

    if ($streamingPass) {
        Write-Host "PASS" -ForegroundColor Green
    } else {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host "    Reason: $streamingReason" -ForegroundColor Red
    }
    $null = $results.Add(@{ Name = 'streaming (incremental delivery)'; Pass = $streamingPass; Skipped = $false; Reason = $streamingReason })
}


function Run-PostExitOutputTest {
    $name = 'post-exit stdout/stderr draining'
    $root = 'C:\mxc_post_exit_output'
    $process = $null
    $pass = $false
    $reason = ''
    Write-Host "  $name ... " -NoNewline
    try {
        # A fixed public path lets the sandbox read the script without access to
        # the caller's profile.
        if (Test-Path -LiteralPath $root) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
        }
        New-Item -Path $root -ItemType Directory -ErrorAction Stop | Out-Null
        $aclOutput = & icacls.exe $root /grant '*S-1-5-11:(OI)(CI)RX' 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Could not grant script read access: $aclOutput"
        }
        Set-Content -LiteralPath "$root\producer.ps1" -Encoding Ascii -Value @'
param([int]$WaitForParent)
$ErrorActionPreference = 'Stop'
if ($WaitForParent) {
    $parent = $null
    try {
        $parent = [Diagnostics.Process]::GetProcessById($WaitForParent)
    } catch [ArgumentException] {
        # The workload already exited before this child started.
    }
    if ($null -ne $parent) {
        try {
            if (-not $parent.WaitForExit(30000)) {
                throw 'Workload did not exit before child output.'
            }
        } finally {
            $parent.Dispose()
        }
    }
    [Console]::Out.WriteLine('STDOUT-AFTER-PARENT-EXIT')
    [Console]::Error.WriteLine('STDERR-AFTER-PARENT-EXIT')
    1..60 | ForEach-Object {
        [Console]::Out.WriteLine(('STDOUT-LINE {0:D3}' -f $_))
        [Console]::Out.Flush()
        [Console]::Error.WriteLine(('STDERR-LINE {0:D3}' -f $_))
        [Console]::Error.Flush()
        Start-Sleep -Milliseconds 500
    }
    [Console]::Out.WriteLine('STDOUT-END')
    [Console]::Error.WriteLine('STDERR-END')
    exit 0
}
# The backend wraps this PowerShell process in cmd.exe. Wait for that workload
# process, not just this script, before the child starts its output sequence.
$workloadId = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId
if (-not $workloadId) { throw 'Could not identify the workload process.' }
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -WaitForParent {1}' -f $PSCommandPath, $workloadId
$start.UseShellExecute = $false
$child = [Diagnostics.Process]::Start($start)
$child.Dispose()
exit 42
'@
        $config = Join-Path $ConfigDir 'isolation_session_post_exit_output.json'
        if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
            throw "Required config missing: $config"
        }
        $stdout = Join-Path $root 'stdout.txt'
        $stderr = Join-Path $root 'stderr.txt'
        $command = '/d /s /c ""{0}" "{1}" 1>"{2}" 2>"{3}""' -f $WxcExec, $config, $stdout, $stderr
        $process = Start-Process -FilePath $env:ComSpec -ArgumentList $command `
            -WindowStyle Hidden -PassThru
        if (-not $process.WaitForExit(120000)) {
            throw 'Executor did not finish within 120 seconds.'
        }
        if ($process.ExitCode -ne 42) {
            throw "Expected workload exit 42, got $($process.ExitCode)."
        }
        foreach ($stream in @(
                @{ Prefix = 'STDOUT'; Path = $stdout },
                @{ Prefix = 'STDERR'; Path = $stderr }
            )) {
            $expected = @("$($stream.Prefix)-AFTER-PARENT-EXIT")
            $expected += 1..60 | ForEach-Object { '{0}-LINE {1:D3}' -f $stream.Prefix, $_ }
            $expected += "$($stream.Prefix)-END"
            $actual = @(Get-Content -LiteralPath $stream.Path)
            if (($actual -join "`n") -cne ($expected -join "`n")) {
                throw "$($stream.Prefix) incomplete or unexpected: expected 62 lines, got $($actual.Count). See $($stream.Path)."
            }
        }
        $pass = $true
    } catch {
        $reason = $_.Exception.Message
    } finally {
        try {
            if ($null -ne $process -and -not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(10000)) {
                    throw "Could not stop output-drain launcher $($process.Id)."
                }
            }
            if ($pass) {
                Remove-Item -LiteralPath $root -Recurse -Force
            }
        } catch {
            $pass = $false
            $reason = "$reason Cleanup failed: $($_.Exception.Message)"
        } finally {
            if ($null -ne $process) { $process.Dispose() }
        }
    }
    if ($pass) {
        Write-Host 'PASS' -ForegroundColor Green
    } else {
        Write-Host 'FAIL' -ForegroundColor Red
        Write-Host "    Reason: $reason" -ForegroundColor Red
        Write-Host "    Diagnostics: $root (preserved until the next run)" -ForegroundColor Gray
    }
    return @{ Name = $name; Pass = $pass; Skipped = $false; Reason = $reason }
}

$null = $results.Add((Run-PostExitOutputTest))

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
    Remove-Item -Recurse -Force $streamingRoot -ErrorAction SilentlyContinue
    if (Test-Path $streamingRoot) { $scratchLeft += $streamingRoot }
} else {
    Write-Host "  (concurrent stdout/stderr preserved at: $concurrentTempRoot)" -ForegroundColor DarkGray
    Write-Host "  (streaming stdout/stderr preserved at: $streamingRoot)" -ForegroundColor DarkGray
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
