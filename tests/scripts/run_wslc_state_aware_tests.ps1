# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs WSLc state-aware lifecycle E2E tests. Companion to
    run_wslc_all_tests.ps1 -- that script asserts the one-shot path; this
    script asserts the state-aware path (`phase` / `sandboxId` envelope style,
    multi-invocation provision -> start -> exec* -> stop -> deprovision driven
    through the long-lived `wxc-wslc-daemon`).

.DESCRIPTION
    Each test invokes wxc-exec.exe with a base64-encoded state-aware request
    envelope. Provision / start / stop / deprovision return a JSON envelope on
    stdout (asserted on `result` / `error`); a successful exec streams the
    script's own stdout (relayed from the daemon) and exits with the script's
    exit code. Because the daemon owns the live WslcSession / WslcContainer
    handles, exec against a provisioned+started sandbox hits a WARM container:
    the tests prove this two ways -- (1) in-container state (a /tmp marker)
    written by one exec is visible to a later, separate wxc-exec invocation,
    and (2) after the last sandbox is deprovisioned the daemon idles out and
    exits on its own.

    Requires: Windows 11, WSL2, the WSLC SDK runtime (wslcsdk.dll staged next
    to the binaries), pre-pulled images, and a wxc-exec.exe + wxc-wslc-daemon.exe
    built with `--features wslc`. Cannot run in GitHub Actions CI.

    Prerequisite probes (skip, not fail, if missing):
      - wxc-wslc-daemon.exe present next to wxc-exec.exe
      - a state-aware provision does not return `backend_unavailable`
        (catches feature-flag-off builds and a missing WSLC runtime)

    To make the idle-teardown assertion observable in a test run this script
    shortens the daemon's idle watchdog via the
    MXC_WSLC_DAEMON_IDLE_TIMEOUT_SECS / MXC_WSLC_DAEMON_IDLE_POLL_SECS env
    overrides. They are set in this process's environment BEFORE the first
    provision so the spawned daemon inherits them.

.PARAMETER WxcExecPath
    Path to wxc-exec.exe. Default probes the x64 target release/debug dirs.

.PARAMETER ConfigDir
    Directory holding the state-aware request fixtures. Defaults to
    <repo>/tests/configs.

.PARAMETER Debug
    Probe the debug target dir and pass --debug to wxc-exec.

.PARAMETER SkipSetup
    Skip the WSLC image pre-pull preflight (assume the cache is warm).

.EXAMPLE
    .\run_wslc_state_aware_tests.ps1
    .\run_wslc_state_aware_tests.ps1 -WxcExecPath C:\test\wxc-exec.exe -SkipSetup
#>

param(
    [string]$WxcExecPath,
    [string]$ConfigDir,
    [switch]$Debug,
    [switch]$SkipSetup
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# ---------------- Locate wxc-exec.exe + daemon ----------------

$Target = "x86_64-pc-windows-msvc"
$Prof = if ($Debug) { "debug" } else { "release" }

if ($WxcExecPath) {
    $WxcExec = $WxcExecPath
} else {
    $CandidatePaths = @(
        (Join-Path $RepoRoot "src\target\$Target\$Prof\wxc-exec.exe"),
        (Join-Path $RepoRoot "src\target\$Prof\wxc-exec.exe")
    )
    $WxcExec = $CandidatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $WxcExec -or -not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found." -ForegroundColor Red
    Write-Host "Build with: cargo build --features wslc $(if (-not $Debug) { '--release ' })--target $Target" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExecPath explicitly." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nWSLc State-Aware E2E Tests" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host "Binary: $WxcExec`n" -ForegroundColor Gray

# ---------------- Prerequisite probes ----------------

$DaemonExe = Join-Path (Split-Path -Parent $WxcExec) "wxc-wslc-daemon.exe"
if (-not (Test-Path $DaemonExe)) {
    Write-Host "SKIPPED: wxc-wslc-daemon.exe not found next to wxc-exec.exe ($DaemonExe)" -ForegroundColor Yellow
    Write-Host "  Build it with: cargo build --features wslc $(if (-not $Debug) { '--release ' })--target $Target -p wxc-wslc-daemon" -ForegroundColor Yellow
    exit 0
}
$DaemonProcName = "wxc-wslc-daemon"

# Shorten the daemon idle watchdog so the idle-teardown test observes a
# self-exit in seconds rather than the 5-minute production default. Set in
# THIS process's env so the daemon (spawned by the first phase's wxc-exec,
# which inherits our environment) picks them up.
$script:IdleTimeoutSecs = 20
$script:IdlePollSecs = 5
$env:MXC_WSLC_DAEMON_IDLE_TIMEOUT_SECS = "$script:IdleTimeoutSecs"
$env:MXC_WSLC_DAEMON_IDLE_POLL_SECS = "$script:IdlePollSecs"

if (-not $ConfigDir) {
    $ConfigDir = Join-Path $RepoRoot "tests\configs"
}

# ---------------- Image pre-pull preflight ----------------

if (-not $SkipSetup) {
    $SetupScript = Join-Path $RepoRoot "scripts\setup-wslc.ps1"
    if (Test-Path $SetupScript) {
        Write-Host "Pre-pulling WSLc images (pass -SkipSetup to skip)..." -ForegroundColor Cyan
        & $SetupScript -WxcExecPath $WxcExec -Image @("alpine:latest") -Force
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARN: setup-wslc.ps1 reported failures; continuing anyway." -ForegroundColor Yellow
        }
        Write-Host ""
    } else {
        Write-Host "WARN: $SetupScript not found; assuming images are pre-pulled." -ForegroundColor Yellow
    }
}

# ---------------- Helpers ----------------

# Encode a state-aware request envelope and run wxc-exec against it. The request
# comes from a static JSON fixture under tests/configs (with `{{SANDBOX_ID}}`
# substitution) or an inline hashtable. Returns @{ ExitCode; Stdout; Stderr }.
function Invoke-StateAware {
    param(
        [hashtable]$Request,
        [string]$ConfigFile,
        [string]$SandboxId
    )

    if ($ConfigFile) {
        $path = Join-Path $ConfigDir $ConfigFile
        if (-not (Test-Path $path)) { throw "Config fixture not found: $path" }
        $json = Get-Content $path -Raw
        if ($json -match '\{\{SANDBOX_ID\}\}') {
            if (-not $SandboxId) {
                throw "Fixture $ConfigFile contains {{SANDBOX_ID}} but -SandboxId was not supplied"
            }
            $json = $json -replace '\{\{SANDBOX_ID\}\}', $SandboxId
        }
    } elseif ($Request) {
        $json = $Request | ConvertTo-Json -Compress -Depth 12
    } else {
        throw "Invoke-StateAware requires either -Request or -ConfigFile"
    }

    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))

    $argList = @('--experimental')
    if ($Debug) { $argList += '--debug' }
    $argList += @('--config-base64', $b64)

    # Drive wxc-exec via System.Diagnostics.Process rather than Start-Process
    # -Wait: the state-aware phase process exits as soon as it has driven the
    # daemon, but the daemon lives on. Start-Process -Wait does a process-tree
    # (job-object) wait and would block until the surviving daemon also exits.
    # WaitForExit()/ReadToEnd() here wait only on the direct phase process (the
    # daemon does not inherit its stdio), matching how real SDK callers behave;
    # capturing stderr this way also keeps wxc-exec's warnings off PowerShell's
    # error stream (a bare `&` + `2>` throws under $ErrorActionPreference=Stop).
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $WxcExec
    foreach ($a in $argList) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $null = $proc.Start()
    # Read stdout to EOF (fires when the phase process exits) while draining
    # stderr async so a large stderr can never deadlock the stdout read.
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    $stdoutText = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()
    $stderrText = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $proc.ExitCode
    $proc.Dispose()
    @{
        ExitCode = $exitCode
        Stdout   = if ($null -eq $stdoutText) { "" } else { [string]$stdoutText }
        Stderr   = if ($null -eq $stderrText) { "" } else { [string]$stderrText }
    }
}

# Like Invoke-StateAware but records the wall-clock arrival time of each stdout
# line, so a test can prove output is streamed incrementally (an early line lands
# well before a later one) rather than buffered and dumped together at process
# exit. `ReadLineAsync` returns the moment the child flushes a newline-terminated
# line, so a streamed line is observed immediately; a buffer-then-dump impl would
# surface every line at once only when the process exits. Returns
# @{ ExitCode; Stdout; Stderr; Lines = @(@{ Text; At }) } (At = UTC DateTime).
function Invoke-StateAwareStreaming {
    param(
        [string]$ConfigFile,
        [hashtable]$Request,
        [string]$SandboxId
    )

    if ($ConfigFile) {
        $path = Join-Path $ConfigDir $ConfigFile
        if (-not (Test-Path $path)) { throw "Config fixture not found: $path" }
        $json = Get-Content $path -Raw
        if ($json -match '\{\{SANDBOX_ID\}\}') {
            if (-not $SandboxId) {
                throw "Fixture $ConfigFile contains {{SANDBOX_ID}} but -SandboxId was not supplied"
            }
            $json = $json -replace '\{\{SANDBOX_ID\}\}', $SandboxId
        }
    } elseif ($Request) {
        $json = $Request | ConvertTo-Json -Compress -Depth 12
    } else {
        throw "Invoke-StateAwareStreaming requires either -Request or -ConfigFile"
    }

    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
    $argList = @('--experimental')
    if ($Debug) { $argList += '--debug' }
    $argList += @('--config-base64', $b64)

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $WxcExec
    foreach ($a in $argList) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $null = $proc.Start()

    # Drain stderr async so a large stderr can never deadlock the stdout read.
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $lines = New-Object System.Collections.Generic.List[object]
    $sb = [System.Text.StringBuilder]::new()
    while ($true) {
        $line = $proc.StandardOutput.ReadLineAsync().GetAwaiter().GetResult()
        if ($null -eq $line) { break }
        $null = $lines.Add(@{ Text = $line; At = [DateTime]::UtcNow })
        $null = $sb.AppendLine($line)
    }
    $proc.WaitForExit()
    $stderrText = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $proc.ExitCode
    $proc.Dispose()
    @{
        ExitCode = $exitCode
        Stdout   = $sb.ToString()
        Stderr   = if ($null -eq $stderrText) { "" } else { [string]$stderrText }
        Lines    = $lines
    }
}

# Parse the wxc-exec stdout envelope; $null if not valid JSON.
function Parse-Envelope {
    param([string]$Stdout)
    if ([string]::IsNullOrWhiteSpace($Stdout)) { return $null }
    try { $Stdout | ConvertFrom-Json } catch { $null }
}

# Which arm of the envelope is present.
function Envelope-Arm {
    param($Envelope)
    if ($null -eq $Envelope) { return '<empty>' }
    if ($Envelope.PSObject.Properties.Name -contains 'result') { return 'result' }
    if ($Envelope.PSObject.Properties.Name -contains 'error') { return 'error' }
    '<unknown>'
}

# StrictMode-safe property read; returns $null when the object or property is
# absent. run_ci_backend_tests.ps1 imposes Set-StrictMode -Version Latest, under
# which touching a missing property on a PSCustomObject is a terminating error --
# and an envelope carries exactly one of `result` / `error`, so the other arm is
# always missing.
function Get-JsonProperty {
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

# The envelope's `error` object, or $null when the envelope is absent/succeeded.
function Get-EnvelopeError {
    param($Envelope)
    Get-JsonProperty $Envelope 'error'
}

# The envelope's error code, or '<no envelope>' / '<no error>' when absent.
function Get-EnvelopeErrorCode {
    param($Envelope)
    if ($null -eq $Envelope) { return '<no envelope>' }
    $err = Get-JsonProperty $Envelope 'error'
    if ($null -eq $err) { return '<no error>' }
    $code = Get-JsonProperty $err 'code'
    if ($null -eq $code) { return '<no code>' }
    return [string]$code
}

# A property of the envelope's `result` object, or $null when absent.
function Get-EnvelopeResultProperty {
    param($Envelope, [Parameter(Mandatory)][string]$Name)
    Get-JsonProperty (Get-JsonProperty $Envelope 'result') $Name
}

# The envelope's `result.sandboxId` as a string, or $null when absent.
function Get-EnvelopeSandboxId {
    param($Envelope)
    $id = Get-EnvelopeResultProperty $Envelope 'sandboxId'
    if ($null -eq $id) { return $null }
    return [string]$id
}

# Is the daemon process currently running?
function Test-DaemonRunning {
    $null -ne (Get-Process -Name $DaemonProcName -ErrorAction SilentlyContinue)
}

$script:TestResults = @()
$script:currentTestPassed = $true
$script:currentTestFirstFailReason = $null

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Host "  PASS: $Message" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: $Message" -ForegroundColor Red
        if ($script:currentTestPassed) { $script:currentTestFirstFailReason = $Message }
        $script:currentTestPassed = $false
    }
}

function Run-StateAwareTest {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ""
    Write-Host "[$Name]" -ForegroundColor Cyan
    $script:currentTestPassed = $true
    $script:currentTestFirstFailReason = $null
    try {
        & $Body
    } catch {
        Assert-True $false "test body threw: $($_.Exception.Message)"
    }
    $script:TestResults += [pscustomobject]@{
        Name   = $Name
        Passed = $script:currentTestPassed
        Reason = $script:currentTestFirstFailReason
    }
    return $script:currentTestPassed
}

# Assert a provision/start/stop/deprovision envelope succeeded and return the
# parsed envelope (or $null on failure).
function Assert-ResultEnvelope {
    param($Result, [string]$What)
    $envObj = Parse-Envelope -Stdout $Result.Stdout
    $arm = Envelope-Arm $envObj
    if ($arm -ne 'result') {
        Write-Host "  Envelope arm: $arm" -ForegroundColor Red
        Write-Host "  Stdout: $($Result.Stdout)" -ForegroundColor Gray
        Write-Host "  Stderr: $($Result.Stderr)" -ForegroundColor Gray
        Assert-True $false "$What returned a result envelope"
        return $null
    }
    Assert-True ($Result.ExitCode -eq 0) "$What exit code = 0 on success"
    return $envObj
}

# Provision a throwaway sandbox and return its sandbox_id (or $null).
function Provision-Sandbox {
    param([string]$ConfigFile = 'wslc_state_aware_provision.json')
    $r = Invoke-StateAware -ConfigFile $ConfigFile
    $envObj = Parse-Envelope -Stdout $r.Stdout
    if ((Envelope-Arm $envObj) -ne 'result') { return $null }
    Get-EnvelopeSandboxId $envObj
}

# ---------------- Backend-availability probe ----------------

# The shortened idle watchdog ($env:MXC_WSLC_DAEMON_IDLE_*) is only honored by a
# daemon THIS harness spawns (the first phase process passes the env down). A
# daemon that predates the harness keeps its own (default 300s) timeout, so the
# ~50s test H idle-teardown assertion would fail deterministically against it.
# Capture that state before the first provision (which may spawn the daemon) so
# test H can skip the idle assertion instead of failing on a reused daemon.
$script:PreExistingDaemon = Test-DaemonRunning
if ($script:PreExistingDaemon) {
    Write-Host "NOTE: a wxc-wslc-daemon predates this harness; it does not honor the shortened idle watchdog, so the idle-teardown assertion (test H) will be skipped." -ForegroundColor Yellow
}

$probe = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision.json'
$probeEnv = Parse-Envelope -Stdout $probe.Stdout
$probeError = Get-EnvelopeError $probeEnv
if ((Get-EnvelopeErrorCode $probeEnv) -eq 'backend_unavailable') {
    Write-Host "SKIPPED: wxc-exec reports backend_unavailable (built without --features wslc, or no WSLC runtime)" -ForegroundColor Yellow
    exit 0
}
$probeSandboxId = Get-EnvelopeSandboxId $probeEnv
if ($null -ne $probeSandboxId) {
    Write-Host "Backend probe: provisioned $probeSandboxId, deprovisioning ..." -ForegroundColor DarkGray
    $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $probeSandboxId
} elseif ($null -ne $probeError) {
    Write-Host "WARN: probe provision errored (code=$(Get-EnvelopeErrorCode $probeEnv)): $(Get-JsonProperty $probeError 'message')" -ForegroundColor Yellow
    Write-Host "  Continuing -- individual tests will report specific failures." -ForegroundColor Yellow
}

# ---------------- Lifecycle A: core lifecycle + warm reuse ----------------

$script:sandboxId = $null
$deprovisionedOk = $false
try {
    # A1: provision returns wslc:<32-hex>.
    Run-StateAwareTest "A: provision (sandbox_id format)" {
        $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision.json'
        $envObj = Assert-ResultEnvelope $r "provision"
        if ($envObj) {
            $script:sandboxId = Get-EnvelopeSandboxId $envObj
            Assert-True ($script:sandboxId -match '^wslc:[0-9a-f]{32}$') `
                "sandbox_id matches wslc:<32-hex> ($script:sandboxId)"
        }
    } | Out-Null

    # A2: start.
    $startedOk = $false
    if ($null -ne $script:sandboxId) {
        $startedOk = Run-StateAwareTest "A: start (provision + start sequence)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:sandboxId
            $envObj = Assert-ResultEnvelope $r "start"
            if ($envObj) {
                Assert-True ($null -eq (Get-EnvelopeResultProperty $envObj 'metadata')) "result.metadata absent (no start metadata in v1)"
            }
        }
    }

    # A3: exec basic -- streamed stdout, not an envelope.
    $execedOk = $false
    if ($startedOk) {
        $execedOk = Run-StateAwareTest "A: exec (basic)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_exec_basic.json' -SandboxId $script:sandboxId
            Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            Assert-True ($r.Stdout -match 'wslc-state-aware-exec-marker') `
                "stdout contains the script's output (relayed live, not enveloped)"
            $maybeEnv = Parse-Envelope -Stdout $r.Stdout
            Assert-True ($null -eq (Get-EnvelopeError $maybeEnv)) `
                "stdout is not a state-aware error envelope on success"
        }
    }

    # A3b: LIVE DRIP -- prove output is streamed incrementally, not buffered and
    # dumped at exit. The script prints PART1, sleeps 3s, then prints PART2. With
    # live streaming the harness observes PART1 ~3s before PART2; a buffer-then-
    # dump impl would surface both lines together at process exit (gap ~0).
    # Asserting the inter-line arrival gap is the airtight liveness proof a
    # content-only "stdout contains X" check cannot give.
    #
    # De-flake / tolerance: the two outcomes are cleanly separated -- buffered
    # ~0s vs streamed ~$dripSleepSec. We assert the observed gap is at least
    # $dripMinGapSec, chosen as roughly half the sleep so it stays far above the
    # buffered-dump floor while absorbing up to ~$($dripSleepSec - $dripMinGapSec)s
    # of scheduler / pipe-relay jitter (first-byte latency on PART1 shrinks the
    # measured gap, so a generous margin below the full sleep is what keeps this
    # from false-failing under CI load). Widen $dripSleepSec, not $dripMinGapSec,
    # if a slower host is ever observed.
    if ($execedOk) {
        Run-StateAwareTest "A: exec (live drip -- incremental streaming)" {
            $dripSleepSec = 3.0
            $dripMinGapSec = 1.5
            $r = Invoke-StateAwareStreaming -ConfigFile 'wslc_state_aware_exec_drip.json' -SandboxId $script:sandboxId
            Assert-True ($r.ExitCode -eq 0) "drip exec exit code = 0"
            $p1 = $r.Lines | Where-Object { $_.Text -match 'DRIP-PART1' } | Select-Object -First 1
            $p2 = $r.Lines | Where-Object { $_.Text -match 'DRIP-PART2' } | Select-Object -First 1
            Assert-True ($null -ne $p1) "PART1 line observed on stdout"
            Assert-True ($null -ne $p2) "PART2 line observed on stdout"
            if ($p1 -and $p2) {
                $gapSec = ($p2.At - $p1.At).TotalSeconds
                Assert-True ($gapSec -ge $dripMinGapSec) `
                    ("PART1 arrived >={0:N1}s before PART2 (gap {1:N2}s, sleep {2:N1}s) -- streamed live, not buffered" -f $dripMinGapSec, $gapSec, $dripSleepSec)
            }
        } | Out-Null
    }

    # A4: WARM REUSE -- in-container state continuity across separate wxc-exec
    # invocations. exec #1 writes /tmp/wslc_sa_marker; exec #2 (a fresh
    # wxc-exec process) reads it back. This only succeeds if the daemon kept
    # the SAME container warm between the two invocations -- a cold container
    # per exec would have an empty /tmp.
    if ($execedOk) {
        Run-StateAwareTest "A: warm reuse (in-container state continuity)" {
            $w = Invoke-StateAware -ConfigFile 'wslc_state_aware_exec_write_marker.json' -SandboxId $script:sandboxId
            Assert-True ($w.ExitCode -eq 0) "exec #1 (write /tmp marker) exit 0"
            $rd = Invoke-StateAware -ConfigFile 'wslc_state_aware_exec_read_marker.json' -SandboxId $script:sandboxId
            Assert-True ($rd.ExitCode -eq 0) "exec #2 (read /tmp marker) exit 0"
            Assert-True ($rd.Stdout -match 'wslc-warm-marker-content') `
                "exec #2 sees the marker exec #1 wrote (container stayed warm across wxc-exec processes)"
        } | Out-Null
    }

    # A5: exit-code propagation across invocations (1, 7, 0). Each invocation
    # reports its own exit code, and a success after two non-zero exits proves
    # a non-zero exit does not wedge the warm session.
    if ($execedOk) {
        Run-StateAwareTest "A: multi-exec (exit code propagation)" {
            foreach ($pair in @(
                    @{ file = 'wslc_state_aware_exec_exit_1.json'; code = 1 },
                    @{ file = 'wslc_state_aware_exec_exit_7.json'; code = 7 },
                    @{ file = 'wslc_state_aware_exec_exit_0.json'; code = 0 }
                )) {
                $r = Invoke-StateAware -ConfigFile $pair.file -SandboxId $script:sandboxId
                Assert-True ($r.ExitCode -eq $pair.code) `
                    "exec 'exit $($pair.code)' propagates exit code $($pair.code) (got $($r.ExitCode))"
            }
        } | Out-Null
    }

    # A6: per-invocation env plumbing.
    if ($execedOk) {
        Run-StateAwareTest "A: multi-exec (per-invocation env)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_exec_env.json' -SandboxId $script:sandboxId
            Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            Assert-True ($r.Stdout -match 'MY_SA_VAR=state-aware-env-value') `
                "wire env block reaches the container ($($r.Stdout.Trim()))"
        } | Out-Null
    }

    # A7: exec rejects filesystem policy (immutable post-provision).
    if ($execedOk) {
        Run-StateAwareTest "A: exec (filesystem policy rejected post-provision)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_exec_rejected_filesystem.json' -SandboxId $script:sandboxId
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = Get-EnvelopeErrorCode $envObj
            Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
        } | Out-Null
    }

    # A8: stop.
    $stoppedOk = $false
    if ($execedOk) {
        $stoppedOk = Run-StateAwareTest "A: stop (full lifecycle through stop)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_stop.json' -SandboxId $script:sandboxId
            $null = Assert-ResultEnvelope $r "stop"
        }
    }

    # A9: deprovision.
    if ($stoppedOk) {
        $deprovPassed = Run-StateAwareTest "A: deprovision (full lifecycle through deprovision)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:sandboxId
            $null = Assert-ResultEnvelope $r "deprovision"
        }
        if ($deprovPassed) { $deprovisionedOk = $true }
    }

    # A10: stale-id -- stop against the just-deprovisioned sandbox is
    # not_provisioned (the daemon no longer knows the id).
    if ($deprovisionedOk) {
        Run-StateAwareTest "A: stale id (stop on deprovisioned sandbox)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_stop.json' -SandboxId $script:sandboxId
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (stop on stale sandbox failed as expected)"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = Get-EnvelopeErrorCode $envObj
            Assert-True ($code -eq 'not_provisioned') "error.code is 'not_provisioned' (got '$code')"
        } | Out-Null
    }
} finally {
    if ($null -ne $script:sandboxId -and -not $deprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:sandboxId" -ForegroundColor DarkGray
        try { $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:sandboxId } catch { }
    }
}

# ---------------- Lifecycle B: filesystem volumes ----------------

# A separate sandbox provisioned with rw + ro volume mounts. Exercises the
# provision-time volume mapping end-to-end: a file written by the container to
# the rw mount is visible on the host, and the ro mount rejects writes.
$script:BTestRoot = 'C:\mxc_wslc_sa_test'
$script:fsSandboxId = $null
$fsDeprovisionedOk = $false
try {
    New-Item -Path "$script:BTestRoot\rw" -ItemType Directory -Force | Out-Null
    New-Item -Path "$script:BTestRoot\ro" -ItemType Directory -Force | Out-Null
    'ro-seed-content' | Set-Content -Path "$script:BTestRoot\ro\seed.txt" -NoNewline

    $fsProvisionedOk = Run-StateAwareTest "B: provision (rw + ro volumes)" {
        $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision_with_filesystem.json'
        $envObj = Assert-ResultEnvelope $r "filesystem provision"
        if ($envObj) {
            $script:fsSandboxId = Get-EnvelopeSandboxId $envObj
            Assert-True ($script:fsSandboxId -match '^wslc:[0-9a-f]{32}$') `
                "sandbox_id matches wslc:<32-hex> ($script:fsSandboxId)"
        }
    }

    $fsStartedOk = $false
    if ($fsProvisionedOk) {
        $fsStartedOk = Run-StateAwareTest "B: start" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:fsSandboxId
            $null = Assert-ResultEnvelope $r "filesystem start"
        }
    }

    if ($fsStartedOk) {
        Run-StateAwareTest "B: rw mount write visible on host" {
            $req = @{
                phase     = 'exec'
                sandboxId = $script:fsSandboxId
                process   = @{ commandLine = "sh -c 'echo host-visible-content > /mnt/c/mxc_wslc_sa_test/rw/from_container.txt; echo wrote'"; timeout = 30000 }
            }
            $r = Invoke-StateAware -Request $req
            Assert-True ($r.ExitCode -eq 0) "container write to rw mount exit 0"
            $hostPath = "$script:BTestRoot\rw\from_container.txt"
            Assert-True (Test-Path $hostPath) "host sees the file the container wrote ($hostPath)"
            if (Test-Path $hostPath) {
                $content = (Get-Content $hostPath -Raw).Trim()
                Assert-True ($content -eq 'host-visible-content') "host file content matches ('$content')"
            }
        } | Out-Null

        Run-StateAwareTest "B: ro mount read succeeds" {
            $req = @{
                phase     = 'exec'
                sandboxId = $script:fsSandboxId
                process   = @{ commandLine = 'cat /mnt/c/mxc_wslc_sa_test/ro/seed.txt'; timeout = 30000 }
            }
            $r = Invoke-StateAware -Request $req
            Assert-True ($r.ExitCode -eq 0) "container read of ro mount exit 0"
            Assert-True ($r.Stdout -match 'ro-seed-content') "container reads host-seeded ro content"
        } | Out-Null

        Run-StateAwareTest "B: ro mount write denied" {
            $req = @{
                phase     = 'exec'
                sandboxId = $script:fsSandboxId
                process   = @{ commandLine = "sh -c 'echo x > /mnt/c/mxc_wslc_sa_test/ro/should_fail.txt && echo WROTE || echo BLOCKED'"; timeout = 30000 }
            }
            $r = Invoke-StateAware -Request $req
            Assert-True ($r.Stdout -match 'BLOCKED') "write to ro mount is blocked"
            Assert-True (-not (Test-Path "$script:BTestRoot\ro\should_fail.txt")) "no file created on host ro path"
        } | Out-Null
    }

    if ($fsProvisionedOk) {
        Run-StateAwareTest "B: stop" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_stop.json' -SandboxId $script:fsSandboxId
            $null = Assert-ResultEnvelope $r "filesystem stop"
        } | Out-Null
        $fsDeprovPassed = Run-StateAwareTest "B: deprovision" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:fsSandboxId
            $null = Assert-ResultEnvelope $r "filesystem deprovision"
        }
        if ($fsDeprovPassed) { $fsDeprovisionedOk = $true }
    }
} finally {
    if ($null -ne $script:fsSandboxId -and -not $fsDeprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:fsSandboxId" -ForegroundColor DarkGray
        try { $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:fsSandboxId } catch { }
    }
    Remove-Item -Recurse -Force $script:BTestRoot -ErrorAction SilentlyContinue
}

# ---------------- Lifecycle C: bridged network + cooperative proxy ----------------

# Provisioned with network=allow (bridged) so the container has connectivity;
# exec injects HTTP(S)_PROXY cooperatively from a url-form proxy. Asserts the
# proxy env reaches the container (the full functional proxy round-trip is
# covered by the one-shot run_wslc_proxy_test.ps1).
$script:netSandboxId = $null
$netDeprovisionedOk = $false
try {
    $netProvisionedOk = Run-StateAwareTest "C: provision (bridged network)" {
        $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision_bridged.json'
        $envObj = Assert-ResultEnvelope $r "bridged provision"
        if ($envObj) { $script:netSandboxId = Get-EnvelopeSandboxId $envObj }
    }

    $netStartedOk = $false
    if ($netProvisionedOk) {
        $netStartedOk = Run-StateAwareTest "C: start" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:netSandboxId
            $null = Assert-ResultEnvelope $r "bridged start"
        }
    }

    if ($netStartedOk) {
        Run-StateAwareTest "C: exec injects cooperative proxy env" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_exec_proxy.json' -SandboxId $script:netSandboxId
            Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            Assert-True ($r.Stdout -match 'HTTP_PROXY=\[http://127\.0\.0\.1:8888\]') `
                "HTTP_PROXY injected into the container ($($r.Stdout.Trim()))"
            Assert-True ($r.Stdout -match 'https_proxy=\[http://127\.0\.0\.1:8888\]') `
                "https_proxy injected into the container"
        } | Out-Null
    }

    if ($netProvisionedOk) {
        Run-StateAwareTest "C: stop" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_stop.json' -SandboxId $script:netSandboxId
            $null = Assert-ResultEnvelope $r "bridged stop"
        } | Out-Null
        $netDeprovPassed = Run-StateAwareTest "C: deprovision" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:netSandboxId
            $null = Assert-ResultEnvelope $r "bridged deprovision"
        }
        if ($netDeprovPassed) { $netDeprovisionedOk = $true }
    }
} finally {
    if ($null -ne $script:netSandboxId -and -not $netDeprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:netSandboxId" -ForegroundColor DarkGray
        try { $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:netSandboxId } catch { }
    }
}

# ---------------- Lifecycle D: validation rejections ----------------

# Validation runs before any daemon call, so these never provision a real
# sandbox and need no cleanup. They cover the provision-phase honor-matrix
# rejection cells.

Run-StateAwareTest "D: provision (deniedPaths nested under mount rejected)" {
    $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision_rejected_denied.json'
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = Get-EnvelopeErrorCode $envObj
    Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
} | Out-Null

Run-StateAwareTest "D: provision (host filtering rejected)" {
    $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision_rejected_hosts.json'
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = Get-EnvelopeErrorCode $envObj
    Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
} | Out-Null

Run-StateAwareTest "D: provision (proxy at provision rejected)" {
    $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision_rejected_proxy.json'
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = Get-EnvelopeErrorCode $envObj
    Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
} | Out-Null

Run-StateAwareTest "D: start (filesystem policy rejected)" {
    $req = @{ phase = 'start'; sandboxId = 'wslc:0123456789abcdef0123456789abcdef'; filesystem = @{ readwritePaths = @('C:\mxc_wslc_sa_test\rw') } }
    $r = Invoke-StateAware -Request $req
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = Get-EnvelopeErrorCode $envObj
    Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
} | Out-Null

# The cross-cutting wire parser + dispatcher must reject a post-provision proxy
# just like the policy unit test does — proxy is an exec-only concern, fixed at
# provision for the network mode. Cover both post-provision validators (start /
# stop) that funnel through validate_post_provision_policy, exercising the real
# base64 -> parser -> dispatch path rather than only the in-crate unit test.
Run-StateAwareTest "D: start (network.proxy rejected post-provision)" {
    $req = @{ phase = 'start'; sandboxId = 'wslc:0123456789abcdef0123456789abcdef'; network = @{ proxy = @{ url = 'http://127.0.0.1:8888' } } }
    $r = Invoke-StateAware -Request $req
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = Get-EnvelopeErrorCode $envObj
    Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
} | Out-Null

Run-StateAwareTest "D: stop (network.proxy rejected post-provision)" {
    $req = @{ phase = 'stop'; sandboxId = 'wslc:0123456789abcdef0123456789abcdef'; network = @{ proxy = @{ url = 'http://127.0.0.1:8888' } } }
    $r = Invoke-StateAware -Request $req
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = Get-EnvelopeErrorCode $envObj
    Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
} | Out-Null

# ---------------- Lifecycle E: restart cycle (stop -> start again) ----------------

# Exercises stop -> re-start re-activation on the same sandbox. The daemon state
# machine allows it (stop sets started=false; start re-calls WslcStartContainer
# with no guard), but whether the WSLc SDK supports restarting a stopped
# container is a runtime behavior this probe DOCUMENTS rather than mandates.
# Hard assertions: every phase returns a well-formed envelope (no crash/hang);
# if the re-start succeeds, a follow-up exec on the same sandbox must work.
$script:reSandboxId = $null
$script:reRestartSucceeded = $false
$reDeprovisionedOk = $false
try {
    $reProvisionedOk = Run-StateAwareTest "E: provision (restart cycle)" {
        $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision.json'
        $envObj = Assert-ResultEnvelope $r "restart provision"
        if ($envObj) { $script:reSandboxId = Get-EnvelopeSandboxId $envObj }
    }

    $reStartedOk = $false
    if ($reProvisionedOk) {
        $reStartedOk = Run-StateAwareTest "E: start #1" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:reSandboxId
            $null = Assert-ResultEnvelope $r "restart start #1"
        }
    }

    if ($reStartedOk) {
        Run-StateAwareTest "E: exec #1 (before stop)" {
            $req = @{ phase = 'exec'; sandboxId = $script:reSandboxId; process = @{ commandLine = 'echo pre-restart-ok'; timeout = 30000 } }
            $r = Invoke-StateAware -Request $req
            Assert-True ($r.ExitCode -eq 0) "exec #1 exit 0"
            Assert-True ($r.Stdout -match 'pre-restart-ok') "exec #1 produces output"
        } | Out-Null

        $reStoppedOk = Run-StateAwareTest "E: stop" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_stop.json' -SandboxId $script:reSandboxId
            $null = Assert-ResultEnvelope $r "restart stop"
        }

        if ($reStoppedOk) {
            # Re-start after stop: PROBE. The daemon must return SOME well-formed
            # envelope (never crash/hang); record whether the SDK actually
            # supports it.
            Run-StateAwareTest "E: start #2 (re-start after stop) [SDK-behavior probe]" {
                $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:reSandboxId
                $envObj = Parse-Envelope -Stdout $r.Stdout
                $arm = Envelope-Arm $envObj
                Assert-True ($arm -eq 'result' -or $arm -eq 'error') `
                    "re-start returns a well-formed envelope (arm=$arm), daemon did not crash"
                if ($arm -eq 'result') {
                    $script:reRestartSucceeded = $true
                    Write-Host "  INFO: WSLc supports restart-after-stop on the same sandbox" -ForegroundColor DarkGray
                } elseif ($arm -eq 'error') {
                    Write-Host "  INFO: WSLc does NOT support restart-after-stop (error.code=$(Get-EnvelopeErrorCode $envObj)) -- documented limitation" -ForegroundColor DarkGray
                }
            } | Out-Null

            if ($script:reRestartSucceeded) {
                Run-StateAwareTest "E: exec #2 (after re-start)" {
                    $req = @{ phase = 'exec'; sandboxId = $script:reSandboxId; process = @{ commandLine = 'echo post-restart-ok'; timeout = 30000 } }
                    $r = Invoke-StateAware -Request $req
                    Assert-True ($r.ExitCode -eq 0) "exec after re-start exit 0"
                    Assert-True ($r.Stdout -match 'post-restart-ok') "exec after re-start produces output"
                } | Out-Null
            }
        }
    }

    if ($reProvisionedOk) {
        $reDeprovPassed = Run-StateAwareTest "E: deprovision" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:reSandboxId
            $null = Assert-ResultEnvelope $r "restart deprovision"
        }
        if ($reDeprovPassed) { $reDeprovisionedOk = $true }
    }
} finally {
    if ($null -ne $script:reSandboxId -and -not $reDeprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:reSandboxId" -ForegroundColor DarkGray
        try { $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:reSandboxId } catch { }
    }
}

# ---------------- Lifecycle F: exec robustness + state-machine edges ----------------

# A single warm sandbox exercised through the exec surface's edge cases:
# exec-before-start rejection, per-process timeout isolation (the container
# survives a killed process), cwd honoring, and the deprovision/double-
# deprovision state-machine transitions.
$script:edgeSandboxId = $null
$edgeDeprovisionedOk = $false
try {
    $edgeProvisionedOk = Run-StateAwareTest "F: provision (exec-edge sandbox)" {
        $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision.json'
        $envObj = Assert-ResultEnvelope $r "edge provision"
        if ($envObj) { $script:edgeSandboxId = Get-EnvelopeSandboxId $envObj }
    }

    # F1: exec BEFORE start -> not_started (the daemon knows the id but the
    # container has not been started).
    if ($edgeProvisionedOk) {
        Run-StateAwareTest "F: exec before start rejected (not_started)" {
            $req = @{ phase = 'exec'; sandboxId = $script:edgeSandboxId; process = @{ commandLine = 'echo should-not-run'; timeout = 30000 } }
            $r = Invoke-StateAware -Request $req
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (exec before start rejected)"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = Get-EnvelopeErrorCode $envObj
            Assert-True ($code -eq 'not_started') "error.code is 'not_started' (got '$code')"
        } | Out-Null
    }

    $edgeStartedOk = $false
    if ($edgeProvisionedOk) {
        $edgeStartedOk = Run-StateAwareTest "F: start" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:edgeSandboxId
            $null = Assert-ResultEnvelope $r "edge start"
        }
    }

    # F2: per-process timeout isolation. A short timeout SIGKILLs the sleeping
    # process (backend_error), but the keepalive container survives -- a
    # subsequent exec on the same warm sandbox succeeds.
    if ($edgeStartedOk) {
        Run-StateAwareTest "F: exec timeout kills process, container survives" {
            $slow = @{ phase = 'exec'; sandboxId = $script:edgeSandboxId; process = @{ commandLine = 'sleep 30'; timeout = 3000 } }
            $r = Invoke-StateAware -Request $slow
            Assert-True ($r.ExitCode -ne 0) "timed-out exec exits non-zero"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = Get-EnvelopeErrorCode $envObj
            Assert-True ($code -eq 'backend_error') "timeout maps to 'backend_error' (got '$code')"

            $after = @{ phase = 'exec'; sandboxId = $script:edgeSandboxId; process = @{ commandLine = 'echo survived-timeout'; timeout = 30000 } }
            $r2 = Invoke-StateAware -Request $after
            Assert-True ($r2.ExitCode -eq 0) "next exec after a timeout succeeds (container stayed warm)"
            Assert-True ($r2.Stdout -match 'survived-timeout') "warm container still executes commands"
        } | Out-Null
    }

    # F3: working directory (cwd) is honored per exec.
    if ($edgeStartedOk) {
        Run-StateAwareTest "F: exec honors working directory (cwd)" {
            $req = @{ phase = 'exec'; sandboxId = $script:edgeSandboxId; process = @{ commandLine = 'pwd'; cwd = '/tmp'; timeout = 30000 } }
            $r = Invoke-StateAware -Request $req
            Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            Assert-True ($r.Stdout -match '(^|\s)/tmp\s*$') "pwd reports the requested cwd (/tmp) ($($r.Stdout.Trim()))"
        } | Out-Null
    }

    # F4: deprovision WHILE started (skip the explicit stop). deprovision removes
    # the entry regardless of started state, so it succeeds.
    if ($edgeStartedOk) {
        $edgeDeprovPassed = Run-StateAwareTest "F: deprovision while running (skip stop)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:edgeSandboxId
            $null = Assert-ResultEnvelope $r "deprovision-while-running"
        }
        if ($edgeDeprovPassed) { $edgeDeprovisionedOk = $true }
    }

    # F5: double deprovision -> the second is not_provisioned (id already gone).
    if ($edgeDeprovisionedOk) {
        Run-StateAwareTest "F: double deprovision (second is not_provisioned)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:edgeSandboxId
            Assert-True ($r.ExitCode -ne 0) "second deprovision exits non-zero"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = Get-EnvelopeErrorCode $envObj
            Assert-True ($code -eq 'not_provisioned') "error.code is 'not_provisioned' (got '$code')"
        } | Out-Null
    }
} finally {
    if ($null -ne $script:edgeSandboxId -and -not $edgeDeprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:edgeSandboxId" -ForegroundColor DarkGray
        try { $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:edgeSandboxId } catch { }
    }
}

# ---------------- Lifecycle G: multi-container isolation ----------------

# Two independently provisioned sandboxes coexist under the one daemon. Their
# in-container filesystems are isolated (a /tmp marker in A is invisible in B),
# and the daemon refcounts correctly: deprovisioning A leaves B fully usable.
$script:mcSandboxA = $null
$script:mcSandboxB = $null
$mcADeprovisionedOk = $false
$mcBDeprovisionedOk = $false
try {
    $mcAProvOk = Run-StateAwareTest "G: provision sandbox A" {
        $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision.json'
        $envObj = Assert-ResultEnvelope $r "multi-container A provision"
        if ($envObj) { $script:mcSandboxA = Get-EnvelopeSandboxId $envObj }
    }
    $mcBProvOk = Run-StateAwareTest "G: provision sandbox B" {
        $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision.json'
        $envObj = Assert-ResultEnvelope $r "multi-container B provision"
        if ($envObj) { $script:mcSandboxB = Get-EnvelopeSandboxId $envObj }
    }

    if ($mcAProvOk -and $mcBProvOk) {
        Run-StateAwareTest "G: distinct sandbox ids" {
            Assert-True ($script:mcSandboxA -ne $script:mcSandboxB) `
                "A and B have distinct ids ($script:mcSandboxA vs $script:mcSandboxB)"
        } | Out-Null
    }

    $mcAStarted = $false
    $mcBStarted = $false
    if ($mcAProvOk) {
        $mcAStarted = Run-StateAwareTest "G: start sandbox A" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:mcSandboxA
            $null = Assert-ResultEnvelope $r "multi-container A start"
        }
    }
    if ($mcBProvOk) {
        $mcBStarted = Run-StateAwareTest "G: start sandbox B" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:mcSandboxB
            $null = Assert-ResultEnvelope $r "multi-container B start"
        }
    }

    # G: filesystem isolation -- a marker written in A must not appear in B.
    if ($mcAStarted -and $mcBStarted) {
        Run-StateAwareTest "G: /tmp marker in A is invisible in B" {
            $writeA = @{ phase = 'exec'; sandboxId = $script:mcSandboxA; process = @{ commandLine = "sh -c 'echo A-secret-content > /tmp/iso_marker; echo wrote'"; timeout = 30000 } }
            $ra = Invoke-StateAware -Request $writeA
            Assert-True ($ra.ExitCode -eq 0) "write marker in A exit 0"

            $readB = @{ phase = 'exec'; sandboxId = $script:mcSandboxB; process = @{ commandLine = "sh -c 'cat /tmp/iso_marker 2>/dev/null || echo NO_MARKER'"; timeout = 30000 } }
            $rb = Invoke-StateAware -Request $readB
            Assert-True ($rb.ExitCode -eq 0) "read attempt in B exit 0"
            Assert-True ($rb.Stdout -match 'NO_MARKER') "B does not see A's marker (isolated /tmp)"
            Assert-True (-not ($rb.Stdout -match 'A-secret-content')) "A's content never leaks into B"
        } | Out-Null
    }

    # G: refcount -- deprovision A, then B must still be usable (daemon stays up
    # because B is still live).
    if ($mcAProvOk) {
        $mcADeprovPassed = Run-StateAwareTest "G: deprovision A (B still live)" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:mcSandboxA
            $null = Assert-ResultEnvelope $r "multi-container A deprovision"
        }
        if ($mcADeprovPassed) { $mcADeprovisionedOk = $true }
    }

    if ($mcADeprovisionedOk -and $mcBStarted) {
        Run-StateAwareTest "G: exec B after A deprovisioned" {
            $req = @{ phase = 'exec'; sandboxId = $script:mcSandboxB; process = @{ commandLine = 'echo B-still-alive'; timeout = 30000 } }
            $r = Invoke-StateAware -Request $req
            Assert-True ($r.ExitCode -eq 0) "B exec after A deprovision exit 0 (daemon stayed up)"
            Assert-True ($r.Stdout -match 'B-still-alive') "B remains fully usable after A is gone"
        } | Out-Null
    }

    if ($mcBProvOk) {
        $mcBDeprovPassed = Run-StateAwareTest "G: deprovision B" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:mcSandboxB
            $null = Assert-ResultEnvelope $r "multi-container B deprovision"
        }
        if ($mcBDeprovPassed) { $mcBDeprovisionedOk = $true }
    }
} finally {
    if ($null -ne $script:mcSandboxA -and -not $mcADeprovisionedOk) {
        try { $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:mcSandboxA } catch { }
    }
    if ($null -ne $script:mcSandboxB -and -not $mcBDeprovisionedOk) {
        try { $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:mcSandboxB } catch { }
    }
}

# ---------------- Lifecycle H: idle teardown ----------------

# All sandboxes above have been deprovisioned, so the daemon's live-container
# count is zero. With the shortened idle watchdog it must self-exit within the
# idle window. Poll until the process is gone or the deadline passes. This must
# stay the second-to-last lifecycle -- it drives the daemon to exit.
Run-StateAwareTest "H: daemon idles out after last deprovision" {
    if ($script:PreExistingDaemon) {
        # A daemon that predates the harness keeps its own (default) idle
        # timeout, so the shortened window this assertion relies on does not
        # apply. Skip rather than fail deterministically on a reused daemon.
        Write-Host "  SKIP: a pre-existing daemon does not honor the shortened idle watchdog" -ForegroundColor DarkYellow
        return
    }
    if (-not (Test-DaemonRunning)) {
        # Already gone (e.g. torn down during an inter-lifecycle gap). That is
        # itself a valid idle-teardown observation.
        Assert-True $true "daemon already exited (idle teardown observed)"
    } else {
        $deadline = (Get-Date).AddSeconds($script:IdleTimeoutSecs + ($script:IdlePollSecs * 3) + 15)
        while ((Test-DaemonRunning) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $script:IdlePollSecs
        }
        Assert-True (-not (Test-DaemonRunning)) `
            "daemon exited within the idle window (~$($script:IdleTimeoutSecs)s after going idle)"
    }
} | Out-Null

# ---------------- Lifecycle I: idle recovery (daemon respawns) ----------------

# After the idle teardown above, a fresh provision must transparently respawn
# the daemon -- idle teardown is a warm-cache eviction, not a one-way terminal
# state. Runs LAST because it depends on the daemon having exited.
$script:recSandboxId = $null
$recDeprovisionedOk = $false
try {
    $recProvisionedOk = Run-StateAwareTest "I: provision after idle teardown (daemon respawns)" {
        $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_provision.json'
        $envObj = Assert-ResultEnvelope $r "post-teardown provision"
        if ($envObj) {
            $script:recSandboxId = Get-EnvelopeSandboxId $envObj
            Assert-True ($script:recSandboxId -match '^wslc:[0-9a-f]{32}$') `
                "sandbox_id matches wslc:<32-hex> ($script:recSandboxId)"
        }
        Assert-True (Test-DaemonRunning) "daemon is running again after the fresh provision"
    }

    $recStartedOk = $false
    if ($recProvisionedOk) {
        $recStartedOk = Run-StateAwareTest "I: start after recovery" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_start.json' -SandboxId $script:recSandboxId
            $null = Assert-ResultEnvelope $r "post-teardown start"
        }
    }

    if ($recStartedOk) {
        Run-StateAwareTest "I: exec after recovery" {
            $req = @{ phase = 'exec'; sandboxId = $script:recSandboxId; process = @{ commandLine = 'echo recovered-ok'; timeout = 30000 } }
            $r = Invoke-StateAware -Request $req
            Assert-True ($r.ExitCode -eq 0) "exec on the respawned daemon exit 0"
            Assert-True ($r.Stdout -match 'recovered-ok') "respawned daemon executes commands normally"
        } | Out-Null
    }

    if ($recProvisionedOk) {
        $recDeprovPassed = Run-StateAwareTest "I: deprovision after recovery" {
            $r = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:recSandboxId
            $null = Assert-ResultEnvelope $r "post-teardown deprovision"
        }
        if ($recDeprovPassed) { $recDeprovisionedOk = $true }
    }
} finally {
    if ($null -ne $script:recSandboxId -and -not $recDeprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:recSandboxId" -ForegroundColor DarkGray
        try { $null = Invoke-StateAware -ConfigFile 'wslc_state_aware_deprovision.json' -SandboxId $script:recSandboxId } catch { }
    }
}

# ---------------- Summary ----------------

$total  = $script:TestResults.Count
$failed = @($script:TestResults | Where-Object { -not $_.Passed }).Count
$passed = $total - $failed

Write-Host ""
Write-Host "==========================" -ForegroundColor Cyan
if ($failed -eq 0) {
    Write-Host "$passed/$total passed" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$passed/$total passed, $failed FAILED:" -ForegroundColor Red
    $script:TestResults | Where-Object { -not $_.Passed } | ForEach-Object {
        $line = if ($_.Reason) { "  FAIL: $($_.Name) - $($_.Reason)" } else { "  FAIL: $($_.Name)" }
        Write-Host $line -ForegroundColor Red
    }
    exit 1
}
