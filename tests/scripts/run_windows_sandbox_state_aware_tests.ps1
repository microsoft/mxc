# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs Windows Sandbox state-aware lifecycle E2E tests. Companion to the
    one-shot Windows Sandbox path; this script drives the multi-invocation
    state-aware lifecycle (`phase` / `sandboxId` envelope style):
    provision -> start -> exec* -> stop -> deprovision, against a REAL
    wxc-exec.exe + the detached host-side daemon + a live Windows Sandbox VM.

.DESCRIPTION
    Each test invokes wxc-exec.exe with a base64-encoded state-aware request
    envelope, parses the JSON response on stdout, and asserts on the
    envelope's `result` or `error` fields (and, for exec, on the streamed
    stdout / exit code).

    Windows Sandbox is single-instance per host and boots a fresh VM at
    `start`, so this script must run INTERACTIVELY on a host that has the
    Windows Sandbox optional feature enabled. It will SKIP (not fail) when
    that feature is absent.

    Prerequisite probes (skip if missing -- not a failure):
      - WindowsSandbox.exe present in System32 (feature enabled)
      - wxc-exec.exe responds to a state-aware provision request without
        backend_unavailable (catches --experimental-off / feature-off builds)

.PARAMETER WxcExePath
    Path to wxc-exec.exe. Default probes the host-arch target dir, then the
    other-arch target dir, then the default release/debug dirs.

.PARAMETER StartTimeoutSec
    Seconds to wait for the `start` phase (cold VM boot). Default 600.

.EXAMPLE
    .\run_windows_sandbox_state_aware_tests.ps1
    .\run_windows_sandbox_state_aware_tests.ps1 -WxcExePath C:\test\wxc-exec.exe
#>

param(
    [string]$WxcExePath,
    [int]$StartTimeoutSec = 600
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# ---------------- Locate wxc-exec.exe ----------------

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
    Write-Host "Build with: cargo build --release --target $HostTarget" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExePath explicitly." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nWindows Sandbox State-Aware E2E Tests" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Binary: $WxcExec`n" -ForegroundColor Gray

# ---------------- Prerequisite probes ----------------

if (-not (Test-Path 'C:\Windows\System32\WindowsSandbox.exe')) {
    Write-Host "SKIPPED: WindowsSandbox.exe not present (the Windows Sandbox optional feature is not enabled)" -ForegroundColor Yellow
    exit 0
}

# Pre-flight: reap stale state from a prior failed run, and wait for vmmem
# residue to release before we try to start a new VM. The state-aware path
# only ever holds ONE VM (vs the one-shot script's 10), so memory pressure
# is normally fine, but vmmem from a recent prior run can transiently reserve
# 2+ GB; starting before it releases risks OOM on a small host.
Write-Host "Pre-flight: reaping any stale wxc-windows-sandbox-daemon / WindowsSandbox processes..." -ForegroundColor Yellow
Get-Process -Name 'wxc-windows-sandbox-daemon', 'WindowsSandbox*' -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
# Also nuke any stale state-aware records so a prior crashed daemon does not
# trip start with "another sandbox is already active" diagnostics.
Remove-Item -Recurse -Force (Join-Path $env:TEMP 'wxc-wsb\state-aware') -ErrorAction SilentlyContinue

$preflightDeadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $preflightDeadline) {
    $vmmem = @(Get-Process -Name 'vmmem*' -ErrorAction SilentlyContinue)
    # vmmemCmZygote is always present on hosts with the Containers feature;
    # we only wait for any *additional* vmmem from a prior sandbox to release.
    if ($vmmem.Count -le 1) { break }
    Start-Sleep -Seconds 5
}
$os = Get-CimInstance Win32_OperatingSystem
$freeMb = [int]($os.FreePhysicalMemory / 1024)
if ($freeMb -lt 2048) {
    Write-Host "SKIPPED: insufficient free memory before start ($freeMb MB free, need >=2048 MB). Close other workloads and retry." -ForegroundColor Yellow
    exit 0
}
Write-Host "Pre-flight OK: $freeMb MB free, no orphan vmmem`n" -ForegroundColor DarkGray

# ---------------- Helpers ----------------

# Encode a state-aware request envelope and run wxc-exec against it. Captures
# stdout / stderr to files (so the single-envelope stdout is not interleaved
# with ConPTY) and returns a hashtable with ExitCode / Stdout / Stderr. A
# bounded wait guards against a wedged phase (the cold-boot `start` needs a
# generous budget; everything else uses a short default).
function Invoke-StateAware {
    param(
        [hashtable]$Request,
        [int]$TimeoutSec = 120
    )

    $json = $Request | ConvertTo-Json -Compress -Depth 12
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath $WxcExec `
            -ArgumentList @('--experimental', '--config-base64', $b64) `
            -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile `
            -NoNewWindow -PassThru
        $null = $proc.Handle  # cache the handle so ExitCode survives the timed wait
        if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
            try { $proc.Kill() } catch { }
            throw "phase '$($Request.phase)' timed out after $TimeoutSec s"
        }
        $proc.WaitForExit()
        $stdoutText = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
        $stderrText = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
        @{
            ExitCode = $proc.ExitCode
            Stdout   = if ($null -eq $stdoutText) { "" } else { [string]$stdoutText }
            Stderr   = if ($null -eq $stderrText) { "" } else { [string]$stderrText }
        }
    } finally {
        Remove-Item $stdoutFile -ErrorAction SilentlyContinue
        Remove-Item $stderrFile -ErrorAction SilentlyContinue
    }
}

# Parses the wxc-exec stdout envelope and returns the parsed object, or $null
# if the stdout is not valid JSON.
function Parse-Envelope {
    param([string]$Stdout)
    if ([string]::IsNullOrWhiteSpace($Stdout)) { return $null }
    try { $Stdout | ConvertFrom-Json } catch { $null }
}

function Show-Procs {
    (Get-Process -Name 'WindowsSandbox*', 'wxc-windows-sandbox-daemon' -ErrorAction SilentlyContinue |
        Select-Object -Expand Name) -join ', '
}

# ---------------- Backend-availability probe ----------------

# Provision is pure bookkeeping (no VM); a healthy build returns a wsb: id.
# A backend_unavailable envelope means the build lacks the backend -- SKIP.
$probe = Invoke-StateAware -Request @{ phase = 'provision'; containment = 'windows_sandbox' } -TimeoutSec 60
$probeEnv = Parse-Envelope -Stdout $probe.Stdout
if ($null -ne $probeEnv -and $probeEnv.error.code -eq 'backend_unavailable') {
    Write-Host "SKIPPED: wxc-exec reports backend_unavailable (build without the windows_sandbox backend or --experimental off)" -ForegroundColor Yellow
    exit 0
}
# The probe sandbox is bookkeeping-only (no VM, no daemon); deprovision it so
# the run starts from a clean per-sandbox record set.
if ($null -ne $probeEnv -and $null -ne $probeEnv.result -and $null -ne $probeEnv.result.sandboxId) {
    $probeId = [string]$probeEnv.result.sandboxId
    Write-Host "Backend probe: provisioned $probeId, deprovisioning ..." -ForegroundColor DarkGray
    [void](Invoke-StateAware -Request @{ phase = 'deprovision'; sandboxId = $probeId } -TimeoutSec 60)
}

# ---------------- Test harness ----------------

$script:TestResults = @()
$script:currentTestPassed = $true
$script:currentTestFirstFailReason = $null

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Host "  PASS: $Message" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: $Message" -ForegroundColor Red
        if ($script:currentTestPassed) {
            $script:currentTestFirstFailReason = $Message
        }
        $script:currentTestPassed = $false
    }
}

function Run-StateAwareTest {
    param(
        [string]$Name,
        [scriptblock]$Body
    )
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

# ---------------- Lifecycle ----------------
#
# The phases are ordered and stateful: a single sandbox is provisioned, started
# (one live VM behind the daemon), exercised with several execs, then stopped
# and deprovisioned. $script:Sid threads the minted id through the phases; once
# start succeeds, a `finally`-style cleanup guarantees the VM is torn down even
# if an assertion fails midway.

$script:Sid = $null
$script:Started = $false

try {
    Run-StateAwareTest 'provision mints a wsb: sandbox id' {
        $r = Invoke-StateAware -Request @{ phase = 'provision'; containment = 'windows_sandbox' } -TimeoutSec 60
        Assert-True ($r.ExitCode -eq 0) "provision exit 0 (got $($r.ExitCode))"
        $env = Parse-Envelope -Stdout $r.Stdout
        $sid = if ($env) { [string]$env.result.sandboxId } else { $null }
        Assert-True ($null -ne $sid -and $sid.StartsWith('wsb:')) "sandboxId has wsb: prefix (got '$sid')"
        $script:Sid = $sid
    } | Out-Null

    if (-not $script:Sid) {
        Write-Host "`nAborting: provision did not yield a sandbox id." -ForegroundColor Red
    } else {
        Run-StateAwareTest 'start boots the VM and the daemon' {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-StateAware -Request @{ phase = 'start'; sandboxId = $script:Sid } -TimeoutSec $StartTimeoutSec
            $sw.Stop()
            Write-Host "  (start took $([int]$sw.Elapsed.TotalSeconds)s)" -ForegroundColor DarkGray
            Assert-True ($r.ExitCode -eq 0) "start exit 0 (got $($r.ExitCode)); stdout=$($r.Stdout.Trim())"
            if ($r.ExitCode -eq 0) { $script:Started = $true }
            $procs = Show-Procs
            Assert-True ($procs -match 'WindowsSandbox') "a Windows Sandbox VM is running after start (procs: $procs)"
            Assert-True ($procs -match 'wxc-windows-sandbox-daemon') "the host daemon is running after start (procs: $procs)"
        } | Out-Null

        if ($script:Started) {
            Run-StateAwareTest 'exec streams stdout and returns exit 0' {
                $r = Invoke-StateAware -Request @{ phase = 'exec'; sandboxId = $script:Sid; process = @{ commandLine = 'echo hello-from-wsb' } } -TimeoutSec 120
                Assert-True ($r.ExitCode -eq 0) "exec exit 0 (got $($r.ExitCode))"
                Assert-True ($r.Stdout -match 'hello-from-wsb') "exec stdout contains the marker (got '[$($r.Stdout.Trim())]')"
            } | Out-Null

            Run-StateAwareTest 'a second exec reuses the same VM' {
                $r = Invoke-StateAware -Request @{ phase = 'exec'; sandboxId = $script:Sid; process = @{ commandLine = 'echo second-exec' } } -TimeoutSec 120
                Assert-True ($r.ExitCode -eq 0) "reuse exec exit 0 (got $($r.ExitCode))"
                Assert-True ($r.Stdout -match 'second-exec') "reuse exec stdout contains the marker (got '[$($r.Stdout.Trim())]')"
            } | Out-Null

            # Python and PowerShell on the held VM: parity with the one-shot
            # suite's `basic_windows_sandbox.json` + `windows_sandbox_powershell.json`
            # configs. The point of running these against the SAME held VM
            # (instead of cold-booting a fresh VM each time, as one-shot
            # does) is to exercise interpreter spin-up after multiple
            # bridge reconnects. -NoProfile keeps PowerShell from loading
            # the user profile inside the sandbox (which can take seconds
            # and isn't part of the test's behavioural contract).
            Run-StateAwareTest 'python exec on held VM prints expected markers' {
                $cmd = 'python -S -B -c "import sys; print(''Hello from Windows Sandbox!''); print(''pyver:''+sys.version.split()[0]); print(''Script executed successfully in sandbox isolation'')"'
                $r = Invoke-StateAware -Request @{ phase = 'exec'; sandboxId = $script:Sid; process = @{ commandLine = $cmd } } -TimeoutSec 120
                Assert-True ($r.ExitCode -eq 0) "python exec exit 0 (got $($r.ExitCode))"
                Assert-True ($r.Stdout -match 'Hello from Windows Sandbox!') "python stdout greets (got '[$($r.Stdout.Trim())]')"
                Assert-True ($r.Stdout -match 'executed successfully') "python stdout reports success (got '[$($r.Stdout.Trim())]')"
                Assert-True ($r.Stdout -match 'pyver:\d+\.\d+') "python stdout reports interpreter version (got '[$($r.Stdout.Trim())]')"
            } | Out-Null

            Run-StateAwareTest 'powershell exec on held VM prints expected markers' {
                $cmd = 'powershell -NoProfile -Command "Write-Output ''PowerShell works''; Write-Output (''psver:''+$PSVersionTable.PSVersion.ToString())"'
                $r = Invoke-StateAware -Request @{ phase = 'exec'; sandboxId = $script:Sid; process = @{ commandLine = $cmd } } -TimeoutSec 120
                Assert-True ($r.ExitCode -eq 0) "powershell exec exit 0 (got $($r.ExitCode))"
                Assert-True ($r.Stdout -match 'PowerShell works') "powershell stdout greets (got '[$($r.Stdout.Trim())]')"
                Assert-True ($r.Stdout -match 'psver:\d+\.\d+') "powershell stdout reports version (got '[$($r.Stdout.Trim())]')"
            } | Out-Null

            Run-StateAwareTest 'exec propagates a non-zero child exit code' {
                $r = Invoke-StateAware -Request @{ phase = 'exec'; sandboxId = $script:Sid; process = @{ commandLine = 'exit 7' } } -TimeoutSec 120
                Assert-True ($r.ExitCode -eq 7) "exec surfaces child exit 7 (got $($r.ExitCode))"
            } | Out-Null

            # Timeout cleanup must leave the VM reusable.
            # The hardest path in `executor.rs` is "timed-out exec, reap
            # the descendant tree via the Job Object, abort the bridge
            # drains, return to the command loop ready for the next
            # exec." If the timeout cleanup wedged pipes or left a
            # descendant holding the stdio handles, the *next* exec
            # would either hang or see empty output -- which is the
            # whole state-aware value proposition broken. The previous
            # E2E coverage only exercised this path in one-shot
            # (`windows_sandbox_timeout.json`), which cannot prove
            # reuse survives because each one-shot is a fresh VM.
            #
            # The test runs a command that exits well past the
            # configured timeout (PowerShell `Start-Sleep 30` against a
            # 2s timeout), expects a non-zero result, then immediately
            # runs a normal echo and asserts it succeeds with the
            # expected stdout.
            Run-StateAwareTest 'reused VM survives a timed-out exec' {
                $sleepCmd = 'powershell -NoProfile -Command "Start-Sleep -Seconds 30"'
                $timed = Invoke-StateAware -Request @{ phase = 'exec'; sandboxId = $script:Sid; process = @{ commandLine = $sleepCmd; timeout = 2000 } } -TimeoutSec 30
                # The exact exit code on timeout is backend-defined
                # (currently non-zero "process timed out"); we just
                # require it to be non-zero so the test does not get
                # locked to a specific code.
                Assert-True ($timed.ExitCode -ne 0) "timed-out exec surfaces non-zero exit (got $($timed.ExitCode); stderr was '[$($timed.Stderr.Trim())]')"
                # Immediately reuse the VM with a normal echo. If the
                # bridge / pipes / Job Object cleanup wedged
                # something, this will either hang to the script's
                # outer timeout or come back with empty stdout. The
                # assertion catches both.
                $r = Invoke-StateAware -Request @{ phase = 'exec'; sandboxId = $script:Sid; process = @{ commandLine = 'echo post-timeout-still-alive' } } -TimeoutSec 120
                Assert-True ($r.ExitCode -eq 0) "post-timeout exec exit 0 (got $($r.ExitCode))"
                Assert-True ($r.Stdout -match 'post-timeout-still-alive') "post-timeout exec stdout (got '[$($r.Stdout.Trim())]')"
            } | Out-Null
        }
    }
} finally {
    if ($script:Started) {
        Run-StateAwareTest 'stop tears down the VM' {
            $r = Invoke-StateAware -Request @{ phase = 'stop'; sandboxId = $script:Sid } -TimeoutSec 120
            Assert-True ($r.ExitCode -eq 0) "stop exit 0 (got $($r.ExitCode))"
            Start-Sleep -Seconds 3
            $procs = Show-Procs
            Assert-True ($procs -notmatch 'WindowsSandbox') "no Windows Sandbox VM remains after stop (procs: '$procs')"
        } | Out-Null
    }
    if ($script:Sid) {
        Run-StateAwareTest 'deprovision removes the sandbox records' {
            $r = Invoke-StateAware -Request @{ phase = 'deprovision'; sandboxId = $script:Sid } -TimeoutSec 120
            Assert-True ($r.ExitCode -eq 0) "deprovision exit 0 (got $($r.ExitCode))"
            $daemonRec = Join-Path $env:TEMP 'wxc-wsb\state-aware\daemon.json'
            Assert-True (-not (Test-Path $daemonRec)) "daemon.json is gone after deprovision"
        } | Out-Null
    }
}

# ---------------- Summary ----------------

Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
$pass = ($script:TestResults | Where-Object { $_.Passed }).Count
$fail = ($script:TestResults | Where-Object { -not $_.Passed }).Count
foreach ($t in $script:TestResults) {
    if ($t.Passed) {
        Write-Host ("  [PASS] {0}" -f $t.Name) -ForegroundColor Green
    } else {
        Write-Host ("  [FAIL] {0} -- {1}" -f $t.Name, $t.Reason) -ForegroundColor Red
    }
}
Write-Host ("PASS: {0}   FAIL: {1}" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })

# Final reap so a failed run does not strand a daemon or VM that would block
# the next attempt's pre-flight memory check.
Write-Host ""
Write-Host "Final reap of any lingering daemon / VM processes..." -ForegroundColor Yellow
Get-Process -Name 'wxc-windows-sandbox-daemon', 'WindowsSandbox*' -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

exit $(if ($fail -eq 0) { 0 } else { 1 })
