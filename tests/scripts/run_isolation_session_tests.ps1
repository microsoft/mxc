# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs IsolationSession E2E tests. Requires a Windows host with the
    in-proc Windows.AI.IsolationSession IsoSessionOps APIs available
    (IsoSessionApp.dll registered, Feature_IsoBrokerSessionApis enabled,
    and Feature_IsoBrokerCommandLineSessions enabled for the Composable
    config-id path).

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
# Three-tier probe mirroring run_isolation_session_state_aware_tests.ps1:
#   1. IsoSessionApp.dll present in System32
#   2. WinRT activatable class IsoSessionOps registered
#   3. wxc-exec responds to a state-aware request without backend_unavailable
#      (catches feature-flag-off builds)
# Any failure surfaces as SKIP rather than a forest of FAILed tests.

if (-not (Test-Path 'C:\Windows\System32\IsoSessionApp.dll')) {
    Write-Host "SKIPPED: IsoSessionApp.dll not present in System32" -ForegroundColor Yellow
    exit 0
}
$IsoSessionOpsKey = "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.AI.IsolationSession.IsoSessionOps"
if (-not (Test-Path $IsoSessionOpsKey)) {
    Write-Host "SKIPPED: Windows.AI.IsolationSession.IsoSessionOps WinRT class not registered" -ForegroundColor Yellow
    exit 0
}

# Helper: send an inline state-aware request via --config-base64 and return
# { Stdout, ExitCode }.
function Invoke-StateAwareProbe {
    param([hashtable]$Request)
    $json = $Request | ConvertTo-Json -Compress -Depth 8
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
    $out = & $WxcExec --experimental --config-base64 $b64 2>&1 | Out-String
    @{ Stdout = $out; ExitCode = $LASTEXITCODE }
}

$probe = Invoke-StateAwareProbe -Request @{ phase = 'provision'; containment = 'isolation_session' }
$probeEnv = $null
try { $probeEnv = $probe.Stdout | ConvertFrom-Json } catch { }
if ($null -ne $probeEnv -and $probeEnv.error.code -eq 'backend_unavailable') {
    Write-Host "SKIPPED: wxc-exec reports backend_unavailable (likely built without --features isolation_session)" -ForegroundColor Yellow
    exit 0
}
# On a healthy build the probe successfully provisions an agent user --
# deprovision it immediately so the probe doesn't leak.
if ($null -ne $probeEnv -and $null -ne $probeEnv.result -and $null -ne $probeEnv.result.sandboxId) {
    $probeSandboxId = [string]$probeEnv.result.sandboxId
    $probeAgent = if ($probeEnv.result.metadata) { [string]$probeEnv.result.metadata.agentUserName } else { '<absent>' }
    Write-Host "Backend probe: provisioned $probeSandboxId (agentUserName=$probeAgent), deprovisioning ..." -ForegroundColor DarkGray
    $deprov = Invoke-StateAwareProbe -Request @{ phase = 'deprovision'; sandboxId = $probeSandboxId }
    if ($deprov.ExitCode -ne 0) {
        Write-Host "WARN: probe deprovision returned exit $($deprov.ExitCode); local user $probeAgent may persist" -ForegroundColor Yellow
        Write-Host "  Stdout: $($deprov.Stdout)" -ForegroundColor Gray
    }
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

# Creates a directory with a locked-down DACL: inheritance disabled, ACEs
# reset to current user + SYSTEM + Administrators (FullControl). Used by
# the filesystem-policy test so the agent user has no inherited access by
# default -- the test then proves the share_folders grant is what enables
# read access.
function Setup-LockedDownTestDir {
    param([string]$Path)

    New-Item -Path $Path -ItemType Directory -Force | Out-Null

    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $inherit = "ContainerInherit,ObjectInherit"
    foreach ($principal in @($currentUser, "SYSTEM", "Administrators")) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $principal, "FullControl", $inherit, "None", "Allow")))
    }
    Set-Acl -Path $Path -AclObject $acl
}

[System.Collections.ArrayList]$results = @()

# Filesystem-policy test scaffolding: a locked-down dir the test expects
# the agent to read via a readwritePaths grant. Setup runs at file scope,
# BEFORE the outer try and BEFORE any agent provision/deprovision cycles.
# Empirically, running Setup-LockedDownTestDir AFTER agent lifecycles have
# happened in this cmd.exe session causes Set-Acl to fail with
# SeSecurityPrivilege on non-elevated consoles; running it BEFORE works
# (state-aware uses this same ordering for its host-side dirs).
$FsTestRoot = 'C:\mxc_share_test_oneshot'
$FsMarkerContent = 'oneshot-marker-content'
Setup-LockedDownTestDir $FsTestRoot
$FsMarkerContent | Set-Content -Path (Join-Path $FsTestRoot 'marker.txt') -NoNewline

# Filter test scaffolding: same file-scope ordering as $FsTestRoot above.
# The outer-try finally also cleans this up between runs so a stale
# inheritance-disabled directory does not require SeSecurityPrivilege on
# re-run (Set-Acl on an existing inheritance-disabled directory writes
# the SACL slot, which non-elevated admins cannot do).
$FilterTestRoot = 'C:\mxc_filter_test_oneshot'
$FilterMarkerContent = 'oneshot-filter-marker-content'
Setup-LockedDownTestDir $FilterTestRoot
$FilterMarkerContent | Set-Content -Path (Join-Path $FilterTestRoot 'marker.txt') -NoNewline

try {

Write-Host "--- Tests ---" -ForegroundColor Cyan
# Setup for isolation_session_hello.json: cwd must exist before agent start.
New-Item -Path 'C:\mxc_workdir_test' -ItemType Directory -Force | Out-Null
$HostWhoami = (& whoami).Trim()
$null = $results.Add((Run-IsolationSessionTest "isolation_session_hello.json" `
    -OutputContains @("MYVAR=IsolationSessionTest", "CWD=C:\mxc_workdir_test") `
    -OutputLineNotEqual @($HostWhoami)))
# Same shape as hello.json but with experimental.isolation_session.configurationId=medium.
# Proves the Medium config-id end-to-ends through the one-shot path on the target build.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_hello_medium.json" `
    -OutputContains @("MYVAR=IsolationSessionTest", "CWD=C:\mxc_workdir_test") `
    -OutputLineNotEqual @($HostWhoami)))
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
# Filesystem policy: agent has a readwritePaths grant on $FsTestRoot which
# was locked-down and populated with a marker file at file scope above.
# The `type` exit being 0 + the marker content in stdout proves the grant
# was applied and the agent has read access.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_filesystem.json" `
    -OutputContains @($FsMarkerContent)))

# Filter test: readwritePaths contains both protected (C:\Windows, C:\) and
# non-protected ($FilterTestRoot, locked-down and populated at file scope
# above) entries. The wxc-exec filesystem-policy path filter (MXC issue
# #330) drops the protected entries silently, leaves the non-protected one
# in place, and provisioning continues. The `type ...marker.txt` exit being
# 0 + marker content in stdout proves the non-protected grant was applied
# (positive control); the absence of any error envelope proves the protected
# entries were dropped without surfacing.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_filtered.json" `
    -OutputContains @($FilterMarkerContent)))

# One-shot rejection: experimental.isolation_session.user is only honored on
# the state-aware path. validate_runner rejects any one-shot request that
# carries the user bundle so callers do not silently get a non-Entra agent.
$null = $results.Add((Run-IsolationSessionTest "isolation_session_one_shot_user_rejected.json" `
    -ExpectedExit -1 `
    -OutputContains @("user is not supported in one-shot mode")))

# ---------------- Concurrent one-shot test ----------------
#
# Three wxc-exec processes (A, B, C) run a per-agent PowerShell script
# from a shared rw-policy directory. Each script writes timestamped lines
# to its own X.log file: "X-started", "X-still-alive-1" .. "X-still-alive-N",
# "X-done", with one second between iterations. After all three wxc-execs
# exit, the test reads each agent's log file and asserts (a) the wxc-exec
# exited 0, (b) the log contains start / final-still-alive / done markers,
# (c) timestamps are monotonic. This decouples the regid-leak check from
# OS-side teardown timing -- if any of the three isolation sessions were
# torn down mid-run its log would be truncated, and if cleanup failed its
# wxc-exec exit code would be non-zero. A fresh fourth process (D) then
# proves the leak does not poison subsequent sandboxes either.
#
# Each launch is gated on the previously-launched agent's "X-started"
# line appearing in its log file. Polling the log file (not wxc-exec's
# stdout) avoids matching the --debug Logger's command-line echo. The
# barrier prevents the OS-side per-StartSessionAsync setup race where
# two StartSessionAsync calls landing within ~1-2s of each other leave
# the second isolation session unusable.

Write-Host ""
Write-Host "--- Concurrent one-shot ---" -ForegroundColor Cyan

# Shared rw directory the three agent PS1 scripts and X.log files live in.
# Each X.json grants the agent rw access to this path via
# policy.readwritePaths.
$concurrentLogDir = 'C:\mxc_concurrent_log'
Remove-Item -Recurse -Force $concurrentLogDir -ErrorAction SilentlyContinue
New-Item -Path $concurrentLogDir -ItemType Directory -Force | Out-Null

# wxc-exec stdout/stderr capture dir (preserved across runs for inspection;
# cleaned at the start of each run).
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
    # Clean up the shared agent log dir; the wxc-exec stdout/stderr
    # capture dir is preserved for post-run inspection (next run's
    # start-of-test cleanup will replace it).
    Remove-Item -Recurse -Force $concurrentLogDir -ErrorAction SilentlyContinue
    Write-Host "  (concurrent stdout/stderr preserved at: $concurrentTempRoot)" -ForegroundColor DarkGray
}

} finally {
    Remove-Item -Recurse -Force $FsTestRoot -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $FilterTestRoot -ErrorAction SilentlyContinue
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

Write-Host "`n==========================" -ForegroundColor Cyan
if ($failed -eq 0) {
    Write-Host "$passed/$total passed$(if ($skipped -gt 0) { ", $skipped skipped" })" -ForegroundColor Green
} else {
    Write-Host "$passed/$executed passed, $failed FAILED$(if ($skipped -gt 0) { " ($skipped skipped)" }):" -ForegroundColor Red
    $results | Where-Object { -not $_.Pass -and -not $_.Skipped } | ForEach-Object {
        Write-Host "  FAIL: $($_.Name) - $($_.Reason)" -ForegroundColor Red
    }
}

exit $(if ($failed -gt 0) { 1 } else { 0 })
