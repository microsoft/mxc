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
    Path to the test_configs directory. Defaults to ..\test_configs.

.EXAMPLE
    .\run_isolation_session_tests.ps1
    .\run_isolation_session_tests.ps1 -WxcExePath C:\test\wxc-exec.exe -ConfigDir C:\test
#>

param(
    [string]$WxcExePath,
    [string]$ConfigDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

if (-not $ConfigDir) {
    $ConfigDir = Join-Path $RepoRoot "test_configs"
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
        $output = & $WxcExec --experimental $configPath 2>&1 | Out-String
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
# the agent to read via a readwritePaths grant.
$FsTestRoot = 'C:\mxc_share_test_oneshot'
$FsMarkerContent = 'oneshot-marker-content'

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
# Filesystem policy: provision the agent with a readwritePaths grant on a
# locked-down host dir that has a pre-populated marker; agent reads it.
# The `type` exit being 0 + the marker content in stdout proves the grant
# was applied and the agent has read access.
Setup-LockedDownTestDir $FsTestRoot
$FsMarkerContent | Set-Content -Path (Join-Path $FsTestRoot 'marker.txt') -NoNewline
$null = $results.Add((Run-IsolationSessionTest "isolation_session_filesystem.json" `
    -OutputContains @($FsMarkerContent)))

} finally {
    Remove-Item -Recurse -Force $FsTestRoot -ErrorAction SilentlyContinue
}

# Summary
$passed = ($results | Where-Object { $_.Pass -and -not $_.Skipped }).Count
$failed = ($results | Where-Object { -not $_.Pass -and -not $_.Skipped }).Count
$skipped = ($results | Where-Object { $_.Skipped }).Count
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
