# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Runs IsolationSession state-aware lifecycle E2E tests. Companion to
    run_isolation_session_tests.ps1 --that script asserts the one-shot path;
    this script asserts the state-aware path (`phase` / `sandboxId` envelope
    style, multi-invocation lifecycle).

.DESCRIPTION
    Each test invokes wxc-exec.exe with a base64-encoded state-aware request
    envelope, parses the JSON response on stdout, and asserts on the
    envelope's `result` or `error` fields. Subsequent commits extend the
    skeleton with start, exec, stop, and deprovision tests; this revision
    asserts only the provision phase.

    This script must run INTERACTIVELY on the test host. The OS-side service
    calling-process identity check rejects network-logon tokens, so
    PSSession-driven invocations fail with Access Denied. Copy wxc-exec.exe
    and this script to the host, then run it directly in cmd.exe or
    PowerShell on that host.

    Prerequisite probes (skip if missing --not a failure):
      - IsoSessionApp.dll present in System32
      - WinRT activatable class IsoSessionOps registered
      - wxc-exec.exe responds to a state-aware request without
        backend_unavailable (catches feature-flag-off builds)

.PARAMETER WxcExePath
    Path to wxc-exec.exe. Default probes the host-arch target dir, then
    other-arch target dir, then the default release/debug dirs.

.PARAMETER ConfigDir
    Directory holding the state-aware request fixture JSON files. Defaults
    to <repo>/test_configs. Override on the VM where the deployed layout
    differs from the repo layout.

.EXAMPLE
    .\run_isolation_session_state_aware_tests.ps1
    .\run_isolation_session_state_aware_tests.ps1 -WxcExePath C:\test\wxc-exec.exe -ConfigDir C:\test\test_configs
#>

param(
    [string]$WxcExePath,
    [string]$ConfigDir
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

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
    Write-Host "Build with: cargo build --release --features isolation_session --target $HostTarget" -ForegroundColor Yellow
    Write-Host "Or pass -WxcExePath explicitly." -ForegroundColor Yellow
    exit 1
}

Write-Host "`nIsolationSession State-Aware E2E Tests" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "Binary: $WxcExec`n" -ForegroundColor Gray

# ---------------- Prerequisite probes ----------------

if (-not (Test-Path 'C:\Windows\System32\IsoSessionApp.dll')) {
    Write-Host "SKIPPED: IsoSessionApp.dll not present in System32" -ForegroundColor Yellow
    exit 0
}

$IsoSessionOpsKey = "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.AI.IsolationSession.IsoSessionOps"
if (-not (Test-Path $IsoSessionOpsKey)) {
    Write-Host "SKIPPED: Windows.AI.IsolationSession.IsoSessionOps WinRT class not registered" -ForegroundColor Yellow
    exit 0
}

# ---------------- Helpers ----------------

# Resolve the directory holding state-aware request fixtures. The -ConfigDir
# CLI parameter wins when supplied; otherwise default to <repo>/test_configs
# computed from $RepoRoot.
if (-not $ConfigDir) {
    $ConfigDir = Join-Path $RepoRoot "test_configs"
}

# Encode a state-aware request envelope and run wxc-exec against it. The
# request comes either from an in-line hashtable or from a static JSON
# fixture file under test_configs/ (for the project-wide "test scenarios are
# version-controlled JSON" pattern). When the fixture contains the
# placeholder `{{SANDBOX_ID}}`, the caller must supply -SandboxId so it can
# be substituted before the request is base64-encoded. Returns a hashtable
# with stdout / stderr / exitCode for the caller to assert on.
function Invoke-StateAware {
    param(
        [hashtable]$Request,
        [string]$ConfigFile,
        [string]$SandboxId,
        [switch]$Experimental
    )

    if ($ConfigFile) {
        $path = Join-Path $ConfigDir $ConfigFile
        if (-not (Test-Path $path)) {
            throw "Config fixture not found: $path"
        }
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

    $argList = @()
    if ($Experimental.IsPresent) { $argList += '--experimental' }
    $argList += @('--config-base64', $b64)

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        # Start-Process redirects to file so we can capture both streams without
        # ConPTY interleaving --wxc-exec's stdout must be a single envelope.
        $proc = Start-Process -FilePath $WxcExec -ArgumentList $argList `
            -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile `
            -NoNewWindow -PassThru -Wait
        @{
            ExitCode = $proc.ExitCode
            Stdout   = (Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue)
            Stderr   = (Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue)
        }
    } finally {
        Remove-Item $stdoutFile -ErrorAction SilentlyContinue
        Remove-Item $stderrFile -ErrorAction SilentlyContinue
    }
}

# Parses the wxc-exec stdout envelope and returns the parsed object, or
# $null if the stdout is not valid JSON.
function Parse-Envelope {
    param([string]$Stdout)
    if ([string]::IsNullOrWhiteSpace($Stdout)) { return $null }
    try { $Stdout | ConvertFrom-Json } catch { $null }
}

# Returns "result" / "error" / "<empty>" describing which arm of the envelope
# is present. Useful for failure messages.
function Envelope-Arm {
    param($Envelope)
    if ($null -eq $Envelope) { return '<empty>' }
    if ($Envelope.PSObject.Properties.Name -contains 'result') { return 'result' }
    if ($Envelope.PSObject.Properties.Name -contains 'error') { return 'error' }
    '<unknown>'
}

# ---------------- Backend-availability probe ----------------

# Sends a state-aware provision request and surfaces a `backend_unavailable`
# envelope as a SKIP. This catches feature-flag-off builds without raising
# false test failures.
$probe = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision.json' -Experimental
$probeEnv = Parse-Envelope -Stdout $probe.Stdout
if ($null -ne $probeEnv -and $probeEnv.error.code -eq 'backend_unavailable') {
    Write-Host "SKIPPED: wxc-exec reports backend_unavailable (likely built without --features isolation_session)" -ForegroundColor Yellow
    exit 0
}

# ---------------- Tests ----------------

$script:TestResults = @()
$script:currentTestPassed = $true
$script:currentTestFirstFailReason = $null

# Records assertion outcomes for the active Run-StateAwareTest. Per-assertion
# detail is still printed inline so failures show exactly which dimension
# broke; the test as a whole passes iff every assertion in its body passed.
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

# Wraps a logical test (one phase, one phase-pair, or one multi-exec
# scenario). Prints the test name as a section header, runs the body
# (which uses Assert-True for per-dimension checks), and records one
# pass/fail entry in TestResults so the final summary can match the
# project's other PowerShell runners. Returns the overall pass state so
# callers can gate subsequent tests.
function Run-StateAwareTest {
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    Write-Host ""
    Write-Host "[$Name]" -ForegroundColor Cyan
    $script:currentTestPassed = $true
    $script:currentTestFirstFailReason = $null
    & $Body
    $script:TestResults += [pscustomobject]@{
        Name   = $Name
        Passed = $script:currentTestPassed
        Reason = $script:currentTestFirstFailReason
    }
    return $script:currentTestPassed
}

# try-finally wraps the lifecycle so any mid-flow failure still triggers a
# best-effort deprovision. Mirrors the defensive cleanup in
# IsolationSessionRunner::execute -- failed runs do not leak Indefinite-
# lifetime agent users across test runs.
$script:sandboxId = $null
$deprovisionedOk = $false
try {

    # Test 1: provision returns iso:wxc-<8-hex> and a backend_unavailable-free
    # envelope.
    Run-StateAwareTest "provision (sandbox_id format)" {
        $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision.json' -Experimental
        $envObj = Parse-Envelope -Stdout $r.Stdout
        $arm = Envelope-Arm $envObj
        if ($arm -ne 'result') {
            Write-Host "  Envelope arm: $arm" -ForegroundColor Red
            Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
            Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
            Assert-True $false "provision returned a result envelope"
        } else {
            Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            $script:sandboxId = $envObj.result.sandboxId
            $agentUserName = $envObj.result.metadata.agentUserName
            Assert-True ($script:sandboxId -match '^iso:wxc-[0-9a-f]{8}$') "sandbox_id matches iso:wxc-<8-hex> ($script:sandboxId)"
            Assert-True ($null -ne $agentUserName) "metadata.agentUserName is present ($agentUserName)"
        }
    } | Out-Null

    # Test 2: start succeeds against the provisioned sandbox. Exercises the
    # multi-invocation pattern -- provision was a separate wxc-exec process;
    # this is a fresh wxc-exec process consuming the same sandbox_id.
    $startedOk = $false
    if ($null -ne $script:sandboxId) {
        $startedOk = Run-StateAwareTest "start (provision + start sequence)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start.json' -SandboxId $script:sandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Write-Host "  Envelope arm: $arm" -ForegroundColor Red
                Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
                Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
                Assert-True $false "start returned a result envelope"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
                # Start has no metadata in v1 -- `result` should be an empty object.
                Assert-True ($null -eq $envObj.result.metadata) "result.metadata is absent (no start metadata in v1)"
            }
        }
    }

    # Test 3: exec runs a command in the started session. Output streams live
    # (the backend reuses the one-shot relay path) so stdout from this
    # wxc-exec invocation is the script's output rather than a JSON envelope.
    $execedOk = $false
    if ($startedOk) {
        $execedOk = Run-StateAwareTest "exec (basic)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_basic.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            Assert-True ($r.Stdout -match 'state-aware-exec-marker') `
                "stdout contains the script's output (streamed live, not enveloped)"
            # Exec on success does not emit a JSON envelope on stdout -- the
            # SDK discriminates between exec success (raw stdout) and dispatch
            # failure (JSON envelope) using exit code + envelope-parseability.
            $maybeEnv = Parse-Envelope -Stdout $r.Stdout
            Assert-True ($null -eq $maybeEnv -or $null -eq $maybeEnv.error) `
                "stdout is not a state-aware error envelope on success"
        }
    }

    # Test 4: filesystem state continuity across separate wxc-exec invocations
    # against the same sandbox_id. exec #1 writes a marker file to the agent
    # user's TEMP, exec #2 reads it back. Each exec is a fresh wxc-exec
    # process consuming the same sandbox_id, exercising the cross-process
    # state-aware path.
    if ($execedOk) {
        Run-StateAwareTest "multi-exec (filesystem state continuity)" {
            $w = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_write_marker.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($w.ExitCode -eq 0) "exec #1 (write) exit code = 0"
            $rd = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_read_marker.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($rd.ExitCode -eq 0) "exec #2 (read) exit code = 0"
            Assert-True ($rd.Stdout -match 'multi-exec-marker-content') `
                "exec #2 stdout contains the marker exec #1 wrote (state preserved across wxc-exec processes)"
        } | Out-Null
    }

    # Test 5: exit code propagation across multiple exec invocations. Three
    # invocations exit with 1, 2, 0 in sequence. Each invocation must report
    # its own exit code (catches stale exit code leaking between calls), and
    # the third exec succeeding after two non-zero exits proves a non-zero
    # exit doesn't leave the session in a broken state.
    if ($execedOk) {
        Run-StateAwareTest "multi-exec (exit code propagation)" {
            foreach ($pair in @(
                    @{ file = 'isolation_session_state_aware_exec_exit_1.json'; code = 1 },
                    @{ file = 'isolation_session_state_aware_exec_exit_2.json'; code = 2 },
                    @{ file = 'isolation_session_state_aware_exec_exit_0.json'; code = 0 }
                )) {
                $r = Invoke-StateAware -ConfigFile $pair.file -SandboxId $script:sandboxId -Experimental
                Assert-True ($r.ExitCode -eq $pair.code) `
                    "exec 'exit $($pair.code)' propagates exit code $($pair.code) (got $($r.ExitCode))"
            }
        } | Out-Null
    }

    # Test 6: working_directory wire-field plumbing. Sets cwd via the wire
    # request, runs `cd` (cmd built-in: prints current dir), asserts stdout
    # starts with the requested path.
    if ($execedOk) {
        Run-StateAwareTest "multi-exec (cwd plumbing)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_cwd.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            Assert-True ($r.Stdout -match '^C:\\Windows') `
                "stdout starts with C:\Windows (cwd wire field honored on state-aware path)"
        } | Out-Null
    }

    # Test 7: wire-format env per-invocation. Three invocations: initial,
    # modified, absent. Verifies (a) each invocation receives its own env
    # block, (b) the second wire request actually overrides the first (no
    # cached env block), (c) the third invocation does NOT see leakage from
    # prior calls.
    if ($execedOk) {
        Run-StateAwareTest "multi-exec (wire-format env per-invocation)" {
            $rInit = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_env_initial.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($rInit.ExitCode -eq 0) "initial exit code = 0"
            Assert-True ($rInit.Stdout -match 'initial-value') "initial value reaches the agent"

            $rMod = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_env_modified.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($rMod.ExitCode -eq 0) "modified exit code = 0"
            Assert-True ($rMod.Stdout -match 'modified-value') "second wire request overrides the first"
            Assert-True ($rMod.Stdout -notmatch 'initial-value') "no cached env block from prior call"

            # No env block -- the agent inherits its profile env only. echo of
            # an unset variable in cmd.exe prints `%MY_SA_ENV%` literally; the
            # checks below catch leakage from the prior call.
            $rAbsent = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_env_absent.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($rAbsent.ExitCode -eq 0) "absent exit code = 0"
            Assert-True ($rAbsent.Stdout -match '%MY_SA_ENV%') `
                "literal %MY_SA_ENV% in stdout (var unset, no leak from prior call)"
            Assert-True ($rAbsent.Stdout -notmatch 'modified-value') `
                "no leak of modified-value into env-absent invocation"
        } | Out-Null
    }

    # Test 8: HKCU env var persistence and modification. Tests a different
    # persistence layer from filesystem (Test 4): the agent user's HKCU
    # registry. setx writes to HKCU\Environment; a fresh cmd.exe started in a
    # subsequent invocation reads its env block from the registry at startup,
    # so the persisted value should appear. Then we modify it and verify the
    # modification carries forward.
    if ($execedOk) {
        Run-StateAwareTest "multi-exec (HKCU env persistence + modification)" {
            foreach ($step in @(
                    @{ file = 'isolation_session_state_aware_exec_setx_initial.json';  expect = $null;              label = 'setx initial' },
                    @{ file = 'isolation_session_state_aware_exec_read_persist.json';  expect = 'initial-persist';  label = 'fresh cmd reads HKCU' },
                    @{ file = 'isolation_session_state_aware_exec_setx_modified.json'; expect = $null;              label = 'setx modified' },
                    @{ file = 'isolation_session_state_aware_exec_read_persist.json';  expect = 'modified-persist'; label = 'fresh cmd reads modified HKCU' }
                )) {
                $r = Invoke-StateAware -ConfigFile $step.file -SandboxId $script:sandboxId -Experimental
                Assert-True ($r.ExitCode -eq 0) "$($step.label): exit code = 0"
                if ($null -ne $step.expect) {
                    Assert-True ($r.Stdout -match [regex]::Escape($step.expect)) `
                        "$($step.label): stdout contains '$($step.expect)'"
                }
            }
        } | Out-Null
    }

    # Test 9: stop closes the started session. Skipped unless exec succeeded
    # (so we know we have a truly running session to stop, not a half-set-up
    # one).
    $stoppedOk = $false
    if ($execedOk) {
        $stoppedOk = Run-StateAwareTest "stop (full lifecycle through stop)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_stop.json' -SandboxId $script:sandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Write-Host "  Envelope arm: $arm" -ForegroundColor Red
                Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
                Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
                Assert-True $false "stop returned a result envelope"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
                Assert-True ($null -eq $envObj.result.metadata) "result.metadata is absent (no stop metadata in v1)"
            }
        }
    }

    # Test 10: deprovision tears down the agent user and unregisters the
    # client. After this test, $sandboxId is no longer addressable -- the
    # finally block below skips its cleanup pass when this test ran.
    if ($stoppedOk) {
        $deprovPassed = Run-StateAwareTest "deprovision (full lifecycle through deprovision)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:sandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Write-Host "  Envelope arm: $arm" -ForegroundColor Red
                Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
                Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
                Assert-True $false "deprovision returned a result envelope"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
                Assert-True ($null -eq $envObj.result.metadata) "result.metadata is absent (no deprovision metadata in v1)"
            }
        }
        if ($deprovPassed) { $deprovisionedOk = $true }
    }

    # Test 11: provision now honours readwritePaths and readonlyPaths.
    # Throwaway sandbox -- not used by later tests. Comprehensive
    # filesystem-policy lifecycle (write to rw, read from ro, etc.) lands
    # in the Lifecycle B suite added separately.
    Run-StateAwareTest "provision (with filesystem policy accepted)" {
        # share_folders requires the calling MXC process to have WRITE_DAC
        # on each target path; user-owned dirs satisfy that.
        $rwDir = 'C:\mxc_share_test_provision\rw'
        $roDir = 'C:\mxc_share_test_provision\ro'
        New-Item -Path $rwDir -ItemType Directory -Force | Out-Null
        New-Item -Path $roDir -ItemType Directory -Force | Out-Null

        $throwawaySandboxId = $null
        try {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision_with_filesystem.json' -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Write-Host "  Envelope arm: $arm" -ForegroundColor Red
                Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
                Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
                Assert-True $false "provision-with-filesystem returned a result envelope"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
                $throwawaySandboxId = $envObj.result.sandboxId
                Assert-True ($throwawaySandboxId -match '^iso:wxc-[0-9a-f]{8}$') `
                    "sandbox_id matches iso:wxc-<8-hex> ($throwawaySandboxId)"
            }
        } finally {
            if ($throwawaySandboxId) {
                $null = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $throwawaySandboxId -Experimental
            }
            Remove-Item -Recurse -Force 'C:\mxc_share_test_provision' -ErrorAction SilentlyContinue
        }
    } | Out-Null

    # Test 12: stale_id detection. The just-deprovisioned $sandboxId is now
    # unknown to the OS-side service. Calling stop against it must surface
    # `MxcError::StaleId` (wire `error.code = "stale_id"`), proving the
    # Rust-layer ERROR_NOT_FOUND HRESULT detection is wired through the
    # backend impl all the way to the wire envelope.
    if ($deprovisionedOk) {
        Run-StateAwareTest "stale_id (stop on previously-deprovisioned sandbox)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_stop.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (stop on stale sandbox failed as expected)"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            Assert-True ($null -ne $envObj) "stdout is a parseable envelope"
            $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
            Assert-True ($code -eq 'stale_id') "error.code is 'stale_id' (got '$code')"
        } | Out-Null
    }

} finally {
    # Best-effort cleanup. If the suite reached the deprovision test and it
    # succeeded, the agent user is already torn down -- nothing to do. If
    # the suite failed mid-flow, this still runs so a leaked Indefinite-
    # lifetime agent user does not survive across test runs.
    if ($null -ne $script:sandboxId -and -not $deprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:sandboxId" -ForegroundColor DarkGray
        try {
            $cleanupResult = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:sandboxId -Experimental
            if ($cleanupResult.ExitCode -eq 0) {
                Write-Host "  cleanup deprovision succeeded" -ForegroundColor DarkGray
            } else {
                Write-Host "  cleanup deprovision exit $($cleanupResult.ExitCode); stdout: $($cleanupResult.Stdout)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  cleanup deprovision threw: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}

# ---------------- Lifecycle C: Medium configurationId ----------------

# A separate, throwaway sandbox that exercises the Medium config-id end-to-end.
# Lifecycle A defaulted to Composable (no `experimental.isolation_session.start`
# block). This lifecycle proves Medium also works on the target OS build:
# provision -> start with configurationId=medium -> one echo exec -> stop ->
# deprovision. Independent of Lifecycle A's sandbox so a failure here does not
# pollute the main lifecycle's results.
$script:mediumSandboxId = $null
$mediumDeprovisionedOk = $false
try {
    Run-StateAwareTest "Medium: provision" {
        $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision.json' -Experimental
        $envObj = Parse-Envelope -Stdout $r.Stdout
        $arm = Envelope-Arm $envObj
        if ($arm -ne 'result') {
            Write-Host "  Envelope arm: $arm" -ForegroundColor Red
            Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
            Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
            Assert-True $false "Medium provision returned a result envelope"
        } else {
            Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            $script:mediumSandboxId = $envObj.result.sandboxId
            Assert-True ($script:mediumSandboxId -match '^iso:wxc-[0-9a-f]{8}$') `
                "sandbox_id matches iso:wxc-<8-hex> ($script:mediumSandboxId)"
        }
    } | Out-Null

    $mediumStartedOk = $false
    if ($null -ne $script:mediumSandboxId) {
        $mediumStartedOk = Run-StateAwareTest "Medium: start (configurationId=medium)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start_medium.json' -SandboxId $script:mediumSandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Write-Host "  Envelope arm: $arm" -ForegroundColor Red
                Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
                Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
                Assert-True $false "Medium start returned a result envelope"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            }
        }
    }

    $mediumExecedOk = $false
    if ($mediumStartedOk) {
        $mediumExecedOk = Run-StateAwareTest "Medium: exec (basic echo)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_basic.json' -SandboxId $script:mediumSandboxId -Experimental
            Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            Assert-True ($r.Stdout -match 'state-aware-exec-marker') `
                "stdout contains the script's output (Medium config supports process launch)"
        }
    }

    $mediumStoppedOk = $false
    if ($mediumExecedOk) {
        $mediumStoppedOk = Run-StateAwareTest "Medium: stop" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_stop.json' -SandboxId $script:mediumSandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Write-Host "  Envelope arm: $arm" -ForegroundColor Red
                Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
                Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
                Assert-True $false "Medium stop returned a result envelope"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            }
        }
    }

    if ($mediumStoppedOk) {
        $mediumDeprovPassed = Run-StateAwareTest "Medium: deprovision" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:mediumSandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Write-Host "  Envelope arm: $arm" -ForegroundColor Red
                Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
                Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
                Assert-True $false "Medium deprovision returned a result envelope"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            }
        }
        if ($mediumDeprovPassed) { $mediumDeprovisionedOk = $true }
    }
} finally {
    if ($null -ne $script:mediumSandboxId -and -not $mediumDeprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:mediumSandboxId" -ForegroundColor DarkGray
        try {
            $cleanupResult = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:mediumSandboxId -Experimental
            if ($cleanupResult.ExitCode -eq 0) {
                Write-Host "  cleanup deprovision succeeded" -ForegroundColor DarkGray
            } else {
                Write-Host "  cleanup deprovision exit $($cleanupResult.ExitCode); stdout: $($cleanupResult.Stdout)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  cleanup deprovision threw: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}

# ---------------- Summary ----------------

$total  = $script:TestResults.Count
$failed = ($script:TestResults | Where-Object { -not $_.Passed }).Count
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
