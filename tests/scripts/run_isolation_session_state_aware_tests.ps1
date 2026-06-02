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
    to <repo>/tests/configs. Override on the VM where the deployed layout
    differs from the repo layout.

.EXAMPLE
    .\run_isolation_session_state_aware_tests.ps1
    .\run_isolation_session_state_aware_tests.ps1 -WxcExePath C:\test\wxc-exec.exe -ConfigDir C:\test\tests\configs
#>

param(
    [string]$WxcExePath,
    [string]$ConfigDir
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
# CLI parameter wins when supplied; otherwise default to <repo>/tests/configs
# computed from $RepoRoot.
if (-not $ConfigDir) {
    $ConfigDir = Join-Path $RepoRoot "tests\configs"
}

# Encode a state-aware request envelope and run wxc-exec against it. The
# request comes either from an in-line hashtable or from a static JSON
# fixture file under tests/configs/ (for the project-wide "test scenarios are
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
        # Coerce Stdout/Stderr to a single non-null string. Get-Content -Raw
        # on an empty / missing file returns $null, and downstream test
        # bodies use `-match` / `-notmatch` which behave differently on
        # null vs. on a string -- always returning Boolean for a string,
        # and an array when the LHS is null and not all branches collapse.
        # Casting upfront makes the contract simple: $r.Stdout is a string.
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

# Creates a directory with a locked-down DACL: inheritance disabled,
# ACEs reset to current user + SYSTEM + Administrators (FullControl).
# Subdirectories created inside inherit this ACL automatically.
#
# Why: by default, dirs under C:\ inherit Authenticated Users / Users
# read+execute ACEs. The agent user is a member of those groups, so
# without lockdown the "control" test (agent has no share, so cannot
# access the dir) would spuriously pass and the readonly-deny test (B6)
# would not actually prove the ACE granted is read-only.
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

# ---------------- Backend-availability probe ----------------

# Sends a state-aware provision request and surfaces a `backend_unavailable`
# envelope as a SKIP. This catches feature-flag-off builds without raising
# false test failures. On a healthy build the probe successfully creates an
# agent user, so we immediately deprovision the throwaway sandbox -- without
# this, every test run would leak one local agent user.
$probe = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision.json' -Experimental
$probeEnv = Parse-Envelope -Stdout $probe.Stdout
if ($null -ne $probeEnv -and $probeEnv.error.code -eq 'backend_unavailable') {
    Write-Host "SKIPPED: wxc-exec reports backend_unavailable (likely built without --features isolation_session)" -ForegroundColor Yellow
    exit 0
}
if ($null -ne $probeEnv -and $null -ne $probeEnv.result -and $null -ne $probeEnv.result.sandboxId) {
    $probeSandboxId = [string]$probeEnv.result.sandboxId
    $probeAgent = if ($probeEnv.result.metadata) { [string]$probeEnv.result.metadata.agentUserName } else { '<absent>' }
    Write-Host "Backend probe: provisioned $probeSandboxId (agentUserName=$probeAgent), deprovisioning ..." -ForegroundColor DarkGray
    $probeDeprov = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $probeSandboxId -Experimental
    if ($probeDeprov.ExitCode -ne 0) {
        Write-Host "WARN: probe deprovision returned exit $($probeDeprov.ExitCode); local user $probeAgent may persist" -ForegroundColor Yellow
        Write-Host "  Stdout: $($probeDeprov.Stdout)" -ForegroundColor Gray
    }
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
#
# Exceptions thrown from the body are caught and recorded as a failure
# of THIS test only -- the suite keeps running. Without this guard a
# single misbehaving assertion (e.g., a regex op that returns an array
# and trips Assert-True's [bool] coercion) would abort every test that
# would have run after it, including cleanup paths.
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

# Test-dir setup. Lifecycle A's "control" test, Lifecycle B's full
# filesystem-policy lifecycle, and the grant-scope check all run against
# a single locked-down host directory tree:
#
#   C:\mxc_share_test\        (locked-down: current user + SYSTEM + Admins)
#     rw\                     (inherits parent ACL; granted to B agent as rw)
#     ro\
#       marker.txt            (pre-populated; granted to B agent as ro)
#     restricted\
#       marker.txt            (pre-populated; NOT granted to B agent --
#                              proves grants are path-specific, not blanket
#                              on the parent)
#
# The lockdown is essential -- without it the agent user (a member of
# Authenticated Users / Users) would inherit read access by default, so
# the control test would not actually demonstrate that share_folders is
# what enables access in Lifecycle B.
$script:TestRoot = 'C:\mxc_share_test'
$script:FilterTestRoot = 'C:\mxc_filter_test'
$script:RoMarkerContent = 'readonly-marker-content'
$script:RestrictedMarkerContent = 'restricted-marker-content'
Setup-LockedDownTestDir $script:TestRoot
New-Item -Path "$script:TestRoot\rw" -ItemType Directory -Force | Out-Null
New-Item -Path "$script:TestRoot\ro" -ItemType Directory -Force | Out-Null
New-Item -Path "$script:TestRoot\restricted" -ItemType Directory -Force | Out-Null
$script:RoMarkerContent | Set-Content -Path "$script:TestRoot\ro\marker.txt" -NoNewline
$script:RestrictedMarkerContent | Set-Content -Path "$script:TestRoot\restricted\marker.txt" -NoNewline
Setup-LockedDownTestDir $script:FilterTestRoot
New-Item -Path "$script:FilterTestRoot\rw" -ItemType Directory -Force | Out-Null

# Outer try-finally: ensures the host directory tree is removed even if a
# test panics. The summary at the end runs after the cleanup.
try {

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

    # Test 1b: provision rejects non-empty deniedPaths. Backend has no Deny
    # ACE primitive, so any deniedPaths request must be rejected (consistent
    # with how readwrite/readonly are accepted but denied is not). Uses a
    # separate throwaway sandbox -- never reaches the OS-side service since
    # validate_provision_policy rejects up-front, so no cleanup needed.
    Run-StateAwareTest "provision (deniedPaths rejected)" {
        $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision_rejected_denied.json' -Experimental
        Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
        $envObj = Parse-Envelope -Stdout $r.Stdout
        Assert-True ($null -ne $envObj) "stdout is a parseable envelope"
        $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
        Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
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

    # Test 2b: control -- the main sandbox has no fs grants, so the agent
    # user must NOT be able to read C:\mxc_share_test\ro\marker.txt. The
    # locked-down DACL (no Authenticated Users / Users) is what makes this
    # check meaningful: without it the agent would inherit read access via
    # default group membership. Pairs with Lifecycle B's B5, where the same
    # read SUCCEEDS because B's sandbox was provisioned with readonlyPaths.
    if ($startedOk) {
        Run-StateAwareTest "control (unshared path inaccessible)" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_read_readonly.json' -SandboxId $script:sandboxId -Experimental
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (read denied)"
        } | Out-Null
    }

    # Test 2c: start rejects requests that carry filesystem policy. Filesystem
    # policy is bound to provision and immutable thereafter; a non-empty
    # readwritePaths on a start request must be rejected with policy_validation.
    if ($startedOk) {
        Run-StateAwareTest "start (filesystem policy rejected post-provision)" {
            $req = @{
                phase     = 'start'
                sandboxId = $script:sandboxId
                filesystem = @{ readwritePaths = @('C:\mxc_share_test\rw') }
            }
            $r = Invoke-StateAware -Request $req -Experimental
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
            Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
        } | Out-Null
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

    # Test 3b: exec rejects requests that carry filesystem policy. Same
    # rationale as the start-rejection check above.
    if ($execedOk) {
        Run-StateAwareTest "exec (filesystem policy rejected post-provision)" {
            $req = @{
                phase     = 'exec'
                sandboxId = $script:sandboxId
                process    = @{ commandLine = 'echo unused' }
                filesystem = @{ readwritePaths = @('C:\mxc_share_test\rw') }
            }
            $r = Invoke-StateAware -Request $req -Experimental
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
            Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
        } | Out-Null
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

    # Test 8b: stop rejects requests that carry filesystem policy. Runs
    # BEFORE the actual stop test so the sandbox is still in started state.
    if ($execedOk) {
        Run-StateAwareTest "stop (filesystem policy rejected post-provision)" {
            $req = @{
                phase     = 'stop'
                sandboxId = $script:sandboxId
                filesystem = @{ readwritePaths = @('C:\mxc_share_test\rw') }
            }
            $r = Invoke-StateAware -Request $req -Experimental
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
            Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
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

    # Test 9b: deprovision rejects requests that carry filesystem policy.
    # Runs BEFORE the actual deprovision so the sandbox still exists.
    if ($stoppedOk) {
        Run-StateAwareTest "deprovision (filesystem policy rejected post-provision)" {
            $req = @{
                phase     = 'deprovision'
                sandboxId = $script:sandboxId
                filesystem = @{ readwritePaths = @('C:\mxc_share_test\rw') }
            }
            $r = Invoke-StateAware -Request $req -Experimental
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (policy rejected)"
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
            Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
        } | Out-Null
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

    # Test 11: stale_id detection. The just-deprovisioned $sandboxId is now
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

# ---------------- Lifecycle B: Filesystem policy ----------------

# A separate sandbox provisioned with both readwritePaths and readonlyPaths,
# exercising the full read/write semantics of share_folders end-to-end:
#   - rw grant: agent can write a file the host then sees, and read it back
#   - ro grant: agent can read pre-populated host content, but cannot write
#   - no grant: a sibling subdir (restricted) under the same parent is
#     inaccessible -- proves grants are path-specific, not blanket on parent
$script:fsSandboxId = $null
$fsDeprovisionedOk = $false
try {
    $fsProvisionedOk = Run-StateAwareTest "filesystem: provision (rw + ro)" {
        $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision_with_filesystem.json' -Experimental
        $envObj = Parse-Envelope -Stdout $r.Stdout
        $arm = Envelope-Arm $envObj
        if ($arm -ne 'result') {
            Write-Host "  Envelope arm: $arm" -ForegroundColor Red
            Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
            Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
            Assert-True $false "filesystem provision returned a result envelope"
        } else {
            Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            $script:fsSandboxId = $envObj.result.sandboxId
            Assert-True ($script:fsSandboxId -match '^iso:wxc-[0-9a-f]{8}$') `
                "sandbox_id matches iso:wxc-<8-hex> ($script:fsSandboxId)"
            $agentUserName = if ($envObj.result.metadata) { [string]$envObj.result.metadata.agentUserName } else { '<absent>' }
            Write-Host "  filesystem provisioned: agentUserName=$agentUserName" -ForegroundColor DarkGray
        }
    }

    $fsStartedOk = $false
    if ($fsProvisionedOk) {
        $fsStartedOk = Run-StateAwareTest "filesystem: start" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start.json' -SandboxId $script:fsSandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Assert-True $false "filesystem start returned a result envelope (got $arm)"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0 on success"
            }
        }
    }

    if ($fsStartedOk) {
        Run-StateAwareTest "filesystem: exec write-to-rw" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_write_shared.json' -SandboxId $script:fsSandboxId -Experimental
            Assert-True ($r.ExitCode -eq 0) "exit code = 0 (agent wrote successfully)"
            Assert-True ($r.Stdout -match 'shared-write-content') `
                "agent's own type-back read succeeded ('shared-write-content' in stdout)"
            $hostPath = Join-Path $script:TestRoot 'rw\agent_wrote.txt'
            $hostExists = Test-Path $hostPath
            Assert-True $hostExists "host sees the file the agent wrote ($hostPath)"
            if ($hostExists) {
                $hostContent = Get-Content $hostPath -Raw
                Assert-True ($hostContent -match 'shared-write-content') `
                    "host file contains 'shared-write-content'"
            }
        } | Out-Null

        Run-StateAwareTest "filesystem: exec read-from-rw" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_read_shared.json' -SandboxId $script:fsSandboxId -Experimental
            Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            Assert-True ($r.Stdout -match 'shared-write-content') `
                "agent reads back the file it wrote earlier"
        } | Out-Null

        Run-StateAwareTest "filesystem: exec read-from-ro" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_read_readonly.json' -SandboxId $script:fsSandboxId -Experimental
            Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            $expected = [regex]::Escape($script:RoMarkerContent)
            Assert-True ($r.Stdout -match $expected) `
                "agent reads pre-populated marker.txt ('$($script:RoMarkerContent)')"
        } | Out-Null

        Run-StateAwareTest "filesystem: exec write-to-ro denied" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_write_readonly_denied.json' -SandboxId $script:fsSandboxId -Experimental
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (write to read-only path failed)"
            $hostPath = Join-Path $script:TestRoot 'ro\agent_should_fail.txt'
            Assert-True (-not (Test-Path $hostPath)) `
                "host did not see the file (write was actually denied, not silently swallowed)"
        } | Out-Null

        Run-StateAwareTest "filesystem: exec read-from-restricted denied" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_exec_read_restricted.json' -SandboxId $script:fsSandboxId -Experimental
            Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (read from unshared sibling failed)"
            $stdoutText = if ($null -eq $r.Stdout) { "" } else { [string]$r.Stdout }
            $leaked = $stdoutText.Contains($script:RestrictedMarkerContent)
            Assert-True (-not $leaked) `
                "stdout does NOT contain the restricted marker content (grant is path-specific, not blanket)"
        } | Out-Null
    }

    $fsStoppedOk = $false
    if ($fsStartedOk) {
        $fsStoppedOk = Run-StateAwareTest "filesystem: stop" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_stop.json' -SandboxId $script:fsSandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Assert-True $false "filesystem stop returned a result envelope (got $arm)"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            }
        }
    }

    if ($fsStoppedOk) {
        $fsDeprovPassed = Run-StateAwareTest "filesystem: deprovision" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:fsSandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Assert-True $false "filesystem deprovision returned a result envelope (got $arm)"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            }
        }
        if ($fsDeprovPassed) { $fsDeprovisionedOk = $true }
    }
} finally {
    if ($null -ne $script:fsSandboxId -and -not $fsDeprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:fsSandboxId" -ForegroundColor DarkGray
        try {
            $null = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:fsSandboxId -Experimental
        } catch {
            Write-Host "  cleanup deprovision threw: $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}

# ---------------- Lifecycle BF: filesystem-policy path filter ----------------
#
# Verifies the wxc-exec filesystem-policy path filter (MXC issue #330).
# Provisions with a mix of protected (drive root, C:\Windows) and
# non-protected (C:\mxc_filter_test\rw) paths in readwritePaths. Expected:
# provision succeeds (the filter is silent -- no error returned, no
# filter-specific metadata field added), the protected paths get NO new
# agent ACE (filter dropped them before ShareFolderBatchAsync), and the
# non-protected path receives the agent's ACE as normal (positive control:
# legitimate path not accidentally dropped).
#
# Test-dir setup happens at file scope alongside $script:TestRoot so the
# outer try-finally can clean both up between runs; without that cleanup
# a stale $script:FilterTestRoot from a prior run causes Setup-LockedDownTestDir
# to fail with SeSecurityPrivilege (Set-Acl on an existing
# inheritance-disabled directory writes the SACL slot, which non-elevated
# admins cannot do).

# Translates a local-account name to its SID. Returns $null if the
# translation fails (e.g., the user no longer exists).
function Get-LocalAccountSid {
    param([string]$Name)
    try {
        $nt = New-Object System.Security.Principal.NTAccount($Name)
        $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        $null
    }
}

# Returns $true if the ACL on $Path has any access rule whose
# IdentityReference translates to $TargetSid.
function Test-AclContainsSid {
    param([string]$Path, [string]$TargetSid)
    $acl = Get-Acl $Path
    foreach ($ace in $acl.Access) {
        try {
            $aceSid = $ace.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
            if ($aceSid -eq $TargetSid) { return $true }
        } catch {
            # IdentityReference may be untranslatable (orphan SID etc.); skip.
        }
    }
    $false
}

$script:filterSandboxId = $null
$script:filterAgentUserName = $null
$filterDeprovisionedOk = $false
try {
    $filterProvisionedOk = Run-StateAwareTest "filter: provision (protected + non-protected paths)" {
        $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision_with_filter.json' -Experimental
        $envObj = Parse-Envelope -Stdout $r.Stdout
        $arm = Envelope-Arm $envObj
        if ($arm -ne 'result') {
            Write-Host "  Envelope arm: $arm" -ForegroundColor Red
            Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
            Write-Host "  Stderr: $($r.Stderr)" -ForegroundColor Gray
            Assert-True $false "filter provision returned a result envelope (filter is silent -- no error expected)"
        } else {
            Assert-True ($r.ExitCode -eq 0) "exit code = 0 (filter dropped protected paths silently)"
            $script:filterSandboxId = $envObj.result.sandboxId
            Assert-True ($script:filterSandboxId -match '^iso:wxc-[0-9a-f]{8}$') `
                "sandbox_id matches iso:wxc-<8-hex> ($script:filterSandboxId)"
            $script:filterAgentUserName = if ($envObj.result.metadata) { [string]$envObj.result.metadata.agentUserName } else { '<absent>' }
            Write-Host "  filter test provisioned: agentUserName=$($script:filterAgentUserName)" -ForegroundColor DarkGray
        }
    }

    if ($filterProvisionedOk -and $script:filterAgentUserName -and $script:filterAgentUserName -ne '<absent>') {
        $filterAgentSid = Get-LocalAccountSid -Name $script:filterAgentUserName

        Run-StateAwareTest "filter: agent user name translates to SID" {
            Assert-True ($null -ne $filterAgentSid) `
                "translated '$($script:filterAgentUserName)' to SID ($filterAgentSid)"
        } | Out-Null

        if ($null -ne $filterAgentSid) {
            Run-StateAwareTest "filter: protected drive root receives no agent ACE" {
                Assert-True (-not (Test-AclContainsSid -Path 'C:\' -TargetSid $filterAgentSid)) `
                    "agent SID is NOT in ACL of C:\ (drive root filter dropped the entry)"
            } | Out-Null

            Run-StateAwareTest "filter: protected SystemRoot receives no agent ACE" {
                Assert-True (-not (Test-AclContainsSid -Path 'C:\Windows' -TargetSid $filterAgentSid)) `
                    "agent SID is NOT in ACL of C:\Windows (SystemRoot filter dropped the entry)"
            } | Out-Null

            Run-StateAwareTest "filter: non-protected path receives agent ACE (positive control)" {
                $nonProtected = Join-Path $script:FilterTestRoot 'rw'
                Assert-True (Test-AclContainsSid -Path $nonProtected -TargetSid $filterAgentSid) `
                    "agent SID IS in ACL of $nonProtected (filter passed legitimate path through)"
            } | Out-Null
        }
    }

    if ($filterProvisionedOk) {
        $filterDeprovPassed = Run-StateAwareTest "filter: deprovision" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:filterSandboxId -Experimental
            $envObj = Parse-Envelope -Stdout $r.Stdout
            $arm = Envelope-Arm $envObj
            if ($arm -ne 'result') {
                Assert-True $false "filter deprovision returned a result envelope (got $arm)"
            } else {
                Assert-True ($r.ExitCode -eq 0) "exit code = 0"
            }
        }
        if ($filterDeprovPassed) { $filterDeprovisionedOk = $true }
    }
} finally {
    if ($null -ne $script:filterSandboxId -and -not $filterDeprovisionedOk) {
        Write-Host ""
        Write-Host "[cleanup] best-effort deprovision of $script:filterSandboxId" -ForegroundColor DarkGray
        try {
            $null = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:filterSandboxId -Experimental
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
            $agentUserName = if ($envObj.result.metadata) { [string]$envObj.result.metadata.agentUserName } else { '<absent>' }
            Write-Host "  Medium provisioned: agentUserName=$agentUserName" -ForegroundColor DarkGray
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

# ---------------- Lifecycle D: Entra agent validation rejections ----------------

# Validation runs before any OS-side call, so these tests never reach the
# IsoEnvBroker service and need no sandbox cleanup. They cover the four
# rejection cells of the validate_provision/validate_start matrix added
# alongside the v2 binding wiring: malformed user shape at provision, and
# the three sandboxId-vs-user mismatches at start.

Run-StateAwareTest "provision (user.upn malformed: missing @)" {
    $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision_user_malformed_upn.json' -Experimental
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (validation rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
    Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
    $msg = if ($envObj) { [string]$envObj.error.message } else { '' }
    Assert-True ($msg.Contains('upn')) "error.message mentions 'upn' (got '$msg')"
} | Out-Null

Run-StateAwareTest "provision (user.wamToken empty)" {
    $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision_user_empty_wamtoken.json' -Experimental
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (validation rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
    Assert-True ($code -eq 'policy_validation') "error.code is 'policy_validation' (got '$code')"
    $msg = if ($envObj) { [string]$envObj.error.message } else { '' }
    Assert-True ($msg.Contains('wamToken')) "error.message mentions 'wamToken' (got '$msg')"
} | Out-Null

Run-StateAwareTest "start (Entra sandbox without user)" {
    $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start_entra_missing_user.json' -Experimental
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (validation rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
    Assert-True ($code -eq 'malformed_request') "error.code is 'malformed_request' (got '$code')"
    $msg = if ($envObj) { [string]$envObj.error.message } else { '' }
    Assert-True ($msg.Contains('Entra sandbox requires user')) "error.message mentions Entra-requires-user (got '$msg')"
} | Out-Null

Run-StateAwareTest "start (local sandbox with user)" {
    $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start_local_with_user.json' -Experimental
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (validation rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
    Assert-True ($code -eq 'malformed_request') "error.code is 'malformed_request' (got '$code')"
    $msg = if ($envObj) { [string]$envObj.error.message } else { '' }
    Assert-True ($msg.Contains('not allowed for local sandbox')) "error.message mentions local-sandbox restriction (got '$msg')"
} | Out-Null

Run-StateAwareTest "start (user.upn mismatches sandboxId)" {
    $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start_upn_mismatch.json' -Experimental
    Assert-True ($r.ExitCode -ne 0) "exit code is non-zero (validation rejected)"
    $envObj = Parse-Envelope -Stdout $r.Stdout
    $code = if ($envObj) { $envObj.error.code } else { '<no envelope>' }
    Assert-True ($code -eq 'malformed_request') "error.code is 'malformed_request' (got '$code')"
    $msg = if ($envObj) { [string]$envObj.error.message } else { '' }
    Assert-True ($msg.Contains('does not match sandboxId')) "error.message mentions sandboxId mismatch (got '$msg')"
} | Out-Null

# ---------------- Lifecycle E: Simultaneous isolation-session sandboxes ----------------
#
# Three concurrently-provisioned sandboxes (A, B, C) verify that
# deprovisioning one does not tear down the others. The runner does not
# call UnregisterAppAsync (see IsolationSessionManager::unregister_client)
# so the per-user hardcoded `regid` registration survives a deprovision of
# any individual sandbox. Without that property the first deprovision
# would break every still-running concurrent sandbox.
#
# Per-agent state isolation is verified by having each sandbox write a
# unique marker file into its agent's %TEMP% and asserting that each
# sandbox sees only its own marker.

$script:saSandboxA = $null
$script:saSandboxB = $null
$script:saSandboxC = $null
$script:saSandboxD = $null
$saADeprov = $false
$saBDeprov = $false
$saCDeprov = $false
$saDDeprov = $false

# Helper: provision a fresh sandbox; returns the sandboxId on success, $null on
# failure. Also logs the OS-assigned agentUserName so post-run inspection of
# leftover local users can be correlated back to a specific test.
function Provision-LifecycleESandbox {
    param([string]$Label)
    $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_provision.json' -Experimental
    $envObj = Parse-Envelope -Stdout $r.Stdout
    if ((Envelope-Arm $envObj) -ne 'result') {
        Write-Host "  $Label provision returned arm: $(Envelope-Arm $envObj)" -ForegroundColor Red
        Write-Host "  Stdout: $($r.Stdout)" -ForegroundColor Gray
        return $null
    }
    $sandboxId = $envObj.result.sandboxId
    $agentUserName = if ($envObj.result.metadata) { [string]$envObj.result.metadata.agentUserName } else { '<absent>' }
    Write-Host "  $Label provisioned: sandboxId=$sandboxId agentUserName=$agentUserName" -ForegroundColor DarkGray
    return $sandboxId
}

# Helper: exec a marker-write command inside the given sandbox.
function Exec-LifecycleEWriteMarker {
    param([string]$SandboxId, [string]$Marker)
    $req = @{
        phase     = 'exec'
        sandboxId = $SandboxId
        process   = @{
            commandLine = "cmd /c `"echo $Marker-content > %TEMP%\$Marker.txt`""
            timeout     = 30000
        }
    }
    Invoke-StateAware -Request $req -Experimental
}

# Helper: exec a "list all markers" command inside the given sandbox.
function Exec-LifecycleEListMarkers {
    param([string]$SandboxId)
    $req = @{
        phase     = 'exec'
        sandboxId = $SandboxId
        process   = @{
            commandLine = 'cmd /c "dir /b %TEMP%\marker_*.txt 2>nul"'
            timeout     = 30000
        }
    }
    Invoke-StateAware -Request $req -Experimental
}

try {
    # E1: Provision A, B, C (three distinct sandbox_ids).
    Run-StateAwareTest "Lifecycle E: provision A" {
        $script:saSandboxA = Provision-LifecycleESandbox -Label "A"
        Assert-True ($null -ne $script:saSandboxA) "saSandboxA is non-null"
        if ($null -ne $script:saSandboxA) {
            Assert-True ($script:saSandboxA -match '^iso:wxc-[0-9a-f]{8}$') "saSandboxA matches expected format ($script:saSandboxA)"
        }
    } | Out-Null
    Run-StateAwareTest "Lifecycle E: provision B" {
        $script:saSandboxB = Provision-LifecycleESandbox -Label "B"
        Assert-True ($null -ne $script:saSandboxB) "saSandboxB is non-null"
        if ($null -ne $script:saSandboxB) {
            Assert-True ($script:saSandboxB -ne $script:saSandboxA) "saSandboxB differs from saSandboxA"
        }
    } | Out-Null
    Run-StateAwareTest "Lifecycle E: provision C" {
        $script:saSandboxC = Provision-LifecycleESandbox -Label "C"
        Assert-True ($null -ne $script:saSandboxC) "saSandboxC is non-null"
        if ($null -ne $script:saSandboxC) {
            Assert-True ($script:saSandboxC -ne $script:saSandboxA) "saSandboxC differs from saSandboxA"
            Assert-True ($script:saSandboxC -ne $script:saSandboxB) "saSandboxC differs from saSandboxB"
        }
    } | Out-Null

    $allProvisioned = $null -ne $script:saSandboxA -and $null -ne $script:saSandboxB -and $null -ne $script:saSandboxC

    if ($allProvisioned) {
        # E2: Start A, B, C.
        Run-StateAwareTest "Lifecycle E: start A" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start.json' -SandboxId $script:saSandboxA -Experimental
            Assert-True ($r.ExitCode -eq 0) "start A exit 0"
        } | Out-Null
        Run-StateAwareTest "Lifecycle E: start B" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start.json' -SandboxId $script:saSandboxB -Experimental
            Assert-True ($r.ExitCode -eq 0) "start B exit 0"
        } | Out-Null
        Run-StateAwareTest "Lifecycle E: start C" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start.json' -SandboxId $script:saSandboxC -Experimental
            Assert-True ($r.ExitCode -eq 0) "start C exit 0"
        } | Out-Null

        # E3: Each agent writes its own marker into its %TEMP%.
        Run-StateAwareTest "Lifecycle E: A writes marker_A" {
            $r = Exec-LifecycleEWriteMarker -SandboxId $script:saSandboxA -Marker "marker_A"
            Assert-True ($r.ExitCode -eq 0) "exec write marker_A exit 0"
        } | Out-Null
        Run-StateAwareTest "Lifecycle E: B writes marker_B" {
            $r = Exec-LifecycleEWriteMarker -SandboxId $script:saSandboxB -Marker "marker_B"
            Assert-True ($r.ExitCode -eq 0) "exec write marker_B exit 0"
        } | Out-Null
        Run-StateAwareTest "Lifecycle E: C writes marker_C" {
            $r = Exec-LifecycleEWriteMarker -SandboxId $script:saSandboxC -Marker "marker_C"
            Assert-True ($r.ExitCode -eq 0) "exec write marker_C exit 0"
        } | Out-Null

        # E4: Each agent's %TEMP% lists only its own marker.
        Run-StateAwareTest "Lifecycle E: A sees only its own marker" {
            $r = Exec-LifecycleEListMarkers -SandboxId $script:saSandboxA
            $out = [string]$r.Stdout
            Assert-True ($r.ExitCode -eq 0) "list exit 0"
            Assert-True ($out.Contains("marker_A.txt")) "A sees marker_A.txt"
            Assert-True (-not $out.Contains("marker_B.txt")) "A does not see marker_B.txt"
            Assert-True (-not $out.Contains("marker_C.txt")) "A does not see marker_C.txt"
        } | Out-Null
        Run-StateAwareTest "Lifecycle E: B sees only its own marker" {
            $r = Exec-LifecycleEListMarkers -SandboxId $script:saSandboxB
            $out = [string]$r.Stdout
            Assert-True ($r.ExitCode -eq 0) "list exit 0"
            Assert-True ($out.Contains("marker_B.txt")) "B sees marker_B.txt"
            Assert-True (-not $out.Contains("marker_A.txt")) "B does not see marker_A.txt"
            Assert-True (-not $out.Contains("marker_C.txt")) "B does not see marker_C.txt"
        } | Out-Null
        Run-StateAwareTest "Lifecycle E: C sees only its own marker" {
            $r = Exec-LifecycleEListMarkers -SandboxId $script:saSandboxC
            $out = [string]$r.Stdout
            Assert-True ($r.ExitCode -eq 0) "list exit 0"
            Assert-True ($out.Contains("marker_C.txt")) "C sees marker_C.txt"
            Assert-True (-not $out.Contains("marker_A.txt")) "C does not see marker_A.txt"
            Assert-True (-not $out.Contains("marker_B.txt")) "C does not see marker_B.txt"
        } | Out-Null

        # E5: Stop + deprovision B. The regid leak means the registration
        # survives B's deprovision and A / C remain functional.
        Run-StateAwareTest "Lifecycle E: stop B" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_stop.json' -SandboxId $script:saSandboxB -Experimental
            Assert-True ($r.ExitCode -eq 0) "stop B exit 0"
        } | Out-Null
        $bDeprovPassed = Run-StateAwareTest "Lifecycle E: deprovision B" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:saSandboxB -Experimental
            Assert-True ($r.ExitCode -eq 0) "deprovision B exit 0"
        }
        if ($bDeprovPassed) { $saBDeprov = $true }

        # E6: Regression check -- A and C remain functional after B
        # deprovisioned. Would fail without the regid leak.
        Run-StateAwareTest "Lifecycle E: A still functional after B deprov" {
            $r = Exec-LifecycleEListMarkers -SandboxId $script:saSandboxA
            $out = [string]$r.Stdout
            Assert-True ($r.ExitCode -eq 0) "list exit 0 (regid not torn down by B's deprovision)"
            Assert-True ($out.Contains("marker_A.txt")) "A still sees marker_A.txt"
        } | Out-Null
        Run-StateAwareTest "Lifecycle E: C still functional after B deprov" {
            $r = Exec-LifecycleEListMarkers -SandboxId $script:saSandboxC
            $out = [string]$r.Stdout
            Assert-True ($r.ExitCode -eq 0) "list exit 0 (regid not torn down by B's deprovision)"
            Assert-True ($out.Contains("marker_C.txt")) "C still sees marker_C.txt"
        } | Out-Null

        # E7: Stop + deprovision A.
        Run-StateAwareTest "Lifecycle E: stop A" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_stop.json' -SandboxId $script:saSandboxA -Experimental
            Assert-True ($r.ExitCode -eq 0) "stop A exit 0"
        } | Out-Null
        $aDeprovPassed = Run-StateAwareTest "Lifecycle E: deprovision A" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:saSandboxA -Experimental
            Assert-True ($r.ExitCode -eq 0) "deprovision A exit 0"
        }
        if ($aDeprovPassed) { $saADeprov = $true }

        # E8: Regression check -- C remains functional after A deprovisioned.
        Run-StateAwareTest "Lifecycle E: C still functional after A deprov" {
            $r = Exec-LifecycleEListMarkers -SandboxId $script:saSandboxC
            $out = [string]$r.Stdout
            Assert-True ($r.ExitCode -eq 0) "list exit 0"
            Assert-True ($out.Contains("marker_C.txt")) "C still sees marker_C.txt"
        } | Out-Null

        # E9: Stop + deprovision C.
        Run-StateAwareTest "Lifecycle E: stop C" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_stop.json' -SandboxId $script:saSandboxC -Experimental
            Assert-True ($r.ExitCode -eq 0) "stop C exit 0"
        } | Out-Null
        $cDeprovPassed = Run-StateAwareTest "Lifecycle E: deprovision C" {
            $r = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:saSandboxC -Experimental
            Assert-True ($r.ExitCode -eq 0) "deprovision C exit 0"
        }
        if ($cDeprovPassed) { $saCDeprov = $true }
    }

    # E10: Fresh provision D after all three torn down -- the leaked regid
    # must not poison new sandboxes either.
    Run-StateAwareTest "Lifecycle E: provision D after all torn down" {
        $script:saSandboxD = Provision-LifecycleESandbox -Label "D"
        Assert-True ($null -ne $script:saSandboxD) "saSandboxD is non-null"
    } | Out-Null
    if ($null -ne $script:saSandboxD) {
        $dBundlePassed = Run-StateAwareTest "Lifecycle E: D start + exec + stop + deprovision" {
            $rs = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_start.json' -SandboxId $script:saSandboxD -Experimental
            Assert-True ($rs.ExitCode -eq 0) "start D exit 0"
            $rw = Exec-LifecycleEWriteMarker -SandboxId $script:saSandboxD -Marker "marker_D"
            Assert-True ($rw.ExitCode -eq 0) "exec write marker_D exit 0"
            $rl = Exec-LifecycleEListMarkers -SandboxId $script:saSandboxD
            $out = [string]$rl.Stdout
            Assert-True ($out.Contains("marker_D.txt")) "D sees marker_D.txt"
            $rst = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_stop.json' -SandboxId $script:saSandboxD -Experimental
            Assert-True ($rst.ExitCode -eq 0) "stop D exit 0"
            $rd = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $script:saSandboxD -Experimental
            Assert-True ($rd.ExitCode -eq 0) "deprovision D exit 0"
        }
        if ($dBundlePassed) { $saDDeprov = $true }
    }
} finally {
    # Best-effort deprovision of any sandbox left provisioned (e.g., due
    # to a mid-flow test failure).
    foreach ($entry in @(
            @{ id = $script:saSandboxA; done = $saADeprov; label = 'A' },
            @{ id = $script:saSandboxB; done = $saBDeprov; label = 'B' },
            @{ id = $script:saSandboxC; done = $saCDeprov; label = 'C' },
            @{ id = $script:saSandboxD; done = $saDDeprov; label = 'D' }
        )) {
        if ($null -ne $entry.id -and -not $entry.done) {
            Write-Host ""
            Write-Host "[cleanup] best-effort deprovision of Lifecycle E sandbox $($entry.label) ($($entry.id))" -ForegroundColor DarkGray
            try {
                $null = Invoke-StateAware -ConfigFile 'isolation_session_state_aware_deprovision.json' -SandboxId $entry.id -Experimental
            } catch { }
        }
    }
}

} finally {
    # Outer-try finally: remove the locked-down test trees. Runs even if a
    # test panics so we don't leak the directories between runs. Cleanup is
    # necessary: re-running Setup-LockedDownTestDir on an existing locked-down
    # directory fails non-elevated because Set-Acl tries to write the SACL
    # slot, which requires SeSecurityPrivilege.
    Remove-Item -Recurse -Force $script:TestRoot -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $script:FilterTestRoot -ErrorAction SilentlyContinue
}

# ---------------- Summary ----------------

$total  = $script:TestResults.Count
# @(...) forces array context so a single failure doesn't get unwrapped to
# the bare result object, where .Count would return the property/key count
# instead of 1. PSCustomObject happens to do the right thing today, but
# the wrap makes the count robust regardless of the result-object type.
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
