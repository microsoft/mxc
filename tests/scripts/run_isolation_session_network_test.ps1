# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    IsolationSession network test pass. Judges every row at runtime: a
    request is either admitted and its posture holds, or it is rejected
    with a named network rejection.

.DESCRIPTION
    This is the isolation_session counterpart of the ProcessContainer network
    areas (capability matrix, model-3 equivalence, egress rules, host loopback,
    proxy, rejections), with the LXC GA egress matrix as the row template.
    Rows are ordered by priority: on/off, L3/L4 egress, host loopback, bring-
    your-own proxy, then the rejection surface. A row asserts capability
    outcomes only, never a ProcessContainer capability name, field coupling,
    or schema shape.

    Every row runs wxc-exec for real (no --dry-run, no build flag, no host
    setup). The request carries a probe command that runs inside the session
    and tries a fixed set of targets. The outcome is decided by what the
    binary under test does with the request:

      PASS         admitted and the requested posture held: every target the
                   request allows was reached, every other target was
                   blocked, and the host fixtures were still healthy after
                   the row. A rejection-surface row (X*) passes when it is
                   rejected with a typed admission error naming the field
                   the row is about; P01/P02 (invalid proxy shapes) pass
                   when rejected by the shared proxy rule.
      UNSUPPORTED  rejected with a typed admission error that names the
                   network policy. The row records the capability it needs
                   and the rejection message. A rejection-surface row that
                   another rule rejected first is also UNSUPPORTED: it was
                   not judged. So is an admitted row whose only judged
                   allowed target is udp when the host gets no UDP reply
                   (E08). Not a failure.
      FAIL         admitted but broader than requested (a target outside the
                   request was reached), admitted but narrower (an allowed
                   target was blocked), an indeterminate probe result, an
                   admitted row whose capability has no probe yet (E07, L10),
                   the baseline all-allow row rejected, a rejection-surface
                   row admitted, an incomplete output capture, or any other
                   error.
      KNOWN-GAP    a recorded gap; see K01 below. Not a failure.

    A typed admission error is exit code 1 with a JSON line
    {"error":{"code":...}} whose code is malformed_request or
    policy_validation. A panic, a crash, a backend error or a bare non-zero
    exit is never a rejection.

    A row therefore starts enforcing its posture as soon as a binary admits
    its shape, without editing this script.

    Probe targets (inside the session):
      external   TCP to -ExternalAddress:-ExternalPort
      udp        DNS query over UDP to -ExternalAddress:53; reached only when
                 a reply with the same transaction id comes back
      icmp       echo to -ExternalAddress; reached only when the reply comes
                 from that address. A ping that fails before sending (no
                 route) counts as blocked; where the row denies icmp, the
                 detail names it as "icmp not judged: <reason>"
      dns        resolve -DnsName
      declared   TCP to a host listener on 127.0.0.1 whose port the request
                 names
      other      TCP to a second 127.0.0.1 listener the request never names
      v6         TCP to a host listener on ::1, same port as declared
      down       TCP to a 127.0.0.1 port held bound but not listening; in
                 L02, to L02's own listener, then to its port after the
                 listener is stopped
      linklocal  TCP to 169.254.169.254:80 (instance metadata); judged
                 blocked in every row whose policy denies it (egress default
                 deny, or no egress), and in E13 and E14, which allow it;
                 report-only where the egress default is allow
    Loopback listeners answer with a per-run nonce and the probe reads it: a
    connect can succeed before the host side answers, so a connect alone
    does not show the host was reached. A target is blocked only on a
    timeout, a close, an unreachable reply, or a connect/resolve error that
    means refused, reset, unreachable or not found; any other error is
    indeterminate and fails the row. Every target needs exactly one record:
    a missing, repeated or unknown record fails an admitted row.

    Before the rows run, and again after every admitted row, the host checks
    the fixtures: the external destination answers, each listener returns
    its nonce and is still accepting, and each down port refuses. A failure
    before the rows aborts
    the pass; a failure after a row fails that row.

    Host positive controls: udp, icmp and v6 are also probed from the host
    (udp and icmp again after every admitted row). A target the session
    reaches is always judged: reached where denied fails the row. Without a
    control, a target the session does not reach is report-only where the
    row denies it; where the row allows it, icmp and v6 fail the row and udp
    is report-only. A row whose only judged allowed target is that udp is
    UNSUPPORTED (not judged), never PASS.
    Metadata is judged on non-reachability, so a blocked probe passes either
    way; whether the host reaches the address is recorded in the row detail.
    E13 and E14 assert this pass's requirement for deny-by-default
    policies: a rule that allows instance metadata does not open it. Where
    the egress default is allow, metadata is report-only.
    DNS is report-only in every restricted row: the request has no field
    that governs name resolution, so the result is recorded but never fails
    a restricted row. In the all-allow row it must resolve. The inbound path
    is not probed; rows that claim it (A01, E05, L09) say so in their detail.

    Known gap K01 (cleanup): if a session outlives its timeout this script
    kills wxc-exec; a killed wxc-exec can leave its session's agent user
    behind. The row fails and a K01 KNOWN-GAP row is added.

    Runtime rows provision sessions, so run interactively as the console
    user, never in Session 0.

    Exit codes: 0 no row failed (UNSUPPORTED and KNOWN-GAP included), 1 any
    row failed, the --probe preflight or a host fixture check failed, or
    -Row selected no known row.

.PARAMETER WxcExePath
    Path to wxc-exec.exe built with --features isolation_session.

.PARAMETER ExternalAddress
    IPv4 address used as the external destination. It must be reachable from
    the host itself, so a denial inside the session is attributable to policy.

.PARAMETER DnsName
    Name resolved by the dns probe.

.PARAMETER Version
    Contract version of the generated requests.

.PARAMETER Row
    Optional row ids to run (default: all). An unknown id fails the pass.

.PARAMETER ResultsPath
    Optional path for a JSON array of row results.

.PARAMETER ConfigDir
    Accepted so callers can pass the same arguments to every bundled test
    script. Unused, because rows build their own requests.

.PARAMETER ClassifierOnly
    Define the row classifier and return without running anything. Used by
    test_isolation_session_network_classifier.ps1, which dot-sources this
    script.

.EXAMPLE
    .\run_isolation_session_network_test.ps1 -WxcExePath C:\test\wxc-exec.exe
    .\run_isolation_session_network_test.ps1 -Row A01,L01 -ResultsPath .\net.json
#>

param(
    [string]$WxcExePath,
    [string]$ExternalAddress = '1.1.1.1',
    # Rows build port +/- 1 shapes, so the port must leave room on both sides.
    [ValidateRange(2, 65534)]
    [int]$ExternalPort = 443,
    [string]$DnsName = 'www.microsoft.com',
    [string]$Version = '1.1.0-alpha',
    [string[]]$Row,
    [string]$ResultsPath,
    [string]$ConfigDir,
    # For tests: define the classifier functions and return without running anything.
    [switch]$ClassifierOnly
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$SessionTimeoutMs = 120000
$KillGraceMs = 60000

# A rejection is a structured admission failure ({"error":{"code":...}} on exit 1) with one of
# these codes; any other code (backend_error, backend_unavailable, ...) is not a rejection. A
# named network rejection is an admission failure whose message names the isolation session and
# the network.
$AdmissionCodes = @('malformed_request', 'policy_validation')
$NetworkRejection = '(?i)isolation ?session[^\r\n]{0,60}network'

# Wxc-exec runs with bounded waits: a hung child, a failed kill, or a grandchild holding the
# pipes must not hang the pass, and output that did not finish is reported as incomplete.
function Invoke-Wxc {
    param([string]$Arguments, [int]$TimeoutMs)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $WxcExePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $killed = $false
    $p = [Diagnostics.Process]::Start($psi)
    $so = $p.StandardOutput.ReadToEndAsync()
    $se = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutMs)) {
        $killed = $true
        try { $p.Kill() } catch {}
        [void]$p.WaitForExit(10000)
    }
    $code = if ($p.HasExited) { $p.ExitCode } else { $null }
    $complete = $true
    $parts = foreach ($t in @($so, $se)) {
        if ($t.Wait(10000) -and -not $t.IsFaulted) { $t.Result } else { $complete = $false }
    }
    $out = @($parts) -join "`n"
    return [pscustomobject]@{
        ExitCode = $code; Output = [string]$out; Killed = $killed; Complete = $complete
    }
}

# The structured admission failure in the output, or $null.
function Get-Rejection {
    param($Run)
    if ($Run.ExitCode -ne 1) { return $null }
    foreach ($line in ($Run.Output -split "`r?`n")) {
        if ($line -notmatch '^\s*\{"error"') { continue }
        try { $e = ($line | ConvertFrom-Json).error } catch { continue }
        if ($e -and $AdmissionCodes -contains $e.code) {
            return [pscustomobject]@{ Code = [string]$e.code; Message = [string]$e.message }
        }
    }
    return $null
}

# ---------------------------------------------------------------- classifier

# The verdict a reached target shows, per target.
$Reach = @{
    external = 'CONNECTED'; udp = 'ANSWERED'; dns = 'RESOLVED'; declared = 'REACHED'; other = 'REACHED'
    linklocal = 'CONNECTED'; icmp = 'ECHOED'; v6 = 'REACHED'; down = 'REACHED'
}
$Targets = @('external', 'udp', 'icmp', 'dns', 'declared', 'other', 'v6', 'down', 'linklocal')
# The verdicts the probe emits. Any other value is not a record.
$ValidRecord = '^(REACHED|CONNECTED|CLOSED|RESOLVED|ANSWERED|MISMATCH|TIMEOUT|ECHOED|UNREACH|ERR|ICMP_\w+|WSA\d+)$'

# Outcomes that show a path is closed. Anything else (an invalid argument, no buffer space, an
# unexpected error) is indeterminate, never evidence that a policy blocked the target.
function Test-Blocked([string]$v) {
    $codes = '10013|10050|10051|10053|10054|10060|10061|10064|10065|11001|11002|11003|11004'
    return $v -match "^(TIMEOUT|CLOSED|UNREACH|WSA($codes))$"
}

# Every 'PROBE <name> <verdict>' line in the output, as name -> list of verdicts.
function Get-ProbeRecords([string]$Output) {
    $records = @{}
    foreach ($m in [regex]::Matches($Output, 'PROBE (\S+) (\S+)')) {
        $name = $m.Groups[1].Value
        if (-not $records.ContainsKey($name)) { $records[$name] = [Collections.Generic.List[string]]::new() }
        $records[$name].Add($m.Groups[2].Value)
    }
    return $records
}

function Get-RecordText([hashtable]$Records, [string]$Name) {
    if (-not $Records.ContainsKey($Name) -or $Records[$Name].Count -eq 0) { return 'NORUN' }
    return ($Records[$Name] -join '/')
}

# Judges an admitted row. $Allow lists the targets the request allows; every other target must be
# blocked. Every target needs exactly one valid record first: a missing, repeated or unknown record
# fails the row, and no exception below applies to it. dns is report-only unless DnsRequired is
# set; linklocal unless LinkLocalJudged is set. A target the session reaches is always judged.
# Without a host control ($HostOk[target] false), a target it does not reach is report-only where
# denied; where allowed, udp is report-only and icmp and v6 are unjudgeable (FAIL). Get-RowVerdict
# reports a row whose only judged allowed target is that udp as not judged.
function Get-PostureVerdict {
    param([hashtable]$Records, [string[]]$Allow = @(), [hashtable]$HostOk = @{}, [switch]$DnsRequired,
          [switch]$LinkLocalJudged)
    $broader = @(); $narrower = @(); $unknown = @(); $missing = @()
    foreach ($t in $Targets) {
        $got = Get-RecordText $Records $t
        if ($got -notmatch $ValidRecord) { $missing += "$t=$got"; continue }
        if ($t -eq 'dns' -and -not $DnsRequired) { continue }
        if ($t -eq 'linklocal' -and -not $LinkLocalJudged) { continue }
        if ($HostOk.ContainsKey($t) -and -not $HostOk[$t] -and $got -ne $Reach[$t]) {
            if ($t -eq 'udp' -or $Allow -notcontains $t) { continue }
            $unknown += "$t=$got (no host control)"
            continue
        }
        if ($Allow -contains $t) {
            if ($got -ne $Reach[$t]) {
                if (Test-Blocked $got) { $narrower += "$t=$got" } else { $unknown += "$t=$got" }
            }
        } elseif (-not (Test-Blocked $got)) {
            if ($got -eq $Reach[$t]) { $broader += "$t=$got" } else { $unknown += "$t=$got" }
        }
    }
    $actual = (@($Targets | ForEach-Object { "$_=$(Get-RecordText $Records $_)" })) -join ' '
    $why = @()
    if ($missing) { $why += "no single valid record: $($missing -join ', ')" }
    if ($broader) { $why += "broader than requested: $($broader -join ', ')" }
    if ($narrower) { $why += "allowed target blocked: $($narrower -join ', ')" }
    if ($unknown) { $why += "indeterminate: $($unknown -join ', ')" }
    return [pscustomobject]@{ Ok = ($why.Count -eq 0); Actual = $actual; Why = ($why -join '; ') }
}

# The metadata address is judged blocked in every row whose policy denies it (egress default deny,
# or no egress at all), and in a row that sets MetadataBlocked: there, a rule under a
# deny-by-default policy allows it, and the row asserts this pass's requirement that such a rule
# does not open it. Where the egress default is allow, the policy permits it, so it is report-only.
function Test-LinkLocalJudged([hashtable]$Row) {
    if ($Row.MetadataBlocked) { return $true }
    $egress = if ($Row.Net -is [hashtable]) { $Row.Net['egress'] } else { $null }
    return -not ($egress -is [hashtable] -and $egress['default'] -eq 'allow')
}

function Get-RowExpected([hashtable]$Row, [string[]]$Allow) {
    if ($Row.Reject) { return 'rejected' }
    if ($Row.Invalid) { return 'rejected: networkProxy needs deny-by-default egress with no direct rules' }
    return "admitted with {$($Allow -join ',')} or rejected naming network"
}

# Classifies one wxc-exec run of a row. Pure: the host checks are passed in. $HostOk holds the
# udp/icmp/v6 host controls, $FixtureFailures the host fixture check after the run, $HostLinkLocal
# whether the host itself reaches 169.254.169.254:80 ($null when not checked). $Allow overrides
# the row's allow list. Returns Expected, Actual, Verdict and Detail.
function Get-RowVerdict {
    param([hashtable]$Row, $Run, [hashtable]$HostOk = @{}, [string[]]$FixtureFailures = @(),
          $HostLinkLocal = $null, [string[]]$Allow)
    if (-not $PSBoundParameters.ContainsKey('Allow')) { $Allow = @($Row.Allow) }
    $expected = Get-RowExpected $Row $Allow
    $records = Get-ProbeRecords $Run.Output
    $admitted = $records.Count -gt 0
    $tail = (($Run.Output -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' | '
    # A rejection counts only as a typed admission error on a clean exit 1.
    $rej = if ($admitted) { $null } else { Get-Rejection $Run }
    $got = if ($rej) { "rejected ($($rej.Code))" } else { "exit $($Run.ExitCode), no admission error" }
    $v = { param($a, $verdict, $d = '') [pscustomobject]@{ Expected = $expected; Actual = $a; Verdict = $verdict; Detail = $d } }
    if ($Run.Killed) { return & $v "killed after $($SessionTimeoutMs + $KillGraceMs) ms" 'FAIL' $tail }
    if (-not $Run.Complete) { return & $v "exit $($Run.ExitCode)" 'FAIL' 'output capture incomplete' }
    if ($Row.Reject) {
        if ($admitted) { return & $v 'admitted' 'FAIL' 'a rejection-surface request was admitted' }
        if ($rej -and $rej.Message -match $Row.Own -and $rej.Message -notmatch $NetworkRejection) {
            return & $v $got 'PASS' $rej.Message
        }
        if ($rej) {
            $rule = if ($rej.Message -match $NetworkRejection) { 'the isolation session network rule' }
                else { 'another rule' }
            return & $v $got 'UNSUPPORTED' "not judged: rejected by $rule before $($Row.Field) was checked: $($rej.Message)"
        }
        return & $v $got 'FAIL' $tail
    }
    if ($admitted -and $Row.Invalid) { return & $v 'admitted' 'FAIL' 'an invalid proxy shape was admitted' }
    if ($admitted -and $Row.Unprobed) { return & $v 'admitted' 'FAIL' "admitted; no probe for $($Row.Unprobed)" }
    if ($admitted) {
        $llJudged = Test-LinkLocalJudged $Row
        $pv = Get-PostureVerdict -Records $records -Allow $Allow -HostOk $HostOk `
            -DnsRequired:([bool]$Row.DnsRequired) -LinkLocalJudged:$llJudged
        $ok = $pv.Ok
        $why = $pv.Why
        if ($ok -and $Run.ExitCode -ne 0) { $ok = $false; $why = "session exited $($Run.ExitCode)" }
        # A fixture that broke during the row makes its verdicts meaningless.
        if ($FixtureFailures.Count -gt 0) { $ok = $false; $why = "fixture unhealthy: $($FixtureFailures -join ', ')" }
        $ll = Get-RecordText $records 'linklocal'
        $llNote = if (-not $llJudged) { "linklocal=$ll (report-only: the policy allows it)" }
            elseif ($ok -and $HostLinkLocal -eq $false) { 'linklocal blocked (no host control: the host cannot reach 169.254.169.254:80)' }
        # Allowed udp with no host control is report-only, so a row whose only judged allowed target
        # is that udp has no evidence its allow works: it is not judged, never a PASS.
        $udpUnjudged = $Allow -contains 'udp' -and $HostOk.ContainsKey('udp') -and -not $HostOk['udp'] -and
            (Get-RecordText $records 'udp') -ne $Reach['udp']
        $judgedAllow = @($Allow | Where-Object {
            $_ -ne 'udp' -and ($_ -ne 'dns' -or $Row.DnsRequired) -and ($_ -ne 'linklocal' -or $llJudged) })
        $notJudged = $ok -and $udpUnjudged -and $judgedAllow.Count -eq 0
        $detail = @(@($why, $llNote, $Row.Note) | Where-Object { $_ })
        if (-not $Row.DnsRequired) { $detail += "dns=$(Get-RecordText $records 'dns') (report-only)" }
        foreach ($t in @('udp', 'icmp', 'v6')) {
            $tv = Get-RecordText $records $t
            if ($HostOk.ContainsKey($t) -and -not $HostOk[$t] -and $tv -ne $Reach[$t]) {
                $detail += "$t not judged: no host control ($t=$tv)"
            }
        }
        # A ping that throws never sent an echo, so a denied icmp was not observed being dropped.
        $threw = if ($records.ContainsKey('icmpthrew')) { $records['icmpthrew'][0] }
        if ($threw -and $HostOk['icmp'] -and $Allow -notcontains 'icmp') {
            $reason = switch ($threw) {
                'win32=1231' { 'no route to the network (1231)' }
                'win32=1232' { 'no route to the host (1232)' }
                default { $threw }
            }
            $counted = $(if (Test-Blocked (Get-RecordText $records 'icmp')) { 'counted as blocked' } else { 'indeterminate' })
            $detail += "icmp not judged: ping failed before sending: $reason; $counted"
        }
        if ($notJudged) {
            $detail = @('not judged: its only allowed target is udp, and the host gets no UDP reply') + $detail
            return & $v "admitted: $($pv.Actual)" 'UNSUPPORTED' ($detail -join '; ')
        }
        return & $v "admitted: $($pv.Actual)" $(if ($ok) { 'PASS' } else { 'FAIL' }) ($detail -join '; ')
    }
    if ($rej -and $rej.Message -match $NetworkRejection) {
        if ($Row.Baseline) { return & $v $got 'FAIL' $rej.Message }
        return & $v 'rejected (network)' 'UNSUPPORTED' $rej.Message
    }
    if ($rej -and $Row.Invalid -and $rej.Message -match 'networkProxy requires network\.egress\.default') {
        return & $v 'rejected (proxy shape)' 'PASS'
    }
    return & $v $got 'FAIL' $(if ($rej) { $rej.Message } else { $tail })
}

# Combines L02's two runs. Phase 2 runs only after phase 1 passed, so the policy was admitted and
# the port shown reachable; anything but a PASS on phase 2 (a rejection included) fails the row.
function Join-L02Verdict($Up, $Down) {
    $verdict = if ($Down.Verdict -eq 'PASS') { 'PASS' } else { 'FAIL' }
    $detail = @(@($Up.Detail, $Down.Detail) | Where-Object { $_ })
    if ($Down.Verdict -ne 'PASS' -and $Down.Verdict -ne 'FAIL') {
        $detail += "listener down was $($Down.Verdict) after an admitted listener-up phase"
    }
    return [pscustomobject]@{
        Expected = "listener up: $($Up.Expected); listener down: $($Down.Expected)"
        Actual = "listener up: $($Up.Actual); listener down: $($Down.Actual)"
        Verdict = $verdict
        Detail = $detail -join '; '
    }
}

# -ClassifierOnly (dot-sourced by test_isolation_session_network_classifier.ps1) stops here, with
# the classifier defined and nothing run.
if ($ClassifierOnly) { return }

if (-not $WxcExePath) {
    # TestBundle layout (<bundle>\test_scripts\this script, <bundle>\bin\<arch>\wxc-exec.exe),
    # then repo builds (honors CARGO_TARGET_DIR): host-arch target, other-arch target, no target
    # triple, release before debug.
    $hostTarget = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64-pc-windows-msvc' }
        else { 'x86_64-pc-windows-msvc' }
    $otherTarget = if ($hostTarget -eq 'aarch64-pc-windows-msvc') { 'x86_64-pc-windows-msvc' }
        else { 'aarch64-pc-windows-msvc' }
    $candidates = [Collections.Generic.List[string]]::new()
    foreach ($exe in Get-ChildItem (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin\*\wxc-exec.exe') `
        -ErrorAction Ignore) { $candidates.Add($exe.FullName) }
    $roots = @($env:CARGO_TARGET_DIR, (Join-Path $RepoRoot 'src\target')) | Where-Object { $_ }
    foreach ($root in $roots) {
        foreach ($cfg in 'release', 'debug') {
            foreach ($triple in "$hostTarget\", "$otherTarget\", '') {
                $candidates.Add((Join-Path $root "$triple$cfg\wxc-exec.exe"))
            }
        }
    }
    $WxcExePath = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $WxcExePath -or -not (Test-Path $WxcExePath)) {
    Write-Host 'FAILED: wxc-exec.exe not found; pass -WxcExePath.' -ForegroundColor Red
    exit 1
}

Write-Host "`nIsolationSession network test pass (Preview API, not a contract)" -ForegroundColor Cyan
Write-Host "Binary: $WxcExePath`n" -ForegroundColor Gray

# ---------------------------------------------------------------- preflight

if ((Get-Process -Id $PID).SessionId -eq 0) {
    Write-Host 'SKIPPED: Session 0; run interactively as the console user.' -ForegroundColor Yellow
    exit 0
}
$probeRun = Invoke-Wxc -Arguments '--probe' -TimeoutMs 60000
$available = $null
if ($probeRun.Output -match '"isolationSessionAvailable"\s*:\s*(true|false)') { $available = $Matches[1] }
if ($probeRun.Killed -or -not $probeRun.Complete -or $probeRun.ExitCode -ne 0 -or -not $available) {
    Write-Host ("FAILED: '$WxcExePath --probe' exited $($probeRun.ExitCode) (killed=" +
        "$($probeRun.Killed), complete=$($probeRun.Complete)) without a probe report " +
        '(missing runtime DLL?). No rows were run.') -ForegroundColor Red
    exit 1
}
if ($available -eq 'false') {
    Write-Host 'SKIPPED: wxc-exec --probe reports isolationSessionAvailable=false' -ForegroundColor Yellow
    exit 0
}
$hostExternal = $false
try {
    $c = [Net.Sockets.TcpClient]::new()
    $hostExternal = $c.ConnectAsync($ExternalAddress, $ExternalPort).Wait(5000)
    $c.Close()
} catch {}
if (-not $hostExternal) {
    Write-Host ("FAILED: the host cannot reach $ExternalAddress`:$ExternalPort, so no row can judge " +
        'external reachability. Pass a reachable -ExternalAddress.') -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------- helpers

[System.Collections.ArrayList]$Rows = @()
$script:Killed = @()

function Add-Row {
    param([string]$Id, [string]$Area, [string]$Capability, [string]$Needs,
          [string]$Expected, [string]$Actual, [string]$Verdict, [string]$Detail = '')
    $color = switch ($Verdict) { 'PASS' { 'Green' } 'FAIL' { 'Red' } default { 'Yellow' } }
    $label = if ($Verdict -ne 'UNSUPPORTED') { $Verdict }
        elseif ($Needs -eq '-' -or $Actual -like 'admitted*') { 'UNSUPPORTED (not judged)' }
        else { "UNSUPPORTED (needs $Needs)" }
    Write-Host ("  {0,-5} {1,-46} {2}" -f $Id, $Capability, $label) -ForegroundColor $color
    if ($Verdict -eq 'FAIL' -or $Verdict -eq 'KNOWN-GAP') {
        Write-Host "        expected: $Expected" -ForegroundColor Gray
        Write-Host "        actual:   $Actual" -ForegroundColor Gray
    }
    if ($Detail) { Write-Host "        $Detail" -ForegroundColor DarkGray }
    $null = $Rows.Add([pscustomobject]@{
        Id = $Id; Area = $Area; Capability = $Capability; Needs = $Needs
        Expected = $Expected; Actual = $Actual; Verdict = $Verdict; Detail = $Detail
    })
}

# Requests go to wxc-exec by file, never on its command line, because a
# request can carry a credential (for example in a proxy URL).
function Invoke-WxcRequest {
    param([hashtable]$Request)
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('mxc-net-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    $cfg = Join-Path $dir 'config.json'
    [IO.File]::WriteAllText($cfg, ($Request | ConvertTo-Json -Compress -Depth 12))
    try {
        return Invoke-Wxc -Arguments "--debug --config `"$cfg`"" -TimeoutMs ($SessionTimeoutMs + $KillGraceMs)
    } finally {
        Remove-Item -Path $dir -Recurse -Force -ErrorAction Ignore
    }
}

function New-Request {
    param($Network, [hashtable]$RuntimeConfig, [string]$CommandLine)
    $r = @{
        version = $Version
        containment = 'isolation_session'
        process = @{ commandLine = $CommandLine; cwd = 'C:\'; timeout = $SessionTimeoutMs }
    }
    if ($null -ne $Network) { $r['network'] = $Network }
    if ($null -ne $RuntimeConfig) { $r['runtimeConfig'] = $RuntimeConfig }
    return $r
}

function Rule {
    param([string[]]$Cidr = @(), [string[]]$Except = @(), [string]$Protocol, $Port, $EndPort,
          [switch]$NoPorts)
    $rule = [ordered]@{}
    if ($Cidr.Count -gt 0) {
        $rule['to'] = @(foreach ($c in $Cidr) {
            $peer = [ordered]@{ cidr = $c }
            if ($Except.Count -gt 0) { $peer['except'] = @($Except) }
            $peer
        })
    }
    if (-not $NoPorts) {
        $sel = [ordered]@{}
        if ($Protocol) { $sel['protocol'] = $Protocol }
        if ($null -ne $Port) { $sel['port'] = [int]$Port }
        if ($null -ne $EndPort) { $sel['endPort'] = [int]$EndPort }
        $rule['ports'] = @($sel)
    }
    return $rule
}

$AllowAll = @{ egress = @{ default = 'allow' }; ingress = @{ default = 'allow'; hostLoopback = 'allow' } }
$DenyIngress = @{ default = 'deny'; hostLoopback = 'deny' }
function DenyDefault {
    param([object[]]$Allow, $Ingress = $DenyIngress, [object[]]$Deny)
    $egress = @{ default = 'deny' }
    if ($Allow) { $egress['allow'] = @($Allow) }
    if ($Deny) { $egress['deny'] = @($Deny) }
    $n = @{ egress = $egress }
    if ($null -ne $Ingress) { $n['ingress'] = $Ingress }
    return $n
}
$Lo = '127.0.0.1/32'

# ---------------------------------------------------------------- probe

# Runs inside the session under Windows PowerShell 5.1. Prints one
# 'PROBE <name> <verdict>' line per target; verdicts are REACHED, CONNECTED,
# CLOSED, RESOLVED, ANSWERED, MISMATCH, TIMEOUT, or WSA<code>.
$ProbeBody = @'
function Get-Wsa($e) {
    while ($e) {
        if ($e -is [Net.Sockets.SocketException]) { return "WSA$($e.ErrorCode)" }
        $e = $e.InnerException
    }
    return 'ERR'
}
function Test-Tcp($name, $addr, $port, $nonce) {
    $ip = [Net.IPAddress]::Parse($addr)
    $c = New-Object Net.Sockets.TcpClient($ip.AddressFamily)
    try {
        $t = $c.ConnectAsync($ip, $port)
        if (-not $t.Wait(8000)) { "PROBE $name TIMEOUT"; return }
        # A non-loopback server may send nothing until the client speaks (TLS), so a connect
        # alone proves reachability there.
        if (-not $nonce) { "PROBE $name CONNECTED"; return }
        # Always read: a connect can succeed before the host side answers, so a connect alone
        # cannot tell "reached" from "refused".
        $s = $c.GetStream()
        $s.ReadTimeout = 5000
        $buf = New-Object byte[] 256
        $text = ''
        # TCP may split the nonce across reads; read until it is seen, EOF, or timeout.
        while (-not $text.Contains($nonce) -and $text.Length -lt 256) {
            try { $n = $s.Read($buf, 0, $buf.Length) } catch { if ($text) { break } else { throw } }
            if ($n -eq 0) { break }
            $text += [Text.Encoding]::ASCII.GetString($buf, 0, $n)
        }
        if (-not $text) { "PROBE $name CLOSED"; return }
        if ($text.Contains($nonce)) { "PROBE $name REACHED" } else { "PROBE $name CONNECTED" }
    } catch {
        "PROBE $name $(Get-Wsa $_.Exception)"
    } finally {
        $c.Close()
    }
}
# A sent datagram proves nothing, so this sends a DNS query and needs a reply
# from the same peer carrying the same transaction id.
function Test-Udp($name, $addr, $port, $qname) {
    $id = [guid]::NewGuid().ToByteArray()
    $q = New-Object Collections.Generic.List[byte]
    $q.AddRange([byte[]]@($id[0], $id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($label in $qname.Split('.')) {
        $b = [Text.Encoding]::ASCII.GetBytes($label)
        $q.Add([byte]$b.Length)
        $q.AddRange($b)
    }
    $q.AddRange([byte[]]@(0, 0, 1, 0, 1))
    $u = New-Object Net.Sockets.UdpClient
    try {
        $u.Client.ReceiveTimeout = 5000
        [void]$u.Send($q.ToArray(), $q.Count, $addr, $port)
        $peer = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $resp = $u.Receive([ref]$peer)
        if ($peer.Address.ToString() -eq $addr -and $peer.Port -eq $port -and $resp.Length -ge 12 -and
            $resp[0] -eq $id[0] -and $resp[1] -eq $id[1] -and ($resp[2] -band 128) -ne 0) {
            "PROBE $name ANSWERED"
        } else {
            "PROBE $name MISMATCH"
        }
    } catch {
        "PROBE $name $(Get-Wsa $_.Exception)"
    } finally {
        $u.Close()
    }
}
function Test-Dns($name, $hostName) {
    try {
        [void][Net.Dns]::GetHostAddresses($hostName)
        "PROBE $name RESOLVED"
    } catch {
        "PROBE $name $(Get-Wsa $_.Exception)"
    }
}
# An echo counts only when the reply comes from the target itself.
function Test-Icmp($name, $addr) {
    try {
        $r = (New-Object Net.NetworkInformation.Ping).Send($addr, 5000)
        $s = "$($r.Status)"
        if ($s -eq 'Success' -and "$($r.Address)" -eq $addr) { $s = 'ECHOED' }
        elseif ($s -eq 'TimedOut') { $s = 'TIMEOUT' }
        elseif ($s -match 'Unreachable|Prohibited') { $s = 'UNREACH' }
        else { $s = "ICMP_$s" }
        "PROBE $name $s"
    } catch {
        # An unroutable destination throws rather than returning a status: the inner
        # Win32Exception is ERROR_NETWORK_UNREACHABLE (1231) or ERROR_HOST_UNREACHABLE (1232).
        $v = Get-Wsa $_.Exception
        $why = $_.Exception.GetType().Name
        for ($e = $_.Exception; $e; $e = $e.InnerException) {
            if ($e -is [ComponentModel.Win32Exception]) { $why = "win32=$($e.NativeErrorCode)" }
            if ($v -eq 'ERR' -and $e -is [ComponentModel.Win32Exception] -and $e.NativeErrorCode -in 1231, 1232) { $v = 'UNREACH' }
        }
        "PROBE $name $v"
        "PROBE ${name}threw $why"
    }
}
'@

function Start-NonceListener {
    param([Net.IPAddress]$Address = [Net.IPAddress]::Loopback, [int]$Port = 0)
    $listener = [Net.Sockets.TcpListener]::new($Address, $Port)
    $listener.Start()
    $nonce = 'MXC-NONCE-' + [guid]::NewGuid().ToString('N')
    # Stopping marks a shutdown; an accept failure outside one is recorded, so the fixture check
    # reports it instead of a silent dead listener.
    $state = [hashtable]::Synchronized(@{ Stopping = $false; AcceptError = $null })
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript({
        param($l, $n, $st)
        $bytes = [Text.Encoding]::ASCII.GetBytes("$n`n")
        while ($true) {
            try { $client = $l.AcceptTcpClient() } catch {
                if (-not $st.Stopping) { $st.AcceptError = $_.Exception.Message }
                break
            }
            # A client that resets mid-write costs only that client; the listener keeps accepting.
            try {
                $stream = $client.GetStream()
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush()
            } catch {
            } finally {
                $client.Close()
            }
        }
    }).AddArgument($listener).AddArgument($nonce).AddArgument($state)
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{
        Port = $listener.LocalEndpoint.Port
        Nonce = $nonce
        State = $state
        Stop = {
            $state.Stopping = $true
            try { $listener.Stop() } catch {}
            try { [void]$ps.EndInvoke($handle) } catch {}
            try { $ps.Dispose() } catch {}
        }.GetNewClosure()
    }
}

# The down port stays bound but never listens, so a connect to 127.0.0.1 on it is refused. The
# exclusive bind on 0.0.0.0 keeps any other socket, wildcard or not, off the port during the pass.
function New-ReservedLoopbackPort([int]$Port = 0) {
    $s = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
    $s.ExclusiveAddressUse = $true
    $s.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Any, $Port)))
    return $s
}

# Host positive controls, run with the same probe code as the session. A target
# the host itself cannot reach cannot show that a policy blocked it.
. ([ScriptBlock]::Create($ProbeBody))
function Update-ProtocolControls {
    $HostOk['udp'] = (Test-Udp 'udp' $ExternalAddress 53 $DnsName) -eq "PROBE udp $($Reach.udp)"
    $HostOk['icmp'] = @(Test-Icmp 'icmp' $ExternalAddress) -contains "PROBE icmp $($Reach.icmp)"
}
$HostOk = @{}
Update-ProtocolControls
if (-not $HostOk.udp) {
    Write-Host ("WARNING: the host gets no DNS answer from $ExternalAddress`:53; udp is report-only " +
        'in every row.') -ForegroundColor Yellow
}
if (-not $HostOk.icmp) {
    Write-Host ("WARNING: the host gets no echo reply from $ExternalAddress; icmp is report-only, " +
        'and a row that allows icmp cannot pass.') -ForegroundColor Yellow
}
$script:HostLinkLocal = $null

# ---------------------------------------------------------------- rows

# declared and v6 share one port number (127.0.0.1 and ::1), so a rule naming the port grants
# exactly one of them by address family.
$declared = $null; $other = $null; $v6 = $null; $downSocket = $null
# L02's own listener: it answers while the row proves the port is reachable, then is stopped and its
# port held bound but not listening while the row proves the port is no longer reachable.
$l02 = $null; $l02Socket = $null; $script:L02Stopped = $false
function Stop-Fixtures {
    foreach ($l in @($declared, $other, $v6, $l02)) { if ($l) { & $l.Stop } }
    foreach ($s in @($downSocket, $l02Socket)) { if ($s) { $s.Dispose() } }
}
# Any terminating error from here on still releases the listeners and the reserved port.
trap { Stop-Fixtures; break }
# L04 declares $D-1..$D+1, so the declared port must leave room on both sides.
for ($i = 0; $i -lt 20; $i++) {
    $declared = Start-NonceListener
    if ($declared.Port -ge 2 -and $declared.Port -le 65534) {
        try { $v6 = Start-NonceListener -Address ([Net.IPAddress]::IPv6Loopback) -Port $declared.Port } catch {}
        if ($v6 -or $i -ge 4) { break }
    }
    & $declared.Stop
    $declared = $null
}
if (-not $declared) {
    Write-Host 'FAILED: no declared listener port in 2..65534 could be started. No rows were run.' -ForegroundColor Red
    Stop-Fixtures
    exit 1
}
$other = Start-NonceListener
# Keep the never-named listener clear of the small port ranges rows declare.
for ($i = 0; $i -lt 20 -and [Math]::Abs($other.Port - $declared.Port) -le 4; $i++) {
    $prev = $other; $other = Start-NonceListener; & $prev.Stop
}
if ([Math]::Abs($other.Port - $declared.Port) -le 4) {
    Write-Host 'FAILED: no second listener port clear of the declared port. No rows were run.' -ForegroundColor Red
    Stop-Fixtures
    exit 1
}
$downSocket = New-ReservedLoopbackPort
$downPort = $downSocket.LocalEndPoint.Port
$l02 = Start-NonceListener
$l02Port = $l02.Port
$D = $declared.Port
$X = "$ExternalAddress/32"
$proxyUrl = "http://127.0.0.1:$D"

# Checks every fixture a verdict relies on from the host: the external destination answers, each
# listener returns its own nonce and still accepts, and each down port refuses. Returns the failures.
function Test-Fixtures {
    $bad = @()
    $ext = Test-Tcp 'external' $ExternalAddress $ExternalPort $null
    if ($ext -ne "PROBE external $($Reach.external)") { $bad += $ext }
    $l02Up = if (-not $script:L02Stopped) { $l02 }
    foreach ($f in @(@('declared', '127.0.0.1', $declared), @('other', '127.0.0.1', $other),
                     @('v6', '::1', $v6), @('l02', '127.0.0.1', $l02Up))) {
        if (-not $f[2]) { continue }
        $got = Test-Tcp $f[0] $f[1] $f[2].Port $f[2].Nonce
        if ($got -ne "PROBE $($f[0]) REACHED") { $bad += $got }
        if ($f[2].State.AcceptError) { $bad += "$($f[0]) listener stopped accepting: $($f[2].State.AcceptError)" }
    }
    $downs = @(, @('down', $downPort))
    if ($script:l02Socket) { $downs += , @('l02down', $l02Port) }
    foreach ($d in $downs) {
        $got = Test-Tcp $d[0] '127.0.0.1' $d[1] 'MXC-NO-LISTENER'
        if ($got -ne "PROBE $($d[0]) WSA10061") { $bad += $got }
    }
    return $bad
}
$HostOk['v6'] = $null -ne $v6
if (-not $HostOk.v6) {
    Write-Host ('WARNING: no ::1 listener could be started; v6 is report-only, and a row that ' +
        'allows ::1 cannot pass.') -ForegroundColor Yellow
}
$fixtureFailures = @(Test-Fixtures)
if ($fixtureFailures.Count -gt 0) {
    Write-Host "FAILED: host fixture check: $($fixtureFailures -join ', '). No rows were run." -ForegroundColor Red
    Stop-Fixtures
    exit 1
}

# Allow: targets the request allows. Needs: the capability a binary must have
# to admit the shape (named when it is rejected). Baseline: rejection fails.
# Reject: a rejection-surface row; admission fails, a validation rejection naming the Own field
# path passes, and any other rejection means Field was not judged (UNSUPPORTED).
$Matrix = @(
    # On/off (PC: capability matrix, model-3 equivalence)
    @{ Id = 'A01'; Area = 'on-off'; Cap = 'all-allow posture'; Needs = '-'; Baseline = $true
       Net = $AllowAll; Allow = @('external', 'udp', 'icmp', 'dns', 'declared', 'other', 'v6')
       DnsRequired = $true; Note = 'inbound not probed' }
    @{ Id = 'A02'; Area = 'on-off'; Cap = 'deny-all (no rules)'; Needs = 'defaultDeny'
       Net = (DenyDefault -Allow @()); Allow = @() }
    @{ Id = 'A03'; Area = 'on-off'; Cap = 'network omitted (default off)'; Needs = 'defaultDeny'
       Net = $null; Allow = @() }
    @{ Id = 'A04'; Area = 'on-off'; Cap = 'egress omitted, ingress denied'; Needs = 'defaultDeny'
       Net = @{ ingress = $DenyIngress }; Allow = @() }
    # L3/L4 egress (PC: egress rules; LXC GA egress matrix)
    @{ Id = 'E01'; Area = 'egress'; Cap = 'allow external /32 tcp port'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr $X -Protocol tcp -Port $ExternalPort)); Allow = @('external') }
    @{ Id = 'E02'; Area = 'egress'; Cap = 'allow any destination tcp port'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Protocol tcp -Port $ExternalPort)); Allow = @('external') }
    @{ Id = 'E03'; Area = 'egress'; Cap = 'allow 0.0.0.0/0 tcp port'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '0.0.0.0/0' -Protocol tcp -Port $ExternalPort)); Allow = @('external') }
    @{ Id = 'E04'; Area = 'egress'; Cap = 'deny rule wins over allow'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '0.0.0.0/0' -Protocol tcp -Port $ExternalPort) `
              -Deny @(Rule -Cidr $X -Protocol tcp -Port $ExternalPort)); Allow = @() }
    @{ Id = 'E05'; Area = 'egress'; Cap = 'allow default with allow rules'; Needs = 'egressFiltering'
       Net = @{ egress = @{ default = 'allow'; allow = @(Rule -Cidr '192.0.2.0/24') }
                ingress = @{ default = 'allow'; hostLoopback = 'allow' } }
       Allow = @('external', 'udp', 'icmp', 'declared', 'other', 'v6'); Note = 'inbound not probed' }
    @{ Id = 'E06'; Area = 'egress'; Cap = 'except excludes the target'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '0.0.0.0/0' -Except $X -Protocol tcp -Port $ExternalPort)); Allow = @() }
    @{ Id = 'E07'; Area = 'egress'; Cap = 'IPv6 destination only'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '2001:db8::/32' -Protocol tcp -Port $ExternalPort)); Allow = @()
       Unprobed = 'an IPv6 external destination' }
    @{ Id = 'E08'; Area = 'egress'; Cap = 'udp/53 to any destination'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '0.0.0.0/0' -Protocol udp -Port 53)); Allow = @('udp') }
    @{ Id = 'E09'; Area = 'egress'; Cap = 'icmp only'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '0.0.0.0/0' -Protocol icmp)); Allow = @('icmp') }
    @{ Id = 'E10'; Area = 'egress'; Cap = 'wrong port'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr $X -Protocol tcp -Port ($ExternalPort + 1))); Allow = @() }
    @{ Id = 'E11'; Area = 'egress'; Cap = 'port range covering the target'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr $X -Protocol tcp -Port ($ExternalPort - 1) -EndPort ($ExternalPort + 1)))
       Allow = @('external') }
    # A port-qualified "any" rule matches tcp and udp on that port, never ICMP (as the LXC GA egress
    # spec), so icmp must stay blocked.
    @{ Id = 'E12'; Area = 'egress'; Cap = 'protocol any to the target'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr $X -Protocol any -Port $ExternalPort))
       Allow = @(@('external') + @($(if ($ExternalPort -eq 53) { 'udp' }))) }
    # Every row whose policy denies 169.254.169.254:80 also judges it blocked. E13 and E14 go
    # further: under a deny-by-default policy, a rule allows it, and the row asserts this pass's
    # requirement that such a rule does not open instance metadata. Admitted, the row passes only
    # when 169.254.169.254:80 is blocked. Where the egress default is allow (A01, E05, L11), the
    # metadata result is report-only (Test-LinkLocalJudged).
    @{ Id = 'E13'; Area = 'egress'; Cap = 'link-local metadata address never reachable'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '169.254.0.0/16' -Protocol tcp -Port 80)); Allow = @()
       MetadataBlocked = $true }
    # The exact metadata address, so the verdict does not rest on how a /16 is bounded.
    @{ Id = 'E14'; Area = 'egress'; Cap = 'exact metadata address never reachable'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '169.254.169.254/32' -Protocol tcp -Port 80)); Allow = @()
       MetadataBlocked = $true }
    # E15: E04 with the allow and deny on the same destination, so no wide allow is needed.
    @{ Id = 'E15'; Area = 'egress'; Cap = 'deny wins over a matching /32 allow'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr $X -Protocol tcp -Port $ExternalPort) `
              -Deny @(Rule -Cidr $X -Protocol tcp -Port $ExternalPort)); Allow = @() }
    # Host loopback. These rows test proposed IsolationSession behavior pending #1707; they are not
    # ProcessContainer parity rows. With hostLoopback "deny", L01-L08 and L10 expect an egress.allow
    # rule to a loopback address to open host loopback (outbound only): the declared port, or all
    # ports in L06 (no ports named). ProcessContainer and WSLC do not tie host loopback to egress
    # rules. #1707 proposes a dedicated field instead, so these requests will follow whatever it
    # settles. Only the ports a request declares open; a rule that names a port never opens all.
    @{ Id = 'L01'; Area = 'loopback'; Cap = '127.0.0.1/32 exact tcp port'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -Protocol tcp -Port $D)); Allow = @('declared') }
    # Two runs under one policy that declares a second port. With its host listener up, the nonce
    # must come back on that exact port (down=REACHED); after the listener is stopped, the same
    # probe must be blocked. No particular socket error is required.
    @{ Id = 'L02'; Area = 'loopback'; Cap = 'declared port, host listener up then down'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @((Rule -Cidr $Lo -Protocol tcp -Port $D), (Rule -Cidr $Lo -Protocol tcp -Port $l02Port)))
       Allow = @('declared', 'down'); AllowAfterStop = @('declared'); StopsListener = $true }
    @{ Id = 'L03'; Area = 'loopback'; Cap = 'endPort equal to port'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -Protocol tcp -Port $D -EndPort $D)); Allow = @('declared') }
    @{ Id = 'L04'; Area = 'loopback'; Cap = 'small port range'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -Protocol tcp -Port ($D - 1) -EndPort ($D + 1))); Allow = @('declared') }
    @{ Id = 'L05'; Area = 'loopback'; Cap = 'ingress omitted (defaults to deny)'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -Protocol tcp -Port $D) -Ingress $null); Allow = @('declared') }
    @{ Id = 'L06'; Area = 'loopback'; Cap = 'all-ports loopback (no ports)'; Needs = 'hostLoopbackAllPorts'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -NoPorts)); Allow = @('declared', 'other') }
    @{ Id = 'L07'; Area = 'loopback'; Cap = '127.0.0.0/8 tcp port'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '127.0.0.0/8' -Protocol tcp -Port $D)); Allow = @('declared') }
    @{ Id = 'L08'; Area = 'loopback'; Cap = '::1/128 only'; Needs = 'ipv6Loopback'
       Net = (DenyDefault -Allow @(Rule -Cidr '::1/128' -Protocol tcp -Port $D)); Allow = @('v6') }
    @{ Id = 'L09'; Area = 'loopback'; Cap = 'hostLoopback=allow'; Needs = 'hostLoopbackAllPorts'
       Net = (DenyDefault -Allow @() -Ingress @{ default = 'deny'; hostLoopback = 'allow' })
       Allow = @('declared', 'other', 'v6'); Note = 'inbound not probed' }
    @{ Id = 'L10'; Area = 'loopback'; Cap = 'ingress.default=allow (inbound)'; Needs = 'inboundPath'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -Protocol tcp -Port $D) -Ingress @{ default = 'allow'; hostLoopback = 'deny' })
       Allow = @('declared'); Unprobed = 'the inbound path' }
    @{ Id = 'L11'; Area = 'loopback'; Cap = 'egress allow, host loopback denied'; Needs = 'egressFiltering'
       Net = @{ egress = @{ default = 'allow' }; ingress = $DenyIngress }; Allow = @('external', 'udp', 'icmp') }
    # Bring-your-own proxy (PC: proxy). The proxy is the declared listener. A proxy needs
    # egress.default=deny with no direct rules, so P01/P02 are invalid shapes: admitted is FAIL,
    # the shared proxy rejection is PASS, the isolation session rejection is UNSUPPORTED.
    @{ Id = 'P01'; Area = 'proxy'; Cap = 'networkProxy with all-allow (invalid)'; Needs = 'runtimeProxy'
       Net = $AllowAll; Rc = @{ networkProxy = $proxyUrl }; Invalid = $true }
    @{ Id = 'P02'; Area = 'proxy'; Cap = 'networkProxy with a direct rule (invalid)'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -Protocol tcp -Port $D)); Rc = @{ networkProxy = $proxyUrl }
       Invalid = $true }
    # P03 expects the proxy port to be open as a declared host port, like the host loopback rows:
    # proposed IsolationSession behavior pending #1707, not a ProcessContainer parity row.
    @{ Id = 'P03'; Area = 'proxy'; Cap = 'networkProxy port implied (no rules)'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @()); Rc = @{ networkProxy = $proxyUrl }; Allow = @('declared') }
    # Rejection surface (PC: rejections). Never admitted on any build.
    @{ Id = 'X01'; Area = 'rejection'; Cap = 'legacy network.allowedHosts'; Needs = '-'; Reject = $true
       Field = 'network.allowedHosts'; Own = '\bnetwork\.allowedHosts\b'
       Net = @{ allowedHosts = @('example.com') } }
    @{ Id = 'X02'; Area = 'rejection'; Cap = 'legacy network.proxy'; Needs = '-'; Reject = $true
       Field = 'network.proxy'; Own = '\bnetwork\.proxy\b'
       Net = @{ proxy = @{ url = 'http://127.0.0.1:8888' } } }
    @{ Id = 'X03'; Area = 'rejection'; Cap = 'malformed CIDR'; Needs = '-'; Reject = $true
       Field = 'the CIDR'; Own = '\bnetwork\.egress\.allow\[0\]\.to\[0\]\.cidr\b'
       Net = (DenyDefault -Allow @(Rule -Cidr '127.0.0.1/33' -Protocol tcp -Port $D)) }
    @{ Id = 'X04'; Area = 'rejection'; Cap = 'loopback port 0'; Needs = '-'; Reject = $true
       Field = 'the port'; Own = '\bnetwork\.egress\.allow\[0\]\.ports\[0\]\.port\b'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -Protocol tcp -Port 0)) }
)
if ($PSBoundParameters.ContainsKey('Row')) {
    # powershell.exe -File passes a list as one comma-joined string.
    $ids = @(@($Row) | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $unknownIds = @($ids | Where-Object { @($Matrix.Id) -notcontains $_ })
    $Matrix = @($Matrix | Where-Object { $ids -contains $_.Id })
    if ($unknownIds.Count -gt 0 -or $Matrix.Count -eq 0) {
        Write-Host "FAILED: -Row selects no rows or names unknown rows: $($unknownIds -join ',')" -ForegroundColor Red
        Stop-Fixtures
        exit 1
    }
}

# Builds the session command line. $DownCall is the probe for the 'down' target: the reserved
# never-listening port in every row but L02, which probes its own listener's port.
function New-ProbeCommand([string]$DownCall) {
    $calls = @(
        "Test-Tcp 'other' '127.0.0.1' $($other.Port) '$($other.Nonce)'",
        "Test-Tcp 'external' '$ExternalAddress' $ExternalPort `$null",
        "Test-Tcp 'linklocal' '169.254.169.254' 80 `$null",
        "Test-Udp 'udp' '$ExternalAddress' 53 '$DnsName'",
        "Test-Icmp 'icmp' '$ExternalAddress'",
        "Test-Dns 'dns' '$DnsName'",
        $DownCall,
        "Test-Tcp 'v6' '::1' $D '$(if ($v6) { $v6.Nonce } else { 'MXC-NO-V6' })'",
        "Test-Tcp 'declared' '127.0.0.1' $D '$($declared.Nonce)'"
    )
    $probeScript = ((($ProbeBody -split "`r?`n") | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') }) -join "`n") + "`n" + ($calls -join "`n")
    # UTF-16 base64 nearly triples the script, so ship it gzipped and expand it inside the session.
    $ms = New-Object IO.MemoryStream
    $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
    $raw = [Text.Encoding]::UTF8.GetBytes($probeScript)
    $gz.Write($raw, 0, $raw.Length)
    $gz.Dispose()
    $packed = [Convert]::ToBase64String($ms.ToArray())
    $loader = "`$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String('$packed'));" +
        "`$z=New-Object IO.Compression.GZipStream(`$m,[IO.Compression.CompressionMode]::Decompress);" +
        "Invoke-Expression (New-Object IO.StreamReader(`$z)).ReadToEnd()"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loader))
    return "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand $b64"
}
# A nonce forces the read, so a reset after the connect (10054) is observed.
$probeCommand = New-ProbeCommand "Test-Tcp 'down' '127.0.0.1' $downPort 'MXC-NO-LISTENER'"
$l02Command = New-ProbeCommand "Test-Tcp 'down' '127.0.0.1' $l02Port '$($l02.Nonce)'"
# Session launch refuses longer command lines ("The command line is too long."); keep under 8191.
$longest = [Math]::Max($probeCommand.Length, $l02Command.Length)
if ($longest -gt 8191) {
    Write-Host "FAILED: probe command is $longest characters; the limit is 8191." -ForegroundColor Red
    Stop-Fixtures
    exit 1
}

# Runs one request and classifies it against the current fixtures and host controls.
function Invoke-RowRun([hashtable]$Row, [string]$Command, [string[]]$Allow) {
    $req = New-Request -Network $Row.Net -RuntimeConfig $Row.Rc -CommandLine $Command
    $run = Invoke-WxcRequest -Request $req
    if ($run.Killed) { $script:Killed += $Row.Id }
    $fx = @()
    if ((Get-ProbeRecords $run.Output).Count -gt 0) {
        # udp and icmp controls can change during the pass, so judge against fresh ones.
        Update-ProtocolControls
        $fx = @(Test-Fixtures)
        if ($null -eq $script:HostLinkLocal -and (Test-LinkLocalJudged $Row)) {
            # The property is non-reachability, so a block passes; the host control is recorded only.
            $script:HostLinkLocal = (Test-Tcp 'linklocal' '169.254.169.254' 80 $null) -eq 'PROBE linklocal CONNECTED'
        }
    }
    return Get-RowVerdict -Row $Row -Run $run -HostOk $HostOk -FixtureFailures $fx `
        -HostLinkLocal $script:HostLinkLocal -Allow $Allow
}

$v6Text = if ($v6) { "::1:$D" } else { 'none' }
Write-Host ("Listeners: declared=$D other=$($other.Port) v6=$v6Text down=$downPort l02=$l02Port; " +
    "external=$ExternalAddress`:$ExternalPort") -ForegroundColor DarkGray
try {
    foreach ($r in $Matrix) {
        try {
            if (-not $r.StopsListener) {
                $rv = Invoke-RowRun $r $probeCommand @($r.Allow)
            } else {
                $up = Invoke-RowRun $r $l02Command @($r.Allow)
                $rv = $up
                if ($up.Verdict -eq 'PASS') {
                    # Same policy, same probe; the listener is gone and its port held bound but not
                    # listening, so the declared port must now be blocked.
                    # Marked stopped before the reserve: if another process takes the port, only L02
                    # fails (runner error) and later rows neither expect the listener nor its refusal.
                    & $l02.Stop
                    $script:L02Stopped = $true
                    $script:l02Socket = New-ReservedLoopbackPort -Port $l02Port
                    $down = Invoke-RowRun $r $l02Command @($r.AllowAfterStop)
                    $rv = Join-L02Verdict $up $down
                }
            }
            Add-Row $r.Id $r.Area $r.Cap $r.Needs $rv.Expected $rv.Actual $rv.Verdict $rv.Detail
        } catch {
            Add-Row $r.Id $r.Area $r.Cap $r.Needs (Get-RowExpected $r @($r.Allow)) 'runner error' 'FAIL' $_.Exception.Message
        }
    }
} finally {
    Stop-Fixtures
}
if ($script:Killed.Count -gt 0) {
    Add-Row 'K01' 'cleanup' 'killed wxc-exec may leave its agent user' '-' 'no killed wxc-exec' `
        "killed in $($script:Killed -join ',')" 'KNOWN-GAP' 'check for and remove a leftover agent user'
}

# ---------------------------------------------------------------- summary

$pass = @($Rows | Where-Object Verdict -eq 'PASS').Count
$fail = @($Rows | Where-Object Verdict -eq 'FAIL').Count
$unsup = @($Rows | Where-Object Verdict -eq 'UNSUPPORTED').Count
$gap = @($Rows | Where-Object Verdict -eq 'KNOWN-GAP').Count
Write-Host "`nSummary: $pass passed, $fail failed, $unsup unsupported, $gap known gaps, $($Rows.Count) rows" -ForegroundColor Cyan
# Harness-parsed summary line ("X/Y passed[, N FAILED]"); UNSUPPORTED and KNOWN-GAP are not failures.
$counted = $pass + $fail
if ($fail -gt 0) { Write-Host "$pass/$counted passed, $fail FAILED ($unsup unsupported, $gap known gaps):" }
else { Write-Host "$pass/$counted passed, $unsup unsupported, $gap known gaps" }
if ($ResultsPath) {
    ConvertTo-Json -InputObject @($Rows) -Depth 4 | Set-Content -Path $ResultsPath -Encoding ascii
    Write-Host "Results: $ResultsPath" -ForegroundColor Gray
}
if ($fail -gt 0) { exit 1 }
exit 0
