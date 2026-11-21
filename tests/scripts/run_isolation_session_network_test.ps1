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
                   the row. Rejection-surface rows (X*) pass when rejected
                   with a typed admission error. E13 also passes when the
                   rejection names linkLocal; P01/P02 (invalid proxy shapes)
                   pass when rejected by the shared proxy rule.
      UNSUPPORTED  rejected with a typed admission error that names the
                   network policy. The row records the capability it needs.
                   Not a failure.
      FAIL         admitted but broader than requested (a target outside the
                   request was reached), admitted but narrower (an allowed
                   target was blocked), an indeterminate probe result, an
                   admitted row whose capability has no probe yet (E07, L10),
                   the baseline all-allow row rejected, a rejection-surface
                   row admitted, an incomplete output capture, or any other
                   error.
      KNOWN-GAP    a recorded gap; see G13 below. Not a failure.

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
                 from that address
      dns        resolve -DnsName
      declared   TCP to a host listener on 127.0.0.1 whose port the request
                 names
      other      TCP to a second 127.0.0.1 listener the request never names
      v6         TCP to a host listener on ::1, same port as declared
      down       TCP to a 127.0.0.1 port held bound but not listening
      linklocal  TCP to 169.254.169.254:80 (instance metadata); judged only
                 in E13, recorded in every other row
    Loopback listeners answer with a per-run nonce, so a relay that accepts
    locally cannot pass as reaching the host. A target is blocked only on a
    timeout, a close, an unreachable reply, or a connect/resolve error that
    means refused, reset, unreachable or not found; any other error is
    indeterminate and fails the row.

    Before the rows run, and again after every admitted row, the host checks
    the fixtures: the external destination answers, each listener returns
    its nonce, and the down port refuses. A failure before the rows aborts
    the pass; a failure after a row fails that row.

    Host positive controls: udp, icmp and v6 are also probed from the host
    (udp and icmp again after every admitted row). A target the session
    reaches is always judged: reached where denied fails the row. Without a
    control, a target the session does not reach is report-only where the
    row denies it; where the row allows it, icmp and v6 fail the row and udp
    is report-only.
    E13 checks non-reachability, so a blocked metadata probe passes either
    way; whether the host reaches the address is recorded in the row detail.
    DNS is report-only in every restricted row: name resolution may leave a
    default-deny session, so it is recorded but never fails a restricted row.
    In the all-allow row it must resolve. The inbound path is not probed;
    rows that claim it (A01, E05, L09) say so in their detail.

    Known gap G13: if a session outlives its timeout this script kills
    wxc-exec; a killed wxc-exec can leave its session's agent user behind.
    The row fails and a G13 KNOWN-GAP row is added.

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
    Accepted for compatibility with the OS MXC integration harness, which
    passes it to every bundle orchestrator. Unused: rows build their own
    requests.

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
    [string]$ConfigDir
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

if (-not $WxcExePath) {
    # Repo build (honors CARGO_TARGET_DIR), then the TestBundle layout.
    $roots = @($env:CARGO_TARGET_DIR, (Join-Path $RepoRoot 'src\target')) | Where-Object { $_ }
    $candidates = foreach ($root in $roots) {
        foreach ($cfg in 'release', 'debug') { Join-Path $root "$cfg\wxc-exec.exe" }
    }
    $candidates += @(Get-ChildItem (Join-Path $RepoRoot 'bin\*\wxc-exec.exe') -ErrorAction Ignore).FullName
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
    $label = if ($Verdict -eq 'UNSUPPORTED') { "UNSUPPORTED (needs $Needs)" } else { $Verdict }
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
        # Always read: a loopback relay accepts locally and only resets after its host-side
        # connect fails, so a connect alone cannot tell "reached" from "relay refused".
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
        for ($e = $_.Exception; $v -eq 'ERR' -and $e; $e = $e.InnerException) {
            if ($e -is [ComponentModel.Win32Exception] -and $e.NativeErrorCode -in 1231, 1232) { $v = 'UNREACH' }
        }
        "PROBE $name $v"
    }
}
'@

function Start-NonceListener {
    param([Net.IPAddress]$Address = [Net.IPAddress]::Loopback, [int]$Port = 0)
    $listener = [Net.Sockets.TcpListener]::new($Address, $Port)
    $listener.Start()
    $nonce = 'MXC-NONCE-' + [guid]::NewGuid().ToString('N')
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript({
        param($l, $n)
        $bytes = [Text.Encoding]::ASCII.GetBytes("$n`n")
        while ($true) {
            try {
                $client = $l.AcceptTcpClient()
                $stream = $client.GetStream()
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush()
                $client.Close()
            } catch { break }
        }
    }).AddArgument($listener).AddArgument($nonce)
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{
        Port = $listener.LocalEndpoint.Port
        Nonce = $nonce
        Stop = {
            try { $listener.Stop() } catch {}
            try { [void]$ps.EndInvoke($handle) } catch {}
            try { $ps.Dispose() } catch {}
        }.GetNewClosure()
    }
}

# The down port stays bound but never listens, so a connect to 127.0.0.1 on it is refused. The
# exclusive bind on 0.0.0.0 keeps any other socket, wildcard or not, off the port during the pass.
function New-ReservedLoopbackPort {
    $s = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
    $s.ExclusiveAddressUse = $true
    $s.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)))
    return $s
}

$Reach = @{
    external = 'CONNECTED'; udp = 'ANSWERED'; dns = 'RESOLVED'; declared = 'REACHED'; other = 'REACHED'
    linklocal = 'CONNECTED'; icmp = 'ECHOED'; v6 = 'REACHED'
}

# Host positive controls, run with the same probe code as the session. A target
# the host itself cannot reach cannot show that a policy blocked it.
. ([ScriptBlock]::Create($ProbeBody))
function Update-ProtocolControls {
    $HostOk['udp'] = (Test-Udp 'udp' $ExternalAddress 53 $DnsName) -eq "PROBE udp $($Reach.udp)"
    $HostOk['icmp'] = (Test-Icmp 'icmp' $ExternalAddress) -eq "PROBE icmp $($Reach.icmp)"
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
$Targets = @('external', 'udp', 'icmp', 'dns', 'declared', 'other', 'v6', 'down', 'linklocal')

# Outcomes that show a path is closed. Anything else (an invalid argument, no buffer space, an
# unexpected error) is indeterminate, never evidence that a policy blocked the target.
function Test-Blocked([string]$v) {
    $codes = '10013|10050|10051|10053|10054|10060|10061|10064|10065|11001|11002|11003|11004'
    return $v -match "^(TIMEOUT|CLOSED|UNREACH|WSA($codes))$"
}

# Judges an admitted row. $Allow lists the targets the request allows; every other target must be
# blocked. dns is report-only unless DnsRequired is set; linklocal unless LinkLocalJudged is set.
# A target the session reaches is always judged. Without a host control, a target it does not
# reach is report-only where denied; where allowed, udp is report-only (agreed lab exception) and
# icmp and v6 are unjudgeable (FAIL).
function Get-PostureVerdict {
    param([hashtable]$Verdicts, [string[]]$Allow, [switch]$DnsRequired, [switch]$LinkLocalJudged)
    $broader = @(); $narrower = @(); $unknown = @()
    foreach ($t in $Targets) {
        $got = $Verdicts[$t]
        if (-not $got) { $got = 'NORUN' }
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
            if ($Reach.ContainsKey($t) -and $got -eq $Reach[$t]) { $broader += "$t=$got" }
            else { $unknown += "$t=$got" }
        }
    }
    $actual = (@($Targets | ForEach-Object {
        $g = $Verdicts[$_]; if (-not $g) { $g = 'NORUN' }; "$_=$g"
    })) -join ' '
    $why = @()
    if ($broader) { $why += "broader than requested: $($broader -join ', ')" }
    if ($narrower) { $why += "allowed target blocked: $($narrower -join ', ')" }
    if ($unknown) { $why += "indeterminate: $($unknown -join ', ')" }
    return [pscustomobject]@{ Ok = ($why.Count -eq 0); Actual = $actual; Why = ($why -join '; ') }
}

# ---------------------------------------------------------------- rows

# declared and v6 share one port number (127.0.0.1 and ::1), so a rule naming the port grants
# exactly one of them by address family.
$declared = $null; $other = $null; $v6 = $null; $downSocket = $null
function Stop-Fixtures {
    foreach ($l in @($declared, $other, $v6)) { if ($l) { & $l.Stop } }
    if ($downSocket) { $downSocket.Dispose() }
}
# Any terminating error from here on still releases the listeners and the reserved port.
trap { Stop-Fixtures; break }
for ($i = 0; $i -lt 5 -and -not $v6; $i++) {
    if ($declared) { & $declared.Stop }
    $declared = Start-NonceListener
    try { $v6 = Start-NonceListener -Address ([Net.IPAddress]::IPv6Loopback) -Port $declared.Port } catch {}
}
$other = Start-NonceListener
# Keep the never-named listener clear of the small port ranges rows declare.
while ([Math]::Abs($other.Port - $declared.Port) -le 4) {
    $prev = $other; $other = Start-NonceListener; & $prev.Stop
}
$downSocket = New-ReservedLoopbackPort
$downPort = $downSocket.LocalEndPoint.Port
$D = $declared.Port
$X = "$ExternalAddress/32"
$proxyUrl = "http://127.0.0.1:$D"

# Checks every fixture a verdict relies on from the host: the external destination answers, each
# listener returns its own nonce, and the down port refuses. Returns the failures.
function Test-Fixtures {
    $bad = @()
    $ext = Test-Tcp 'external' $ExternalAddress $ExternalPort $null
    if ($ext -ne "PROBE external $($Reach.external)") { $bad += $ext }
    foreach ($f in @(@('declared', '127.0.0.1', $declared), @('other', '127.0.0.1', $other),
                     @('v6', '::1', $v6))) {
        if (-not $f[2]) { continue }
        $got = Test-Tcp $f[0] $f[1] $f[2].Port $f[2].Nonce
        if ($got -ne "PROBE $($f[0]) REACHED") { $bad += $got }
    }
    $down = Test-Tcp 'down' '127.0.0.1' $downPort 'MXC-NO-LISTENER'
    if ($down -ne 'PROBE down WSA10061') { $bad += $down }
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
# Reject: a rejection-surface row; admission fails, any clean rejection passes.
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
    # Link-local / instance metadata is never reachable, whatever the policy allows. Preferred:
    # rejected naming linkLocal (PASS); else admitted with 169.254.169.254:80 blocked.
    @{ Id = 'E13'; Area = 'egress'; Cap = 'link-local metadata address never reachable'; Needs = 'egressRules'
       Net = (DenyDefault -Allow @(Rule -Cidr '169.254.0.0/16' -Protocol tcp -Port 80)); Allow = @()
       LinkLocalJudged = $true; PassOnRejection = 'linkLocal' }
    # Host loopback (PC: host loopback). Declared ports only, never all ports.
    @{ Id = 'L01'; Area = 'loopback'; Cap = '127.0.0.1/32 exact tcp port'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @(Rule -Cidr $Lo -Protocol tcp -Port $D)); Allow = @('declared') }
    @{ Id = 'L02'; Area = 'loopback'; Cap = 'declared port, host listener down'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @((Rule -Cidr $Lo -Protocol tcp -Port $D), (Rule -Cidr $Lo -Protocol tcp -Port $downPort)))
       Allow = @('declared'); DownCode = 'WSA10054' }
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
    @{ Id = 'P03'; Area = 'proxy'; Cap = 'networkProxy port implied (no rules)'; Needs = 'loopbackPorts'
       Net = (DenyDefault -Allow @()); Rc = @{ networkProxy = $proxyUrl }; Allow = @('declared') }
    # Rejection surface (PC: rejections). Never admitted on any build.
    @{ Id = 'X01'; Area = 'rejection'; Cap = 'legacy network.allowedHosts'; Needs = '-'; Reject = $true
       Net = @{ allowedHosts = @('example.com') } }
    @{ Id = 'X02'; Area = 'rejection'; Cap = 'legacy network.proxy'; Needs = '-'; Reject = $true
       Net = @{ proxy = @{ url = 'http://127.0.0.1:8888' } } }
    @{ Id = 'X03'; Area = 'rejection'; Cap = 'malformed CIDR'; Needs = '-'; Reject = $true
       Net = (DenyDefault -Allow @(Rule -Cidr '127.0.0.1/33' -Protocol tcp -Port $D)) }
    @{ Id = 'X04'; Area = 'rejection'; Cap = 'loopback port 0'; Needs = '-'; Reject = $true
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

$calls = @(
    "Test-Tcp 'other' '127.0.0.1' $($other.Port) '$($other.Nonce)'",
    "Test-Tcp 'external' '$ExternalAddress' $ExternalPort `$null",
    "Test-Tcp 'linklocal' '169.254.169.254' 80 `$null",
    "Test-Udp 'udp' '$ExternalAddress' 53 '$DnsName'",
    "Test-Icmp 'icmp' '$ExternalAddress'",
    "Test-Dns 'dns' '$DnsName'",
    # A nonce forces the read, so a relay reset (10054) is observed rather than its local accept.
    "Test-Tcp 'down' '127.0.0.1' $downPort 'MXC-NO-LISTENER'",
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
$probeCommand = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand $b64"
# Session launch refuses longer command lines ("The command line is too long."); keep under 8191.
if ($probeCommand.Length -gt 8191) {
    Write-Host "FAILED: probe command is $($probeCommand.Length) characters; the limit is 8191." -ForegroundColor Red
    Stop-Fixtures
    exit 1
}

$v6Text = if ($v6) { "::1:$D" } else { 'none' }
Write-Host ("Listeners: declared=$D other=$($other.Port) v6=$v6Text down=$downPort; " +
    "external=$ExternalAddress`:$ExternalPort") -ForegroundColor DarkGray
try {
    foreach ($r in $Matrix) {
        $expected = if ($r.Reject) { 'rejected' }
            elseif ($r.Invalid) { 'rejected: networkProxy needs deny-by-default egress with no direct rules' }
            else { "admitted with {$($r.Allow -join ',')} or rejected naming network" }
        try {
            $req = New-Request -Network $r.Net -RuntimeConfig $r.Rc -CommandLine $probeCommand
            $run = Invoke-WxcRequest -Request $req
            if ($run.Killed) { $script:Killed += $r.Id }
            $verdicts = @{}
            foreach ($m in [regex]::Matches($run.Output, 'PROBE (\S+) (\S+)')) {
                $verdicts[$m.Groups[1].Value] = $m.Groups[2].Value
            }
            $admitted = $verdicts.Count -gt 0
            $tail = (($run.Output -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' | '
            # A rejection counts only as a typed admission error on a clean exit 1.
            $rej = if ($admitted) { $null } else { Get-Rejection $run }
            $got = if ($rej) { "rejected ($($rej.Code))" } else { "exit $($run.ExitCode), no admission error" }
            if ($run.Killed) {
                Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected "killed after $($SessionTimeoutMs + $KillGraceMs) ms" 'FAIL' $tail
            } elseif (-not $run.Complete) {
                Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected "exit $($run.ExitCode)" 'FAIL' 'output capture incomplete'
            } elseif ($r.Reject) {
                if ($admitted) {
                    Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected 'admitted' 'FAIL' 'a rejection-surface request was admitted'
                } elseif ($rej) {
                    Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected $got 'PASS'
                } else {
                    Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected $got 'FAIL' $tail
                }
            } elseif ($admitted -and $r.Invalid) {
                Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected 'admitted' 'FAIL' 'an invalid proxy shape was admitted'
            } elseif ($admitted -and $r.Unprobed) {
                Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected 'admitted' 'FAIL' "admitted; no probe for $($r.Unprobed)"
            } elseif ($admitted) {
                # udp and icmp controls can change during the pass, so judge against fresh ones.
                Update-ProtocolControls
                $pv = Get-PostureVerdict -Verdicts $verdicts -Allow $r.Allow `
                    -DnsRequired:([bool]$r.DnsRequired) -LinkLocalJudged:([bool]$r.LinkLocalJudged)
                $ok = $pv.Ok
                $why = $pv.Why
                if ($ok -and $r.DownCode -and $verdicts['down'] -ne $r.DownCode) {
                    $ok = $false; $why = "declared port with no listener must fail with $($r.DownCode)"
                }
                if ($ok -and $run.ExitCode -ne 0) { $ok = $false; $why = "session exited $($run.ExitCode)" }
                # A fixture that broke during the row makes its verdicts meaningless.
                $fx = @(Test-Fixtures)
                if ($fx.Count -gt 0) { $ok = $false; $why = "fixture unhealthy: $($fx -join ', ')" }
                $llNote = $null
                if ($ok -and $r.LinkLocalJudged) {
                    # The property is non-reachability, so a block passes; the host control is recorded only.
                    if ($null -eq $script:HostLinkLocal) {
                        $script:HostLinkLocal = (Test-Tcp 'linklocal' '169.254.169.254' 80 $null) -eq 'PROBE linklocal CONNECTED'
                    }
                    if (-not $script:HostLinkLocal) {
                        $llNote = 'blocked (no host control: the host cannot reach 169.254.169.254:80)'
                    }
                }
                $detail = @(@($why, $llNote, $r.Note) | Where-Object { $_ })
                if (-not $r.DnsRequired) { $detail += "dns=$($verdicts['dns']) (report-only)" }
                foreach ($t in @('udp', 'icmp', 'v6')) {
                    if (-not $HostOk[$t] -and $verdicts[$t] -ne $Reach[$t]) {
                        $detail += "$t not judged: no host control ($t=$($verdicts[$t]))"
                    }
                }
                Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected "admitted: $($pv.Actual)" `
                    ($(if ($ok) { 'PASS' } else { 'FAIL' })) ($detail -join '; ')
            } elseif ($rej -and $r.PassOnRejection -and $rej.Message -cmatch "\b$($r.PassOnRejection)\b") {
                Add-Row $r.Id $r.Area $r.Cap $r.PassOnRejection $expected "rejected ($($r.PassOnRejection))" 'PASS'
            } elseif ($rej -and $rej.Message -match $NetworkRejection) {
                $needs = $r.Needs
                if ($rej.Message -match "requires platform capability '([A-Za-z]+)'") { $needs = $Matches[1] }
                if ($r.Baseline) {
                    Add-Row $r.Id $r.Area $r.Cap $needs $expected $got 'FAIL' $rej.Message
                } else {
                    Add-Row $r.Id $r.Area $r.Cap $needs $expected 'rejected (network)' 'UNSUPPORTED'
                }
            } elseif ($rej -and $r.Invalid -and $rej.Message -match 'networkProxy requires network\.egress\.default') {
                Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected 'rejected (proxy shape)' 'PASS'
            } else {
                $why = if ($rej) { $rej.Message } else { $tail }
                Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected $got 'FAIL' $why
            }
        } catch {
            Add-Row $r.Id $r.Area $r.Cap $r.Needs $expected 'runner error' 'FAIL' $_.Exception.Message
        }
    }
} finally {
    Stop-Fixtures
}

if ($script:Killed.Count -gt 0) {
    Add-Row 'G13' 'quiesce' 'killed wxc-exec may leave its agent user' '-' 'no killed wxc-exec' `
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
