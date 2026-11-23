# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Unit tests for the row classifier in run_isolation_session_network_test.ps1. They feed it
# synthetic wxc-exec runs, so they need no VM, no isolation session and no feature keys.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'run_isolation_session_network_test.ps1') -ClassifierOnly

$script:Failures = 0
function Assert-Verdict {
    param([string]$Name, $Result, [string]$Verdict, [string]$DetailLike)
    $ok = $Result.Verdict -eq $Verdict
    if ($ok -and $DetailLike) { $ok = "$($Result.Detail) $($Result.Actual)" -like "*$DetailLike*" }
    if ($ok) {
        Write-Host "PASS: $Name"
    } else {
        Write-Host "FAIL: $Name -- expected $Verdict ($DetailLike), got $($Result.Verdict): $($Result.Actual) | $($Result.Detail)"
        $script:Failures++
    }
}

# Every target blocked, as a deny-all session reports it; $Set overrides targets, $null drops one.
function New-ProbeRun {
    param([hashtable]$Set = @{}, [int]$ExitCode = 0, [string[]]$Extra = @())
    $base = [ordered]@{
        external = 'WSA10051'; udp = 'WSA10051'; icmp = 'UNREACH'; dns = 'WSA11004'; declared = 'WSA10013'
        other = 'WSA10013'; v6 = 'WSA10013'; down = 'WSA10013'; linklocal = 'WSA10013'
    }
    foreach ($k in $Set.Keys) { $base[$k] = $Set[$k] }
    $lines = @($base.Keys | Where-Object { $null -ne $base[$_] } | ForEach-Object { "PROBE $_ $($base[$_])" })
    return [pscustomobject]@{ ExitCode = $ExitCode; Output = (($lines + $Extra) -join "`n"); Killed = $false; Complete = $true }
}

function New-RejectRun([string]$Code, [string]$Message, [int]$ExitCode = 1) {
    $json = @{ error = @{ code = $Code; message = $Message } } | ConvertTo-Json -Compress
    return [pscustomobject]@{ ExitCode = $ExitCode; Output = $json; Killed = $false; Complete = $true }
}

$allOk = @{ udp = $true; icmp = $true; v6 = $true }
$deny = @{ egress = @{ default = 'deny' } }
$a01 = @{ Id = 'A01'; Net = @{ egress = @{ default = 'allow' } }; Baseline = $true; DnsRequired = $true
          Allow = @('external', 'udp', 'icmp', 'dns', 'linklocal') }
$a02 = @{ Id = 'A02'; Net = $deny; Allow = @() }
$a03 = @{ Id = 'A03'; Net = $null; Allow = @() }
$e08 = @{ Id = 'E08'; Net = $deny; Allow = @() }
$e09 = @{ Id = 'E09'; Net = $deny; Allow = @('icmp') }
$e13 = @{ Id = 'E13'; Net = $deny; Allow = @(); MetadataBlocked = $true }
$e14net = @{ egress = @{ default = 'allow' } }
$l01 = @{ Id = 'L01'; Net = $deny; Allow = @('declared') }
$l02 = @{ Id = 'L02'; Net = $deny; Allow = @('declared', 'down'); AllowAfterStop = @('declared') }
$x03 = @{ Id = 'X03'; Net = $deny; Reject = $true; Field = 'the CIDR'
          Own = '\bnetwork\.egress\.allow\[0\]\.to\[0\]\.cidr\b' }
$netMsg = 'the isolation session backend does not support network egress rules'
$a01Reach = @{ external = 'CONNECTED'; udp = 'ANSWERED'; icmp = 'ECHOED'; dns = 'RESOLVED' }

# Deny-all posture.
Assert-Verdict 'deny-all blocked everywhere passes' (Get-RowVerdict -Row $a02 -Run (New-ProbeRun) -HostOk $allOk) 'PASS'
Assert-Verdict 'reached external where denied fails' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun @{ external = 'CONNECTED' }) -HostOk $allOk) 'FAIL' 'broader than requested'
# F1: the metadata address is judged in every row whose policy denies it.
Assert-Verdict 'reached metadata in deny row fails' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun @{ linklocal = 'CONNECTED' }) -HostOk $allOk) 'FAIL' 'linklocal=CONNECTED'
Assert-Verdict 'reached metadata with no network fails' `
    (Get-RowVerdict -Row $a03 -Run (New-ProbeRun @{ linklocal = 'CONNECTED' }) -HostOk $allOk) 'FAIL' 'linklocal=CONNECTED'
Assert-Verdict 'reached metadata in metadata row fails' `
    (Get-RowVerdict -Row $e13 -Run (New-ProbeRun @{ linklocal = 'CONNECTED' }) -HostOk $allOk) 'FAIL' 'linklocal=CONNECTED'
Assert-Verdict 'reached metadata under allow default is report-only' `
    (Get-RowVerdict -Row $a01 -Run (New-ProbeRun ($a01Reach + @{ linklocal = 'CONNECTED' })) -HostOk $allOk) 'PASS' 'report-only'
Assert-Verdict 'metadata report-only also for an allow-default row without MetadataBlocked' `
    (Get-RowVerdict -Row @{ Id = 'E05'; Net = $e14net; Allow = @('external', 'udp', 'icmp', 'dns', 'linklocal', 'other', 'declared') } `
        -Run (New-ProbeRun ($a01Reach + @{ linklocal = 'TIMEOUT'; other = 'REACHED'; declared = 'REACHED' })) -HostOk $allOk) 'PASS'
Assert-Verdict 'blocked metadata with no host control passes and says so' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun) -HostOk $allOk -HostLinkLocal $false) 'PASS' 'no host control'

# F3: every target needs exactly one valid record.
Assert-Verdict 'missing record fails even without a host control' `
    (Get-RowVerdict -Row $e08 -Run (New-ProbeRun @{ udp = $null }) -HostOk @{ udp = $false; icmp = $true; v6 = $true }) 'FAIL' 'udp=NORUN'
Assert-Verdict 'duplicate record fails' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun -Extra @('PROBE external CONNECTED')) -HostOk $allOk) 'FAIL' 'no single valid record'
Assert-Verdict 'unknown record fails' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun @{ other = 'MAYBE' }) -HostOk $allOk) 'FAIL' 'no single valid record'
Assert-Verdict 'missing report-only dns still fails' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun @{ dns = $null }) -HostOk $allOk) 'FAIL' 'dns=NORUN'

# Allowed but blocked, and indeterminate outcomes.
Assert-Verdict 'allowed declared port blocked fails' `
    (Get-RowVerdict -Row $l01 -Run (New-ProbeRun) -HostOk $allOk) 'FAIL' 'allowed target blocked'
Assert-Verdict 'allowed declared port reached passes' `
    (Get-RowVerdict -Row $l01 -Run (New-ProbeRun @{ declared = 'REACHED' }) -HostOk $allOk) 'PASS'
Assert-Verdict 'unexpected socket error on a denied target fails' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun @{ other = 'WSA10022' }) -HostOk $allOk) 'FAIL' 'indeterminate'
Assert-Verdict 'probe error on a denied target fails' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun @{ external = 'ERR' }) -HostOk $allOk) 'FAIL' 'indeterminate'
Assert-Verdict 'nonzero session exit fails' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun -ExitCode 3) -HostOk $allOk) 'FAIL' 'session exited 3'

# Host controls.
Assert-Verdict 'denied udp not reached without a host control is report-only' `
    (Get-RowVerdict -Row $e08 -Run (New-ProbeRun @{ udp = 'WSA10060' }) -HostOk @{ udp = $false; icmp = $true; v6 = $true }) 'PASS' 'udp not judged'
Assert-Verdict 'reached udp where denied fails even without a host control' `
    (Get-RowVerdict -Row $e08 -Run (New-ProbeRun @{ udp = 'ANSWERED' }) -HostOk @{ udp = $false; icmp = $true; v6 = $true }) 'FAIL' 'broader'
Assert-Verdict 'allowed icmp without a host control fails' `
    (Get-RowVerdict -Row $e09 -Run (New-ProbeRun) -HostOk @{ udp = $true; icmp = $false; v6 = $true }) 'FAIL' 'no host control'

# Fixtures and run state.
Assert-Verdict 'fixture failure after the row fails it' `
    (Get-RowVerdict -Row $a02 -Run (New-ProbeRun) -HostOk $allOk -FixtureFailures @('PROBE other TIMEOUT')) 'FAIL' 'fixture unhealthy'
$killed = New-ProbeRun; $killed.Killed = $true
Assert-Verdict 'killed run fails' (Get-RowVerdict -Row $a02 -Run $killed -HostOk $allOk) 'FAIL' 'killed'
$partial = New-ProbeRun; $partial.Complete = $false
Assert-Verdict 'incomplete capture fails' (Get-RowVerdict -Row $a02 -Run $partial -HostOk $allOk) 'FAIL' 'incomplete'

# Typed rejections.
Assert-Verdict 'network rejection is unsupported' `
    (Get-RowVerdict -Row $l01 -Run (New-RejectRun 'policy_validation' $netMsg)) 'UNSUPPORTED'
Assert-Verdict 'network rejection of a baseline row fails' `
    (Get-RowVerdict -Row $a01 -Run (New-RejectRun 'policy_validation' $netMsg)) 'FAIL'
Assert-Verdict 'backend error is not a rejection' `
    (Get-RowVerdict -Row $l01 -Run (New-RejectRun 'backend_error' $netMsg)) 'FAIL'
Assert-Verdict 'rejection on exit 0 is not a rejection' `
    (Get-RowVerdict -Row $l01 -Run (New-RejectRun 'policy_validation' $netMsg -ExitCode 0)) 'FAIL'
Assert-Verdict 'rejection naming the field passes' `
    (Get-RowVerdict -Row $x03 -Run (New-RejectRun 'malformed_request' 'invalid network.egress.allow[0].to[0].cidr: 127.0.0.1/33')) 'PASS'
Assert-Verdict 'rejection by the network rule does not judge the field' `
    (Get-RowVerdict -Row $x03 -Run (New-RejectRun 'policy_validation' $netMsg)) 'UNSUPPORTED' 'not judged'
Assert-Verdict 'admitted rejection-surface request fails' `
    (Get-RowVerdict -Row $x03 -Run (New-ProbeRun) -HostOk $allOk) 'FAIL' 'was admitted'

# F4: L02 listener up, then down.
Assert-Verdict 'L02 listener up: reached passes' `
    (Get-RowVerdict -Row $l02 -Run (New-ProbeRun @{ declared = 'REACHED'; down = 'REACHED' }) -HostOk $allOk) 'PASS'
Assert-Verdict 'L02 listener up: blocked fails' `
    (Get-RowVerdict -Row $l02 -Run (New-ProbeRun @{ declared = 'REACHED' }) -HostOk $allOk) 'FAIL' 'allowed target blocked: down'
Assert-Verdict 'L02 listener down: blocked passes' `
    (Get-RowVerdict -Row $l02 -Run (New-ProbeRun @{ declared = 'REACHED'; down = 'WSA10054' }) -HostOk $allOk -Allow $l02.AllowAfterStop) 'PASS'
Assert-Verdict 'L02 listener down: still reached fails' `
    (Get-RowVerdict -Row $l02 -Run (New-ProbeRun @{ declared = 'REACHED'; down = 'REACHED' }) -HostOk $allOk -Allow $l02.AllowAfterStop) 'FAIL' 'broader'
# The two phases combined: only a listener-down PASS passes, and a rejection after an admitted
# listener-up phase fails instead of reading as UNSUPPORTED.
$l02Up = Get-RowVerdict -Row $l02 -Run (New-ProbeRun @{ declared = 'REACHED'; down = 'REACHED' }) -HostOk $allOk
$l02DownOk = Get-RowVerdict -Row $l02 -Run (New-ProbeRun @{ declared = 'REACHED'; down = 'WSA10061' }) -HostOk $allOk -Allow $l02.AllowAfterStop
$l02DownReached = Get-RowVerdict -Row $l02 -Run (New-ProbeRun @{ declared = 'REACHED'; down = 'REACHED' }) -HostOk $allOk -Allow $l02.AllowAfterStop
$l02DownRejected = Get-RowVerdict -Row $l02 -Run (New-RejectRun 'policy_validation' $netMsg) -HostOk $allOk -Allow $l02.AllowAfterStop
Assert-Verdict 'L02 both phases pass' (Join-L02Verdict $l02Up $l02DownOk) 'PASS' 'listener down:'
Assert-Verdict 'L02 down still reached fails' (Join-L02Verdict $l02Up $l02DownReached) 'FAIL'
Assert-Verdict 'L02 down rejected after admitted up fails' (Join-L02Verdict $l02Up $l02DownRejected) 'FAIL' 'listener down was UNSUPPORTED'

if ($script:Failures -gt 0) { throw "$($script:Failures) classifier test(s) failed." }
Write-Host 'All classifier tests passed.'
