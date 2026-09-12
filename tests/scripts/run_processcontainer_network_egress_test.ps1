# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Explicit egress allow/deny rules (PSEC-only per the 0.8 spec).
#
# Runs standalone, or under run_processcontainer_all_tests.ps1.

[CmdletBinding()]
param(
    [string]$ContextJson,

    [string]$ResultsJson,
    [string]$RequireTier,
    [switch]$SkipNetwork,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

Initialize-WpcContext @PSBoundParameters


# Phase 8c — explicit WFP egress rules (PSEC only).
#
# From docs/process-container/networking.md §3 and the shared spec's D4: a
# CIDR/port allow permits that destination and still blocks everything else,
# and an explicit deny beats an overlapping allow. Off PSEC the documented
# behavior is a typed rejection — a silently dropped rule set would leave the
# caller believing egress is filtered while it is wide open.
function Phase-NetworkEgressRules {
    Section 'Phase 8c: explicit egress rules (WFP / PSEC-only)'

    if ($SkipNetwork) {
        Record-Result -Phase 'P8c' -Name 'explicit egress rules' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible

    $fs = Get-NetFsGrants
    $psec = Test-PsecEligible

    # Probe the negative control's destination up front. On a runner behind an
    # allowlisting proxy that permits the anchor but not this destination, the
    # control reads BLOCKED and scores green while proving nothing — an
    # unattributable negative, the exact failure the control exists to prevent.
    # Recorded as a failure, then used to gate only the assertion that depends
    # on it: the rest of the phase (including the whole documented rejection
    # surface on a non-PSEC tier) needs no second destination.
    $unlistedUsable = Test-HostCanReachAnchor -Url $UnlistedDestinationUrl
    if (-not $unlistedUsable) {
        Record-Result -Phase 'P8c' -Name 'prerequisite: host reaches the unlisted-destination control' `
            -Pass $false `
            -Detail ("$UnlistedDestinationUrl is unreachable from the host, so a BLOCKED verdict inside the " +
                     'container would not be attributable to the egress rules. Pass -UnlistedDestinationUrl <reachable-url>.')
    }

    # Resolve the anchor to an address so an allow rule can name it. DNS
    # itself follows the same egress rules (documented), so the rule set must
    # also permit UDP/53 to the resolver for the allow case to be reachable.
    $anchorHost = ([Uri]$ExternalAnchorUrl).Host
    $anchorIps = @()
    try {
        $anchorIps = @([System.Net.Dns]::GetHostAddresses($anchorHost) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.IPAddressToString })
    } catch {}

    if ($anchorIps.Count -eq 0) {
        Record-Result -Phase 'P8c' -Name 'resolve anchor for CIDR rules' -Pass $false `
            -Detail "could not resolve $anchorHost from the host; cannot author an address-scoped rule"
        return
    }

    # Allow the anchor's /32 on tcp/443 plus DNS to every resolver the host
    # uses. Anything else stays denied by the egress default.
    $dnsServers = Get-HostDnsServers
    $allowRules = @()
    foreach ($ip in $anchorIps) {
        $allowRules += (New-EgressRule -Cidr @("$ip/32") -Protocol 'tcp' -Port 443)
    }
    foreach ($dns in $dnsServers) {
        $allowRules += (New-EgressRule -Cidr @("$dns/32") -Protocol 'udp' -Port 53)
    }

    $cfgAllow = New-Config -Name 'net-rules-allow-anchor' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' `
        -EgressAllow $allowRules -TimeoutMs 30000
    $allow = Invoke-NetRun -Name 'net-rules-allow-anchor' -ConfigPath $cfgAllow

    # D4: an explicit deny on the same destination must beat the allow.
    $denyRules = @(foreach ($ip in $anchorIps) { New-EgressRule -Cidr @("$ip/32") -Protocol 'tcp' -Port 443 })
    $cfgPrecedence = New-Config -Name 'net-rules-deny-precedence' `
        -CommandLine (Get-AnchorFetchCommand) `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' `
        -EgressAllow $allowRules -EgressDeny $denyRules -TimeoutMs 30000
    $precedence = Invoke-NetRun -Name 'net-rules-deny-precedence' -ConfigPath $cfgPrecedence

    # Negative control: same allow rule set, but the workload reaches for a
    # destination the rules never named. Without this, "allow worked" and
    # "nothing was filtered" look identical.
    $unlisted = $null
    if ($unlistedUsable) {
        $cfgUnlisted = New-Config -Name 'net-rules-unlisted-dest' `
            -CommandLine (Get-AnchorFetchCommand -Url $UnlistedDestinationUrl) `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -EgressDefault 'deny' -IngressDefault 'deny' -HostLoopback 'deny' `
            -EgressAllow $allowRules -TimeoutMs 30000
        $unlisted = Invoke-NetRun -Name 'net-rules-unlisted-dest' -ConfigPath $cfgUnlisted
    }

    if ($psec) {
        Record-Result -Phase 'P8c' -Name 'egress allow rule permits the named CIDR:443' `
            -Pass ($allow.Verdict -eq 'REACHED') `
            -Detail "verdict=$($allow.Verdict); rules=$($allowRules.Count); exit=$($allow.Result.ExitCode)"
        Record-Result -Phase 'P8c' -Name 'unlisted destination still blocked under the same rule set' `
            -Pass ($null -ne $unlisted -and $unlisted.Verdict -eq 'BLOCKED') `
            -Detail $(if ($null -eq $unlisted) { 'not run: the control destination is unreachable from the host' }
                      else { "verdict=$($unlisted.Verdict)" })
        Record-Result -Phase 'P8c' -Name 'D4: explicit deny overrides overlapping explicit allow' `
            -Pass ($precedence.Verdict -eq 'BLOCKED') `
            -Detail "verdict=$($precedence.Verdict)"
    } else {
        # Documented: "Explicit egress rules, proxy peer identity, and
        # host-loopback allow fail with a typed unsupported-policy error when
        # PSEC cannot enforce them."
        foreach ($case in @(
            @{ Tag = 'allow rules';      Run = $allow },
            @{ Tag = 'deny rules';       Run = $precedence })) {
            $rejected = Test-WasRejected $case.Run
            Record-Result -Phase 'P8c' -Name "non-PSEC tier rejects explicit egress $($case.Tag)" `
                -Pass $rejected `
                -Detail "verdict=$($case.Run.Verdict); exit=$($case.Run.Result.ExitCode); timedOut=$($case.Run.Result.TimedOut); tier=$($Script:ExpectedTier)"
        }
        $combined = @((Remove-ConfigEcho "$($allow.Result.Stderr)"), (Remove-ConfigEcho "$($allow.Log)")) -join "`n"
        Record-Result -Phase 'P8c' -Name 'rejection is a typed unsupported-policy error' `
            -Pass ([bool]($combined -match '(?i)unsupported|not supported|policy_validation|unsupported_policy')) `
            -Detail 'documented as a typed error, not a silent drop'
    }
}

Invoke-WpcPhase -Key 'NetworkEgressRules' -Body { Phase-NetworkEgressRules }
Complete-WpcChild

