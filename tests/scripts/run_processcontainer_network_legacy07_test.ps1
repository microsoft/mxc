# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_network_legacy07_test.ps1
#
# Legacy 0.7 network fields (defaultPolicy / allowedHosts / firewall rules).
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_network_legacy07_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = every assertion passed, 1 = at least one failed (or none
# ran), 78 = MXC-FATAL safety abort, which stops the whole suite.

[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$CargoRoot,
    [string]$WxcDebug,
    [string]$WxcRelease,
    [string]$UiProbeDebug,
    [string]$UiProbeRelease,
    [string]$ScratchRoot,
    [string]$ResultsJson,
    [string]$CargoLog,
    # Host capabilities probed once by the entry script and handed down, so
    # nineteen child processes do not each re-run --probe. Absent (a standalone
    # run) means probe the host here.
    [string]$CapsJson,
    # Not [ValidateSet]-decorated: the attribute binds to the variable, and
    # Initialize-WpcContext assigns through it. It validates the value instead.
    [string]$RequireTier,
    [string]$ExternalAnchorUrl,
    [string]$UnlistedDestinationUrl,
    [switch]$SkipNetwork,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts,
    # Set by the entry script, which owns the scratch tree and has already
    # populated it. A standalone run leaves this off and gets a freshly wiped
    # tree of its own.
    [switch]$ReuseScratch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 9 — LEGACY network fields, pinned at schema 0.7.
#
# The 0.6/0.7 shape (defaultPolicy / enforcementMode / allowedHosts /
# blockedHosts) is a different parse path from the directional shape and stays
# on 0.7 deliberately. os-version-support.md states capability- and
# firewall-based enforcement works on every release, so these run on any tier.
#
# The firewall lane also closes the teardown asymmetry: the DACL side asserts
# apply -> restore -> orphan reap in three phases, while nothing ever checked
# that `netsh advfirewall` rules created for a container are removed when it
# exits. A leaked allow rule outlives the sandbox it was scoped to.
# -----------------------------------------------------------------------
function Phase-NetworkLegacy07 {
    Section 'Phase 9: legacy network fields (schema 0.7)'

    if ($SkipNetwork) {
        Record-Result -Phase 'P9' -Name 'legacy network' -Status 'skip' -Detail '-SkipNetwork'
        return
    }

    $fs = Get-NetFsGrants
    $cmd = Get-AnchorFetchCommand

    # defaultPolicy allow vs block, capability enforcement. The pair is the
    # assertion: either verdict alone is unattributable.
    $cfgAllow = New-Config -Name 'net07-cap-allow' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -LegacyDefaultPolicy 'allow' -LegacyEnforcementMode 'capabilities' -TimeoutMs 30000
    $cfgBlock = New-Config -Name 'net07-cap-block' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -LegacyDefaultPolicy 'block' -LegacyEnforcementMode 'capabilities' -TimeoutMs 30000

    $allow = Invoke-NetRun -Name 'net07-cap-allow' -ConfigPath $cfgAllow
    $block = Invoke-NetRun -Name 'net07-cap-block' -ConfigPath $cfgBlock

    Record-Result -Phase 'P9' -Name 'schema 0.7 config is accepted (version pinned to 0.7.0-alpha)' `
        -Pass ($allow.Verdict -ne 'NORUN' -or $allow.Result.ExitCode -eq 0) `
        -Detail "exit=$($allow.Result.ExitCode)"
    Record-Result -Phase 'P9' -Name 'legacy defaultPolicy=allow reaches the anchor' `
        -Pass ($allow.Verdict -eq 'REACHED') -Detail "verdict=$($allow.Verdict)"
    Record-Result -Phase 'P9' -Name 'legacy defaultPolicy=block does not reach the anchor' `
        -Pass ($block.Verdict -eq 'BLOCKED') -Detail "verdict=$($block.Verdict)"
    Record-Result -Phase 'P9' -Name 'legacy allow/block differ (policy is what changed the outcome)' `
        -Pass ((Test-VerdictsRan @($allow, $block)) -and ($allow.Verdict -ne $block.Verdict)) `
        -Detail "allow=$($allow.Verdict); block=$($block.Verdict)"

    # Explicit internetClient capability, and the negative control that makes
    # the grant meaningful: same policy, capability withheld.
    $cfgCap = New-Config -Name 'net07-explicit-capability' -CommandLine $cmd `
        -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
        -LegacyDefaultPolicy 'allow' -LegacyEnforcementMode 'capabilities' `
        -Capabilities @('internetClient') -TimeoutMs 30000
    $cap = Invoke-NetRun -Name 'net07-explicit-capability' -ConfigPath $cfgCap
    Record-Result -Phase 'P9' -Name 'explicit processContainer.capabilities=[internetClient] reaches the anchor' `
        -Pass ($cap.Verdict -eq 'REACHED') -Detail "verdict=$($cap.Verdict)"
    Record-Result -Phase 'P9' -Name 'explicit capability is named in the log' `
        -Pass ([bool]((Remove-ConfigEcho $cap.Log) -match '(?i)internetClient')) `
        -Detail 'capability list reached the backend (config echo stripped)'

    # enforcementMode matrix. `firewall` and `both` need admin for netsh; a
    # non-admin host cannot exercise them, which is a skip rather than a pass.
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    foreach ($mode in @('firewall', 'both')) {
        if (-not $isAdmin) {
            Record-Result -Phase 'P9' -Name "enforcementMode=$mode" -Status 'skip' `
                -Detail 'netsh advfirewall rule authoring requires an elevated host'
            continue
        }
        $before = Get-MxcFirewallRuleNames
        $cfgMode = New-Config -Name "net07-mode-$mode" -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -LegacyDefaultPolicy 'block' -LegacyEnforcementMode $mode `
            -LegacyAllowedHosts @(([Uri]$ExternalAnchorUrl).Host) `
            -Capabilities @('internetClient') -TimeoutMs 40000

        # Sample the rule set WHILE the container is alive. Comparing only
        # before/after cannot tell "rules were applied and cleaned up" from
        # "enforcementMode was silently ignored and no rule ever existed" —
        # and the second is exactly the drift this phase exists to catch, so
        # without a mid-run sample the leak assertion cannot fail in the
        # interesting direction. The workload fetches for up to 40s, which is
        # the window this poll runs in.
        $sampler = [PowerShell]::Create()
        [void]$sampler.AddScript({
            param($deadlineSec)
            $seen = [System.Collections.Generic.HashSet[string]]::new()
            $end = (Get-Date).AddSeconds($deadlineSec)
            while ((Get-Date) -lt $end) {
                $rules = & netsh.exe advfirewall firewall show rule name=all 2>$null
                foreach ($m in ($rules | Select-String -Pattern '(WXC_[A-Za-z0-9_.-]+)' -AllMatches |
                                ForEach-Object { $_.Matches })) {
                    [void]$seen.Add($m.Groups[1].Value.Trim())
                }
                Start-Sleep -Milliseconds 400
            }
            return @($seen)
        }).AddArgument(55)
        $samplerHandle = $sampler.BeginInvoke()

        $run = Invoke-NetRun -Name "net07-mode-$mode" -ConfigPath $cfgMode -TimeoutSec 60
        $after = Get-MxcFirewallRuleNames
        $duringRaw = @()
        try { $duringRaw = @($sampler.EndInvoke($samplerHandle)) } catch {}
        try { $sampler.Dispose() } catch {}
        $during = @($duringRaw | Where-Object { $_ -notin $before })

        Record-Result -Phase 'P9' -Name "enforcementMode=${mode}: allowedHosts entry is reachable" `
            -Pass ($run.Verdict -eq 'REACHED') `
            -Detail "verdict=$($run.Verdict); allowedHosts=$(([Uri]$ExternalAnchorUrl).Host)"
        Record-Result -Phase 'P9' -Name "enforcementMode=${mode}: firewall rules are actually installed during the run" `
            -Pass ($during.Count -gt 0) `
            -Detail ("observed=$($during.Count); " +
                     'a zero here means the mode was accepted and silently not enforced, which also makes the leak check below vacuous')
        # The teardown assertion the DACL side has had all along. Only
        # meaningful once something was installed to leak.
        $leaked = @($after | Where-Object { $_ -notin $before })
        Record-Result -Phase 'P9' -Name "enforcementMode=${mode}: no firewall rules leaked after the run" `
            -Pass (($during.Count -gt 0) -and ($leaked.Count -eq 0)) `
            -Detail "installed=$($during.Count); leaked=$($leaked.Count)$(if ($leaked.Count) { ': ' + ($leaked -join ', ') })"
    }

    # blockedHosts under an allow default: the destination named is the one
    # that must fail while the default still permits everything else.
    if ($isAdmin) {
        $cfgBlocked = New-Config -Name 'net07-blockedhosts' -CommandLine $cmd `
            -ReadWrite $fs.ReadWrite -ReadOnly $fs.ReadOnly `
            -LegacyDefaultPolicy 'allow' -LegacyEnforcementMode 'firewall' `
            -LegacyBlockedHosts @(([Uri]$ExternalAnchorUrl).Host) `
            -Capabilities @('internetClient') -TimeoutMs 40000
        $blocked = Invoke-NetRun -Name 'net07-blockedhosts' -ConfigPath $cfgBlocked -TimeoutSec 60
        Record-Result -Phase 'P9' -Name 'blockedHosts entry is unreachable under an allow default' `
            -Pass ($blocked.Verdict -eq 'BLOCKED') -Detail "verdict=$($blocked.Verdict)"
    } else {
        Record-Result -Phase 'P9' -Name 'blockedHosts under allow default' -Status 'skip' `
            -Detail 'firewall enforcement requires an elevated host'
    }
}

Invoke-WpcPhase -Key 'NetworkLegacy07' -Body { Phase-NetworkLegacy07 }
Complete-WpcChild

