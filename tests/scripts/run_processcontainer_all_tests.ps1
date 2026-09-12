# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_all_tests.ps1
#
# Entry point for the Windows process-container (AppContainer / BaseContainer)
# suite. Probes the host once, then dispatches each area to its own
# run_processcontainer_*_test.ps1 and merges the results.
#
# The harness is capability-driven and runs on any Windows host: it derives the
# EXPECTED containment tier from the runtime --probe signals rather than
# hardcoding it (see Get-HostCapabilities in lib\WinProcessContainer.Common.ps1).
#
# Tier scope:
#   T1 (BaseContainer) and T3 (AppContainer + DACL) only. T2 (`appcontainer-bfs`)
#   is NOT covered — it is off by default behind the `tier2_bfs` Cargo feature
#   and is not in use, so the suite records no assertions about it. What remains
#   below is a guard, not coverage.
#
# Safety model (`tier2_bfs` Cargo feature OFF, the default):
#   * The suite never invokes bfscfg.exe, which hard-locks the bfs.sys
#     minifilter on 25H2.
#   * Test-Preflight refuses to run if either wxc-exec binary reports
#     `bfsCompiledIn=true` in --probe output. This is the load-bearing gate;
#     everything else is belt-and-suspenders. It applies on every build, so no
#     OS-version branching is needed. Every child re-runs the gate
#     (Assert-BfsSafety) so a directly invoked script cannot skip it.
#   * With `tier2_bfs` off, `fallback_detector::find_bfscfg_exe` returns
#     `Ok(None)` unconditionally, `appcontainer-bfs` is never selected, and the
#     dispatcher falls back to BaseContainer (T1, when usable) or
#     AppContainer + DACL (T3).
#   * Every run is post-checked by Assert-NoBfscfg. If a log shows bfscfg being
#     spawned, or `appcontainer-bfs` being selected, that is MXC-FATAL: the
#     child exits 78 and dispatch stops immediately. These raise rather than
#     record, precisely because they are guards and not test coverage.
#   * Tier selection is NATURAL — there is no -ForceTier and no MXC_FORCE_TIER
#     manipulation (that env var is `#[cfg(test)]`-gated and has no effect on a
#     production wxc-exec).
#
# Tier expectations are identical for every policy shape:
#   * BaseContainer usable -> `base-container`
#   * otherwise            -> `appcontainer-dacl`
# $Script:ExpectedTier (derived once at startup, passed to every child) drives
# every tier assertion.
#
# Schema version:
#   Configs are authored at 0.8.0-alpha ($Script:SchemaVersion). The LEGACY
#   network fields — defaultPolicy / enforcementMode / allowedHosts /
#   blockedHosts / allowLocalNetwork / network.proxy — are pinned to 0.7.0-alpha
#   ($Script:LegacySchemaVersion), because 0.8 is where the directional
#   network.egress / network.ingress shape became the documented way to express
#   network intent. New-Config switches lanes automatically when a -Legacy*
#   parameter is supplied.
#
# What the network areas assert:
#   The DOCUMENTED contract, not the current implementation. The authoritative
#   sources are docs/process-container/networking.md and
#   docs/sandbox-policy/0.8.0/networking/networking.md. Where the backend has
#   not caught up, the assertion FAILS — that is the intended signal. A suite
#   that only encodes present behavior cannot tell anyone the backend drifted
#   from its spec.
#
# Prerequisites are failures, not skips:
#   * -RequireTier <tier> aborts when the host does not naturally select that
#     tier. Without it, a mis-provisioned T1 runner silently runs the T3
#     assertions and reports green having proven nothing about BaseContainer.
#   * The egress anchor is probed from the HOST before any network area runs. A
#     host with no connectivity would read every positive assertion as
#     "blocked", so an unreachable anchor aborts. -SkipNetwork is the explicit
#     opt-out for air-gapped bring-up.
#   * A child that records no assertions at all fails. Reporting success for a
#     script that proved nothing is the false green this suite exists to avoid.
#
# Usage:
#   .\run_processcontainer_all_tests.ps1
#   .\run_processcontainer_all_tests.ps1 -SkipBuild -RequireTier base-container
#   .\run_processcontainer_all_tests.ps1 -Areas NetworkProxy,NetworkEgressRules
#
# Each area also runs standalone — see run_processcontainer_<area>_test.ps1.

[CmdletBinding()]
param(
    # Defaults for all of these live in Initialize-WpcContext, the single place
    # the suite writes one down. Left unset here so $PSBoundParameters carries
    # exactly what the operator asked for.
    [string]$RepoRoot,
    [string]$CargoRoot,
    [string]$WxcDebug,
    [string]$WxcRelease,
    [string]$UiProbeDebug,
    [string]$UiProbeRelease,
    [string]$ScratchRoot,
    [string]$ResultsFile,
    [string]$ResultsJson,
    [string]$CargoLog,
    [switch]$SkipBuild,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts,
    # Hard prerequisite on the containment tier. When set, the suite ABORTS if
    # the host does not naturally select this tier. Without it a mis-provisioned
    # T1 runner silently runs the T3 assertions (every expectation is derived
    # from $Script:ExpectedTier) and reports green having proven nothing about
    # BaseContainer. CI passes the tier its job name claims to cover. Same
    # doctrine as run_seatbelt_all_tests.sh: a missing prerequisite is a
    # FAILURE, not a skip.
    # The empty string is in the set on purpose, and means "no tier
    # requirement". ValidateSet binds to the VARIABLE, not just to parameter
    # binding, so it re-fires when Initialize-WpcContext publishes the suite
    # context back into this scope; omitting '' would make an unspecified
    # -RequireTier throw. The area scripts drop ValidateSet entirely and let
    # Initialize-WpcContext do the checking.
    [ValidateSet('', 'base-container', 'appcontainer-dacl')]
    [string]$RequireTier,
    # Reachability anchor for the positive egress assertions. An egress-allow
    # test that cannot distinguish "policy blocked it" from "this host has no
    # internet" proves nothing, so the suite probes this from the HOST first and
    # fails (never skips) when the host itself cannot reach it.
    [string]$ExternalAnchorUrl,
    # A second reachable destination, used as the negative control for the
    # explicit-egress-rule area: the allow rules name the anchor and nothing
    # else, so this one must be blocked INSIDE the container while remaining
    # reachable from the host. If the host cannot reach it either, a BLOCKED
    # verdict is unattributable and the area fails rather than scoring green.
    [string]$UnlistedDestinationUrl,
    # Opt out of every live-network area (air-gapped bring-up). The parse-only
    # rejection area still runs — it needs no connectivity.
    [switch]$SkipNetwork,
    # Restrict the run to a subset of areas. Accepts the keys in $Areas below,
    # e.g. -Areas UiMitigationMatrix. Empty = run everything. `-Phases` is
    # accepted as an alias for compatibility with the pre-split harness.
    [Alias('Phases')]
    [string[]]$Areas = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')

# Area registry: key -> the script that owns it. The keys are the contract with
# scripts\ci\run_backend_validation_tests.ps1 and are unchanged from the
# pre-split harness's phase names, so an existing -Phases list keeps working.
$AreaScripts = [ordered]@{
    'UnitTests'                = 'run_processcontainer_unit_tests_test.ps1'
    'Probes'                   = 'run_processcontainer_probes_test.ps1'
    'EmptyRelease'             = 'run_processcontainer_empty_release_test.ps1'
    'DeniedRelease'            = 'run_processcontainer_denied_release_test.ps1'
    'T3Forced'                 = 'run_processcontainer_filesystem_matrix_test.ps1'
    'T1DenyForced'             = 'run_processcontainer_denied_paths_test.ps1'
    'UiMitigationMatrix'       = 'run_processcontainer_ui_mitigations_test.ps1'
    'GlobalAtomIsolation'      = 'run_processcontainer_global_atom_test.ps1'
    'DaclDisabled'             = 'run_processcontainer_dacl_disabled_test.ps1'
    'CrashRecovery'            = 'run_processcontainer_crash_recovery_test.ps1'
    'NetworkCapabilityMatrix'  = 'run_processcontainer_network_capability_test.ps1'
    'NetworkModel3Equivalence' = 'run_processcontainer_network_model3_test.ps1'
    'NetworkEgressRules'       = 'run_processcontainer_network_egress_test.ps1'
    'NetworkHostLoopback'      = 'run_processcontainer_network_loopback_test.ps1'
    'NetworkProxy'             = 'run_processcontainer_network_proxy_test.ps1'
    'NetworkRejections'        = 'run_processcontainer_network_rejections_test.ps1'
    'NetworkLegacy07'          = 'run_processcontainer_network_legacy07_test.ps1'
    'PathAliasing'             = 'run_processcontainer_path_aliasing_test.ps1'
    'ProcessPlumbing'          = 'run_processcontainer_process_plumbing_test.ps1'
}

# Run children under the SAME PowerShell host as this process. Hardcoding
# powershell.exe would silently run the suite on Windows PowerShell 5.1 when the
# operator launched it from pwsh, and the two disagree on enough (ConvertTo-Json
# depth, error records, encoding) to change results.
$PSHostExe = (Get-Process -Id $PID).Path
if (-not $PSHostExe) { $PSHostExe = 'powershell.exe' }

# Validate the selection before anything expensive happens.
if ($Areas.Count -gt 0) {
    $unknown = @($Areas | Where-Object { $_ -notin $AreaScripts.Keys })
    if ($unknown.Count -gt 0) {
        throw "Unknown -Areas value(s): $($unknown -join ', '). Valid: $($AreaScripts.Keys -join ', ')"
    }
}
foreach ($key in $AreaScripts.Keys) {
    $path = Join-Path $PSScriptRoot $AreaScripts[$key]
    if (-not (Test-Path $path)) { throw "Area '$key' points at a missing script: $path" }
}

# Capture all host output to a transcript so an operator can paste a single path
# instead of scrolling. Stop-Transcript runs in `finally` so even an abort
# produces a complete transcript.
try { Stop-Transcript | Out-Null } catch {}
$Merged = [System.Collections.Generic.List[object]]::new()
$FatalAbort = $null
# Snapshot the operator's foreground colour so it can be re-asserted between
# areas and restored on the way out. $null when output is redirected.
$BaseConsoleColor = Get-WpcConsoleColor

try {
    # Initialize-WpcContext needs the transcript path resolved, but the default
    # lives inside it. Resolve early so Start-Transcript has somewhere to write.
    if (-not $ResultsFile) { $ResultsFile = Join-Path $env:TEMP 'WinProcessContainer-Tests.results.txt' }
    if (-not $ResultsJson) { $ResultsJson = Join-Path $env:TEMP 'WinProcessContainer-Tests.results.json' }
    $null = Start-Transcript -Path $ResultsFile -Force -IncludeInvocationHeader
} catch {
    Write-Host "warning: could not start transcript: $_" -ForegroundColor Yellow
}

try {
    $ctx = @{} + $PSBoundParameters
    $ctx.Remove('Areas') | Out-Null
    $ctx.Remove('Phases') | Out-Null
    $ctx['ResultsFile'] = $ResultsFile
    $ctx['ResultsJson'] = $ResultsJson
    Initialize-WpcContext -Fresh @ctx

    # Hand the probed capabilities down so nineteen children do not each re-run
    # --probe, and — more importantly — so they cannot disagree about the tier
    # mid-suite if the host changes underneath them.
    $capsPath = Join-Path $Script:ScratchRoot 'results\host-capabilities.json'
    ($Script:Caps | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $capsPath -Encoding utf8 -Force

    $selected = @(if ($Areas.Count -gt 0) { $AreaScripts.Keys | Where-Object { $_ -in $Areas } } else { $AreaScripts.Keys })

    foreach ($key in $selected) {
        $script = Join-Path $PSScriptRoot $AreaScripts[$key]
        Section ("Area: {0}  ({1})" -f $key, $AreaScripts[$key])

        $childArgs = Get-WpcChildArguments -Key $key
        $argv = ConvertTo-WpcArgumentList -Arguments $childArgs

        # Re-emit the child's streams through this host: output that bypasses
        # the PowerShell host does not land in the transcript, and a transcript
        # missing the actual test output is worthless for diagnosing a CI
        # failure. Write-WpcChildOutput also restores the colour the child
        # used, which does not survive the pipe.
        & $PSHostExe -NoProfile -ExecutionPolicy Bypass -File $script @argv 2>&1 |
            Write-WpcChildOutput
        $childExit = $LASTEXITCODE

        # Re-assert the console colour between areas so a child that died mid
        # write, or a native binary that changed the attribute, cannot tint
        # everything the suite prints from here on.
        Reset-WpcConsoleColor -To $BaseConsoleColor

        $childJson = $childArgs['ResultsJson']
        if (Test-Path $childJson) {
            try {
                $doc = Get-Content -Raw -LiteralPath $childJson | ConvertFrom-Json
                $rows = @($doc.results)
                foreach ($r in $rows) { $Merged.Add($r) | Out-Null }
                if ($rows.Count -eq 0) {
                    # Mirrors Complete-WpcChild's exit-1-on-empty rule. Without
                    # this an area that silently did nothing would contribute
                    # nothing to the summary and read as success.
                    $Merged.Add([pscustomobject]@{
                        Phase = $key; Name = 'area recorded no assertions'; Pass = $false
                        Status = 'fail'; Detail = "exit=$childExit; a deliberate skip must be recorded as one"
                    }) | Out-Null
                }
            } catch {
                $Merged.Add([pscustomobject]@{
                    Phase = $key; Name = 'child results were unreadable'; Pass = $false
                    Status = 'fail'; Detail = "$childJson : $_"
                }) | Out-Null
            }
        } else {
            # No document at all means the child died before Complete-WpcChild —
            # a crash, a throw in Initialize-WpcContext, or a host-level abort.
            # Record it rather than letting the area vanish from the summary.
            $Merged.Add([pscustomobject]@{
                Phase = $key; Name = 'area produced no results'; Pass = $false
                Status = 'fail'; Detail = "exit=$childExit; expected results at $childJson"
            }) | Out-Null
        }

        if ($childExit -eq 78) {
            $FatalAbort = "area '$key' reported MXC-FATAL (exit 78). Dispatch stopped; no further area was run."
            Write-Host ''
            Write-Host "MXC-FATAL from area '$key' — stopping the suite." -ForegroundColor Red
            break
        }
    }
}
catch {
    Write-Host ''
    Write-Host "HARNESS ABORTED: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    # Record the abort as a failure so the cleanup logic in `finally` preserves
    # the scratch dir for post-mortem inspection.
    $Merged.Add([pscustomobject]@{
        Phase = 'ABORT'; Name = 'harness aborted'; Pass = $false; Status = 'fail'; Detail = "$_"
    }) | Out-Null
}
finally {
    # A child may have left the console tinted; restore before printing the
    # summary so it is not rendered in some other area's colour.
    Reset-WpcConsoleColor -To $BaseConsoleColor
    Section 'Summary'
    if ($FatalAbort) {
        Write-Host $FatalAbort -ForegroundColor Red
        Write-Host ''
    }
    $results = $Merged.ToArray()
    Write-WpcSummary -Results $results

    $tally = Get-WpcTally -Results $results
    $pass = $tally.Passed.Count; $fail = $tally.Failed.Count
    $skip = $tally.Skipped.Count; $warn = $tally.Warned.Count

    # Structured JSON for programmatic consumption. Guarded end to end: this
    # runs in `finally`, so an unhandled throw here would skip the exit-code
    # line at the bottom and hand the CI dispatcher a bogus result. CIM is
    # unavailable on locked-down hosts.
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $osCaption = [string]$osInfo.Caption
        $osBuild = [string]$osInfo.BuildNumber
    } catch {
        $osCaption = 'unknown'
        $osBuild = 'unknown'
    }
    try {
        $summary = [pscustomobject]@{
            timestamp = (Get-Date).ToString('o')
            host      = $env:COMPUTERNAME
            os        = $osCaption
            osBuild   = $osBuild
            total     = $pass + $fail + $skip + $warn
            passed    = $pass
            failed    = $fail
            skipped   = $skip
            warnings  = $warn
            fatal     = [bool]$FatalAbort
            results   = $results
        }
        ($summary | ConvertTo-Json -Depth 6) | Out-File -LiteralPath $ResultsJson -Encoding utf8 -Force
    } catch {
        Write-Host "warning: could not write JSON results: $_" -ForegroundColor Yellow
    }

    Write-Host ''
    if ($Script:ScratchRoot -and (Test-Path $Script:ScratchRoot)) {
        Write-Host ("Logs and configs: {0}" -f $Script:ScratchRoot)
    }
    Write-Host ("Transcript:        {0}" -f $ResultsFile)
    Write-Host ("JSON summary:      {0}" -f $ResultsJson)
    if ($Script:CargoLog -and (Test-Path $Script:CargoLog)) {
        Write-Host ("Cargo full log:    {0}" -f $Script:CargoLog)
    }

    if (-not $KeepArtifacts -and $fail -eq 0 -and $pass -gt 0 -and $Script:ScratchRoot -and (Test-Path $Script:ScratchRoot)) {
        # Re-validate before deletion. Assert-SafeScratchRoot ran at the start of
        # the suite, but the variable could in principle be mutated mid-run by a
        # future refactor. Cheap belt-and-suspenders against an accidental
        # recursive delete escape.
        Assert-SafeScratchRoot
        Remove-Item -Recurse -Force -LiteralPath $Script:ScratchRoot -ErrorAction SilentlyContinue
    }
    try { Stop-Transcript | Out-Null } catch {}
    # Never hand the operator's shell back in a colour the suite chose.
    Reset-WpcConsoleColor -To $BaseConsoleColor
    if ($fail -gt 0 -or $pass -eq 0) { exit 1 } else { exit 0 }
}
