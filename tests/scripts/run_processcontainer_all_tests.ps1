# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Entry point for the Windows process-container suite: probes the host once,
# writes the resolved context to JSON, dispatches each area to its own
# run_processcontainer_*_test.ps1, and merges the results. Areas also run
# standalone.
#
# Tiers covered are T1 (base-container) and T3 (appcontainer-dacl); selection is
# natural, there is no -ForceTier. T2 (appcontainer-bfs) is off behind the
# `tier2_bfs` Cargo feature and Assert-BfsSafety refuses a binary built with it,
# because bfscfg.exe hard-locks the bfs.sys minifilter on 25H2.
#
# Configs are authored at 0.8.0-alpha; only the legacy network fields stay at
# 0.7.0-alpha. Network areas assert the DOCUMENTED contract (docs/process-
# container/networking.md, docs/sandbox-policy/0.8.0/networking/networking.md),
# so an assertion that outruns the backend fails by design.
#
# Prerequisites fail, they do not skip: a -RequireTier mismatch, an unreachable
# egress anchor (-SkipNetwork opts out), or a child recording zero assertions.
#
#   .\run_processcontainer_all_tests.ps1 -SkipBuild -RequireTier base-container
#   .\run_processcontainer_all_tests.ps1 -Areas NetworkProxy,NetworkEgressRules

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
    [switch]$SkipBuild,
    [switch]$KeepArtifacts,
    # Aborts when the host does not naturally select this tier: without it a
    # mis-provisioned T1 runner would run the T3 assertions and report green.
    # '' means "no requirement" and must stay in the set, because ValidateSet
    # binds to the VARIABLE and re-fires when Initialize-WpcContext publishes
    # the context back into this scope.
    [ValidateSet('', 'base-container', 'appcontainer-dacl')]
    [string]$RequireTier,
    # Reachability anchor for the positive egress assertions, probed from the
    # host first: an allow test that cannot tell "policy blocked it" from "no
    # internet here" proves nothing, so an unreachable anchor fails the run.
    [string]$ExternalAnchorUrl,
    # Negative control for the explicit egress-rule area: the allow rules name
    # the anchor and not this, so it must be blocked inside the container while
    # staying reachable from the host — otherwise BLOCKED is unattributable.
    [string]$UnlistedDestinationUrl,
    # Opt out of every live-network area (air-gapped bring-up). The parse-only
    # rejection area still runs — it needs no connectivity.
    [switch]$SkipNetwork,
    # Restrict the run to a subset of areas. Accepts the keys in $AreaScripts
    # below. Empty = run everything. `-Phases` is an alias for compatibility
    # with the pre-split harness.
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
    'Probes'                   = 'run_processcontainer_probes_test.ps1'
    'T3Forced'                 = 'run_processcontainer_filesystem_matrix_test.ps1'
    'T1DenyForced'             = 'run_processcontainer_denied_paths_test.ps1'
    'UiMitigationMatrix'       = 'run_processcontainer_ui_mitigations_test.ps1'
    'UiPolicyMatrix'           = 'run_processcontainer_ui_policy_matrix_test.ps1'
    'Capabilities'             = 'run_processcontainer_capabilities_test.ps1'
    'CaptureDenials'           = 'run_processcontainer_capture_denials_test.ps1'
    'Lifecycle'                = 'run_processcontainer_lifecycle_test.ps1'
    'Privilege'                = 'run_processcontainer_privilege_test.ps1'
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
    $contextPath = Join-Path $Script:ScratchRoot 'results\suite-context.json'
    Write-WpcContextFile -Path $contextPath

    $selected = @(if ($Areas.Count -gt 0) { $AreaScripts.Keys | Where-Object { $_ -in $Areas } } else { $AreaScripts.Keys })

    foreach ($key in $selected) {
        $script = Join-Path $PSScriptRoot $AreaScripts[$key]
        Section ("Area: {0}  ({1})" -f $key, $AreaScripts[$key])

        $childJson = Join-Path $Script:ScratchRoot "results\$key.json"

        # Re-emit the child's streams through this host: output that bypasses
        # the PowerShell host does not land in the transcript, and a transcript
        # missing the actual test output is worthless for diagnosing a CI
        # failure. Write-WpcChildOutput also restores the colour the child
        # used, which does not survive the pipe.
        & $PSHostExe -NoProfile -ExecutionPolicy Bypass -File $script `
            -ContextJson $contextPath -ResultsJson $childJson 2>&1 |
            Write-WpcChildOutput
        $childExit = $LASTEXITCODE

        # Re-assert the console colour between areas so a child that died mid
        # write, or a native binary that changed the attribute, cannot tint
        # everything the suite prints from here on.
        Reset-WpcConsoleColor -To $BaseConsoleColor

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
