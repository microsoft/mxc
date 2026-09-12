# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_unit_tests_test.ps1
#
# Rust unit tests for the process-container crates (cargo test).
#
# Part of the Windows process-container suite. Normally invoked by
# run_processcontainer_all_tests.ps1, which probes the host once and passes
# the shared context down. Runs standalone too:
#
#   .\run_processcontainer_unit_tests_test.ps1 -RequireTier base-container
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
# Phase 7 — Rust unit tests
# -----------------------------------------------------------------------
function Invoke-CargoTest {
    # Run a `cargo test` invocation, append its full output to $CargoLog,
    # surface only summary / error lines to the transcript.
    param(
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Label
    )
    "" | Add-Content -LiteralPath $CargoLog
    "===== $Label  (cargo $($Arguments -join ' ')) =====" | Add-Content -LiteralPath $CargoLog
    $output = & cargo @Arguments 2>&1
    $exit = $LASTEXITCODE
    $output | Out-File -LiteralPath $CargoLog -Append -Encoding utf8

    # Surface load-bearing lines to the transcript:
    # - "test result:" — pass/fail summary per test binary
    # - "error[" / "error:" / "warning:" — compile / link diagnostics
    # - "Compiling " / "Finished " — high-level cargo progress
    $summary = $output | Where-Object {
        $_ -match '^(test result:|error(\[|:)|warning:|\s+Compiling |\s+Finished )'
    }
    if ($summary) {
        $summary | ForEach-Object { Write-Host "  $_" }
    } else {
        # Fallback: surface the last 10 lines so a silent failure doesn't
        # disappear into the side log.
        Write-Host '  (no summary lines matched — last 10 lines:)'
        $output | Select-Object -Last 10 | ForEach-Object { Write-Host "    $_" }
    }
    return $exit
}


function Phase-UnitTests {
    Section 'Phase 7: cargo test'
    # Truncate the cargo log at the start of each run.
    Set-Content -LiteralPath $CargoLog -Value "WinProcessContainer-Tests cargo log — $(Get-Date -Format 'o')`n" -Encoding utf8
    Push-Location $CargoRoot
    try {
        $exit1 = Invoke-CargoTest -Arguments @('test', '-p', 'wxc_common', '--lib') -Label 'wxc_common --lib'
        Record-Result -Phase 'P7' -Name 'cargo test -p wxc_common' -Pass ($exit1 -eq 0) -Detail "exit=$exit1; full log: $CargoLog"
        # `wxc` is a binary-only crate — no --lib target. Run its bin tests.
        $exit2 = Invoke-CargoTest -Arguments @('test', '-p', 'wxc', '--bins') -Label 'wxc --bins'
        Record-Result -Phase 'P7' -Name 'cargo test -p wxc --bins' -Pass ($exit2 -eq 0) -Detail "exit=$exit2; full log: $CargoLog"
    } finally {
        Pop-Location
    }
}

Invoke-WpcPhase -Key 'UnitTests' -Body { Phase-UnitTests }
Complete-WpcChild

