# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_path_aliasing_test.ps1
#
# Denied paths reached via .., 8.3 short names, and the \\?\ prefix.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_path_aliasing_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = all passed, 1 = a failure or zero assertions, 78 = fatal.

[CmdletBinding()]
param(
    # -ContextJson carries the context the entry script already resolved.
    # Anything passed explicitly overrides it, so a standalone run works too.
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


# -----------------------------------------------------------------------
# Phase 10 — path aliasing and most-specific-wins.
#
# Three Linux/macOS backends have dedicated suites for this because a grant
# that resolves to a different object than the caller wrote is either a hole
# or a mystery denial, and neither is visible from the config text. Windows
# has MORE ways to alias a path than any of them — `..` traversal, 8.3 short
# names, the `\\?\` prefix, and junctions all reach the same object that the
# DACL ACEs are applied to.
# -----------------------------------------------------------------------
function Phase-PathAliasing {
    Section 'Phase 10: path aliasing and most-specific-wins'

    if (-not $Script:Caps.SupportsDeniedPaths) {
        Record-Result -Phase 'P10' -Name 'path aliasing' -Status 'skip' `
            -Detail "deniedPaths not supported on tier=$($Script:ExpectedTier)"
        return
    }

    $rw      = Join-Path $ScratchRoot 'rw'
    $alias   = Join-Path $ScratchRoot 'alias'
    $secret  = Join-Path $alias 'secret'
    New-Item -ItemType Directory -Force -Path $secret | Out-Null
    $sentinel = 'ALIAS-SENTINEL-9f31'
    Set-Content -LiteralPath (Join-Path $secret 'data.txt') -Value $sentinel -Encoding ascii

    $read = New-ProbeCommand -Body "type `"$secret\data.txt`""

    # 1. `..` traversal reaching a denied directory. The policy denies the
    #    canonical path; the workload addresses it through a parent hop. Both
    #    spellings name the same object, so the deny must hold.
    $dotdot = Join-Path $alias 'secret\..\secret'
    $cfgDotDot = New-Config -Name 'alias-dotdot' `
        -CommandLine (New-ProbeCommand -Body "type `"$dotdot\data.txt`"") `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
    $logDotDot = Join-Path $ScratchRoot 'logs\alias-dotdot.log'
    $rDotDot = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgDotDot -LogPath $logDotDot -TimeoutSec 40
    Record-Result -Phase 'P10' -Name 'denied path is still denied through a `..` alias' `
        -Pass ((Test-WorkloadRan $rDotDot) -and -not ($rDotDot.Stdout -match $sentinel)) `
        -Detail "ran=$(Test-WorkloadRan $rDotDot); sawSentinel=$([bool]($rDotDot.Stdout -match $sentinel)); exit=$($rDotDot.ExitCode)"

    # 2. `\\?\` extended-length prefix. Same object, different spelling.
    $cfgExt = New-Config -Name 'alias-extended-prefix' `
        -CommandLine (New-ProbeCommand -Body "type `"\\?\$secret\data.txt`"") `
        -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
    $logExt = Join-Path $ScratchRoot 'logs\alias-extended-prefix.log'
    $rExt = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgExt -LogPath $logExt -TimeoutSec 40
    Record-Result -Phase 'P10' -Name 'denied path is still denied through a \\?\ alias' `
        -Pass ((Test-WorkloadRan $rExt) -and -not ($rExt.Stdout -match $sentinel)) `
        -Detail "ran=$(Test-WorkloadRan $rExt); sawSentinel=$([bool]($rExt.Stdout -match $sentinel)); exit=$($rExt.ExitCode)"

    # 3. 8.3 short name. Only meaningful where the volume generates them.
    $shortPath = $null
    try {
        $fso = New-Object -ComObject Scripting.FileSystemObject
        $shortPath = $fso.GetFolder($secret).ShortPath
    } catch {}
    if ($shortPath -and ($shortPath -ne $secret)) {
        $cfgShort = New-Config -Name 'alias-shortname' `
            -CommandLine (New-ProbeCommand -Body "type `"$shortPath\data.txt`"") `
            -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
        $logShort = Join-Path $ScratchRoot 'logs\alias-shortname.log'
        $rShort = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgShort -LogPath $logShort -TimeoutSec 40
        Record-Result -Phase 'P10' -Name 'denied path is still denied through an 8.3 short-name alias' `
            -Pass ((Test-WorkloadRan $rShort) -and -not ($rShort.Stdout -match $sentinel)) `
            -Detail "short=$shortPath; ran=$(Test-WorkloadRan $rShort); sawSentinel=$([bool]($rShort.Stdout -match $sentinel))"
    } else {
        Record-Result -Phase 'P10' -Name '8.3 short-name alias' -Status 'skip' `
            -Detail '8.3 name generation is disabled on this volume'
    }

    # 4. Conflicting intents on the SAME object. The object is named readwrite
    #    and denied at once; the documented resolution is most-restrictive-wins
    #    (deny > ro > rw), so the deny must hold.
    $cfgConflict = New-Config -Name 'alias-conflicting-intent' -CommandLine $read `
        -ReadWrite @($rw, $secret) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
    $logConflict = Join-Path $ScratchRoot 'logs\alias-conflicting-intent.log'
    $rConflict = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgConflict -LogPath $logConflict -TimeoutSec 40
    Record-Result -Phase 'P10' -Name 'same object as both readwrite and denied resolves to denied' `
        -Pass ((Test-WorkloadRan $rConflict) -and -not ($rConflict.Stdout -match $sentinel)) `
        -Detail "ran=$(Test-WorkloadRan $rConflict); sawSentinel=$([bool]($rConflict.Stdout -match $sentinel)); deny > rw"

    # 5. Most-specific-wins: denied PARENT with a readwrite CHILD. The child
    #    must remain usable, and a non-regranted sibling must stay denied.
    $child   = Join-Path $secret 'child'
    $sibling = Join-Path $secret 'sibling'
    New-Item -ItemType Directory -Force -Path $child, $sibling | Out-Null
    Set-Content -LiteralPath (Join-Path $sibling 'data.txt') -Value $sentinel -Encoding ascii
    $probe = New-ProbeCommand -Body (
        "(echo CHILD-WRITE> `"$child\w.txt`" && type `"$child\w.txt`" && echo CHILD=OK) & " +
        "(type `"$sibling\data.txt`" >nul 2>&1 && echo SIBLING=LEAK || echo SIBLING=DENIED)")
    $cfgSpecific = New-Config -Name 'alias-most-specific' -CommandLine $probe `
        -ReadWrite @($rw, $child) -ReadOnly @($env:SystemRoot) -Denied @($secret) -TimeoutMs 25000
    $logSpecific = Join-Path $ScratchRoot 'logs\alias-most-specific.log'
    $rSpecific = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgSpecific -LogPath $logSpecific -TimeoutSec 40
    Record-Result -Phase 'P10' -Name 'readwrite child punches through a denied parent' `
        -Pass ([bool]($rSpecific.Stdout -match 'CHILD=OK')) `
        -Detail "ran=$(Test-WorkloadRan $rSpecific); stdout=$(($rSpecific.Stdout).Trim() -replace '\s+', ' ')"
    Record-Result -Phase 'P10' -Name 'non-regranted sibling of the denied parent stays denied' `
        -Pass ((Test-WorkloadRan $rSpecific) -and ($rSpecific.Stdout -match 'SIBLING=DENIED')) `
        -Detail "ran=$(Test-WorkloadRan $rSpecific); stdout=$(($rSpecific.Stdout).Trim() -replace '\s+', ' ')"
}

Invoke-WpcPhase -Key 'PathAliasing' -Body { Phase-PathAliasing }
Complete-WpcChild

