# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# processContainer.leastPrivilege (LPAC), processContainer.learningMode, and
# the legacy 0.7 network.proxy shapes.
#
# LPAC coverage previously lived only in run_lpacac_test.ps1, outside this
# suite and outside CI's process-container area list; `learningMode` and the
# legacy proxy builder parameters were unexercised entirely.
#
# LPAC interacts with tier selection: native PSEC capture cannot combine with
# leastPrivilege (docs/schema.md), and least-privilege mode makes a run
# PSEC-ineligible. Phase 15a asserts the documented incompatibility rather
# than the tier, which depends on the host.
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
. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Native.ps1')

Initialize-WpcContext @PSBoundParameters

$Script:PrivMarker = 'MXC-PRIV-RAN'
$Script:PrivCmd    = "cmd /c echo $Script:PrivMarker"


# Phase 15a -- leastPrivilege (LPAC)
#
# Both values, plus the documented interaction with captureDenials. The
# tier that results is host-dependent and deliberately not asserted.
function Phase-LeastPrivilege {
    Section 'Phase 15a: processContainer.leastPrivilege (LPAC)'

    $rw = Join-Path $ScratchRoot 'rw'

    foreach ($lp in $true, $false) {
        $slug = $(if ($lp) { 'true' } else { 'false' })
        $cfg = New-Config -Name "priv-lpac-$slug" -CommandLine $Script:PrivCmd -ReadWrite @($rw) `
            -LeastPrivilege $lp
        $log = Join-Path $ScratchRoot "logs\priv-lpac-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        $ran = [bool]("$($r.Stdout)" -match $Script:PrivMarker)
        Record-Result -Phase 'P15a' -Name "leastPrivilege=$slug is accepted" -Pass (-not $rejected) `
            -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected; workloadRan=$ran"
    }

    # LPAC plus capabilities: an LPAC container still takes a capability list,
    # so the combination must not be refused.
    $cfg = New-Config -Name 'priv-lpac-caps' -CommandLine $Script:PrivCmd -ReadWrite @($rw) `
        -LeastPrivilege $true -Capabilities @('internetClient')
    $log = Join-Path $ScratchRoot 'logs\priv-lpac-caps.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
    Record-Result -Phase 'P15a' -Name 'leastPrivilege combined with a capability list is accepted' `
        -Pass (-not $rejected) -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"

    # Documented in docs/schema.md: "Native PSEC/V2 capture cannot combine
    # with leastPrivilege or network.proxy. Hosts without that complete native
    # set retain an eligible legacy containment tier and use guarded WPR."
    #
    # So the combination is a tier constraint, not a rejection: the run should
    # still be accepted and fall back. Asserting a rejection here would encode
    # the opposite of the documented behavior.
    $cfg = New-Config -Name 'priv-lpac-capture' -CommandLine $Script:PrivCmd -ReadWrite @($rw) `
        -LeastPrivilege $true -CaptureDenialsMode 'block'
    $log = Join-Path $ScratchRoot 'logs\priv-lpac-capture.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $logText = Read-Log $log
    $rejected = Test-WasRejected -Run $r -Log $logText
    Record-Result -Phase 'P15a' -Name 'leastPrivilege + captureDenials falls back rather than being rejected' `
        -Pass (-not $rejected) `
        -Detail ("exit=$($r.ExitCode); rejectedAtValidation=$rejected; " +
                 'documented as a tier constraint (guarded WPR fallback), not a validation error')
}


# Phase 15b -- learningMode
#
# The supported entry point for the learning-mode capability that Phase 12a
# proves cannot be requested through `capabilities`. Both spellings of that
# relationship are worth holding: the reserved capability name is refused,
# and this field is the thing that replaces it.
function Phase-LearningMode {
    Section 'Phase 15b: processContainer.learningMode'

    $rw = Join-Path $ScratchRoot 'rw'

    foreach ($lm in $true, $false) {
        $slug = $(if ($lm) { 'true' } else { 'false' })
        $cfg = New-Config -Name "priv-lm-$slug" -CommandLine $Script:PrivCmd -ReadWrite @($rw) `
            -LearningMode $lm
        $log = Join-Path $ScratchRoot "logs\priv-lm-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        Record-Result -Phase 'P15b' -Name "learningMode=$slug is accepted" -Pass (-not $rejected) `
            -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"
    }

    $cfg = New-Config -Name 'priv-lm-capture' -CommandLine $Script:PrivCmd -ReadWrite @($rw) `
        -LearningMode $true -CaptureDenialsMode 'block'
    $log = Join-Path $ScratchRoot 'logs\priv-lm-capture.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
    Record-Result -Phase 'P15b' -Name 'learningMode combined with captureDenials is accepted' `
        -Pass (-not $rejected) -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"
}


# Phase 15c -- the legacy 0.7 network.proxy shapes
#
# Three mutually exclusive spellings of network.proxy, none previously
# exercised, all pinned to 0.7 because the directional 0.8 shape replaced
# them with runtimeConfig.networkProxy.
#
# These are acceptance assertions. Whether the proxy is reachable is the
# proxy area's job; what is asserted here is that each legacy spelling still
# parses on the schema version that defines it, and that the 0.8 replacement
# has not quietly broken the older shape.
function Phase-LegacyProxyShapes {
    Section 'Phase 15c: legacy 0.7 network.proxy shapes'

    if ($SkipNetwork) {
        Record-Result -Phase 'P15c' -Name 'legacy proxy shapes' -Status 'skip' `
            -Detail '-SkipNetwork was requested'
        return
    }

    $rw = Join-Path $ScratchRoot 'rw'

    $cases = @(
        @{ Name = 'legacy network.proxy.url is accepted on 0.7'
           Args = @{ LegacyProxyUrl = 'http://127.0.0.1:8888' } }
        @{ Name = 'legacy network.proxy.localhost (port form) is accepted on 0.7'
           Args = @{ LegacyProxyLocalhost = 8888 } }
        @{ Name = 'legacy network.proxy.builtinTestServer is accepted on 0.7'
           Args = @{ LegacyProxyBuiltinTestServer = $true } }
        @{ Name = 'legacy allowLocalNetwork=true is accepted on 0.7'
           Args = @{ LegacyAllowLocalNetwork = $true; LegacyDefaultPolicy = 'allow' } }
        @{ Name = 'legacy allowLocalNetwork=false is accepted on 0.7'
           Args = @{ LegacyAllowLocalNetwork = $false; LegacyDefaultPolicy = 'allow' } }
    )

    foreach ($case in $cases) {
        $slug = ($case.Name -replace '[^a-zA-Z0-9]+', '-').Trim('-').ToLowerInvariant()
        $cfgArgs = @{
            Name        = "priv-legacy-$slug"
            CommandLine = $Script:PrivCmd
            ReadWrite   = @($rw)
        }
        foreach ($k in $case.Args.Keys) { $cfgArgs[$k] = $case.Args[$k] }

        $cfg = New-Config @cfgArgs
        $log = Join-Path $ScratchRoot "logs\priv-legacy-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        Record-Result -Phase 'P15c' -Name $case.Name -Pass (-not $rejected) `
            -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"
    }

    # `network.proxy` survives into the 0.8 schema alongside the directional
    # keys, so it is NOT rejected there. The thing worth asserting is that the
    # older spelling still parses on the newer version rather than being
    # quietly dropped -- a dropped proxy runs unproxied, which is the failure
    # a caller would not notice.
    $raw = [ordered]@{
        version     = $Script:SchemaVersion
        containerId = 'MxcWinPC-priv-legacy-on-08'
        containment = 'processcontainer'
        process     = [ordered]@{ commandLine = $Script:PrivCmd; timeout = 30000 }
        filesystem  = [ordered]@{ readwritePaths = @($rw) }
        network     = [ordered]@{ proxy = [ordered]@{ url = 'http://127.0.0.1:8888' } }
        ui          = [ordered]@{ disable = $false }
    }
    $cfg = New-RawConfig -Name 'priv-legacy-on-08' -Object $raw
    $log = Join-Path $ScratchRoot 'logs\priv-legacy-on-08.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $logText = Read-Log $log
    $rejected = Test-WasRejected -Run $r -Log $logText
    # The runner announces the proxy it will apply. Matched against the log
    # with the config echo stripped, so this sees the runner's decision rather
    # than the config being read back.
    $applied = [bool]((Remove-ConfigEcho $logText) -match '(?i)network_proxy:\s*enabled')
    Record-Result -Phase 'P15c' -Name 'legacy network.proxy is still honored on schema 0.8' `
        -Pass ((-not $rejected) -and $applied) `
        -Detail ("exit=$($r.ExitCode); rejectedAtValidation=$rejected; runnerAppliedProxy=$applied; " +
                 '0.8 keeps `proxy` alongside the directional keys; a silently dropped proxy runs unproxied')
}


Invoke-WpcPhase -Key 'LeastPrivilege'    -Body { Phase-LeastPrivilege }
Invoke-WpcPhase -Key 'LearningMode'      -Body { Phase-LearningMode }
Invoke-WpcPhase -Key 'LegacyProxyShapes' -Body { Phase-LegacyProxyShapes }
Complete-WpcChild
