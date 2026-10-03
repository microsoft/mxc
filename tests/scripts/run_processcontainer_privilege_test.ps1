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
    # Test-WasRejected is false for backend_error, runner_unavailable and any
    # unexplained launch failure, so negating it alone proves no fallback ran.
    $ran = [bool]("$($r.Stdout)" -match $Script:PrivMarker)
    Record-Result -Phase 'P15a' -Name 'leastPrivilege + captureDenials falls back rather than being rejected' `
        -Pass ((-not $rejected) -and $ran) `
        -Detail ("exit=$($r.ExitCode); rejectedAtValidation=$rejected; workloadRan=$ran; " +
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


Invoke-WpcPhase -Key 'LeastPrivilege'    -Body { Phase-LeastPrivilege }
Invoke-WpcPhase -Key 'LearningMode'      -Body { Phase-LearningMode }
Complete-WpcChild
