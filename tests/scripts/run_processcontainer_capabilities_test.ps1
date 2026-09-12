# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# processContainer.capabilities -- the AppContainer capability list.
#
# The list is NOT a closed enum: the schema types it as `items: {type:
# string}` and the parser validates only that no entry contains a comma and
# that no entry names a reserved learning-mode capability. Everything else is
# passed to the sandbox verbatim, so a misspelled capability is accepted and
# silently grants nothing. Phase 12b pins that down.
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


# Phase 12a -- the documented rejections
#
# config_parser.rs rejects two shapes before launch: an entry containing a
# comma (BaseContainer comma-joins the list, so one would forge extra
# capabilities) and a reserved learning-mode capability, matched
# case-insensitively as Windows derives capability SIDs that way.
#
# Test-WasRejected refuses to count a launch-API failure as a rejection, so a
# host where nothing runs cannot score this phase green.
function Phase-CapabilityRejections {
    Section 'Phase 12a: processContainer.capabilities documented rejections'

    $rw = Join-Path $ScratchRoot 'rw'
    $marker = 'MXC-CAP-RAN'
    $cmd = "cmd /c echo $marker"

    $cases = @(
        @{ Name = 'capability entry containing a comma is rejected'
           Caps = @('internetClient,registryRead')
           Why  = 'commas are the BaseContainer wire delimiter; one entry must not smuggle two capabilities' }
        @{ Name = 'reserved learningModeLogging is rejected'
           Caps = @('learningModeLogging')
           Why  = 'reserved; processContainer.learningMode is the supported way to ask for it' }
        @{ Name = 'reserved permissiveLearningMode is rejected'
           Caps = @('permissiveLearningMode')
           Why  = 'reserved; --audit is the supported way to ask for it' }
        @{ Name = 'reserved capability is rejected case-insensitively'
           Caps = @('LEARNINGMODELOGGING')
           Why  = 'Windows derives capability SIDs case-insensitively, so the check must be too' }
        @{ Name = 'a reserved capability is rejected even alongside valid ones'
           Caps = @('internetClient', 'permissiveLearningMode')
           Why  = 'the scan must cover every entry, not just the first' }
        @{ Name = 'a comma in a later entry is rejected'
           Caps = @('internetClient', 'registryRead,documentsLibrary')
           Why  = 'the comma scan must cover every entry, not just the first' }
    )

    foreach ($case in $cases) {
        $slug = ($case.Name -replace '[^a-zA-Z0-9]+', '-').Trim('-').ToLowerInvariant()
        $cfg = New-Config -Name "cap-rej-$slug" -CommandLine $cmd -ReadWrite @($rw) -Capabilities $case.Caps
        $log = Join-Path $ScratchRoot "logs\cap-rej-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $ranAnyway = [bool]("$($r.Stdout)" -match $marker)
        $logText = Read-Log $log
        Record-Result -Phase 'P12a' -Name $case.Name `
            -Pass ((Test-WasRejected -Run $r -Log $logText) -and (-not $ranAnyway)) `
            -Detail "exit=$($r.ExitCode); workloadRan=$ranAnyway; $($case.Why)"
    }

    # Positive control. Every assertion above is "this config failed", which is
    # equally true on a host where nothing launches. The control is the same
    # fixture with a legal list: it must run to completion and print the
    # marker. Without it the six rejections are unattributable.
    $ctlCfg = New-Config -Name 'cap-rej-positive-control' -CommandLine $cmd -ReadWrite @($rw) `
        -Capabilities @('internetClient', 'registryRead')
    $ctlLog = Join-Path $ScratchRoot 'logs\cap-rej-positive-control.log'
    $ctl = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $ctlCfg -LogPath $ctlLog -TimeoutSec 30
    $ctlRan = [bool]("$($ctl.Stdout)" -match $marker)
    Record-Result -Phase 'P12a' -Name 'positive control: a legal multi-entry capability list RUNS' `
        -Pass (($ctl.ExitCode -eq 0) -and $ctlRan) `
        -Detail ("exit=$($ctl.ExitCode); workloadRan=$ctlRan; " +
                 'without this, the rejections above are indistinguishable from a host on which nothing launches')
}


# Phase 12b -- the open contract
#
# `capabilities` is an open string list, so a misspelled capability is
# accepted without complaint and grants nothing. The permissive expectation
# is asserted because that is what `items: {type: string}` and the parser's
# comma/reserved-only validation describe. If MXC ever tightens this to a
# closed enum, this is the assertion that should flip.
function Phase-CapabilityContract {
    Section 'Phase 12b: processContainer.capabilities open contract'

    $rw = Join-Path $ScratchRoot 'rw'
    $marker = 'MXC-CAP-RAN'
    $cmd = "cmd /c echo $marker"

    $accepted = @(
        @{ Name = 'registryRead is accepted'
           Caps = @('registryRead') }
        @{ Name = 'an unrecognized capability name is accepted, not rejected'
           Caps = @('notARealCapability') }
        @{ Name = 'a misspelled capability is accepted (silently grants nothing)'
           Caps = @('internetCleint') }
        @{ Name = 'an empty capability list is accepted'
           Caps = @() }
        @{ Name = 'a capability list with several entries is accepted'
           Caps = @('internetClient', 'registryRead', 'privateNetworkClientServer') }
    )

    foreach ($case in $accepted) {
        $slug = ($case.Name -replace '[^a-zA-Z0-9]+', '-').Trim('-').ToLowerInvariant()
        $cfg = New-Config -Name "cap-ok-$slug" -CommandLine $cmd -ReadWrite @($rw) -Capabilities $case.Caps
        $log = Join-Path $ScratchRoot "logs\cap-ok-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $ran = [bool]("$($r.Stdout)" -match $marker)
        # "Accepted" is a claim about validation, so that is what is asserted.
        # Requiring a successful run instead would fold host provisioning into
        # a parser assertion and report a launch failure as a parser bug.
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        Record-Result -Phase 'P12b' -Name $case.Name -Pass (-not $rejected) `
            -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected; workloadRan=$ran; caps=[$($case.Caps -join ', ')]"
    }

    # The capability list must reach the sandbox, not just survive validation.
    # Only the legacy SBOX path names them in the log.
    $cfg = New-Config -Name 'cap-reaches-sandbox' -CommandLine $cmd -ReadWrite @($rw) `
        -Capabilities @('registryRead')
    $log = Join-Path $ScratchRoot 'logs\cap-reaches-sandbox.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
    $logText = Remove-ConfigEcho (Read-Log $log)
    Record-CapabilityLogged -Phase 'P12b' -Name 'a granted capability is named in the runner log' `
        -LogContent $logText -Capability @('registryRead') -Detail "exit=$($r.ExitCode)"
}


# Phase 12c -- registryRead does what its name says
#
# No doc gives a behavioral contract for individual capability names, so this
# asserts only the direction a caller can rely on: registryRead can read HKLM.
#
# The reverse is deliberately not asserted as a failure — AppContainers get
# read access to much of HKLM through ALL APPLICATION PACKAGES regardless of
# the capability. The no-capability run is recorded as information only.
function Phase-RegistryReadCapability {
    Section 'Phase 12c: registryRead behavior'

    $rw = Join-Path $ScratchRoot 'rw'
    # A value every Windows install has, read through reg.exe so the workload
    # needs no extra binary staged into the container.
    $key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $cmd = "cmd /c reg query `"$key`" /v ProductName && echo MXC-REG-OK"

    $withCfg = New-Config -Name 'cap-registry-with' -CommandLine $cmd -ReadWrite @($rw) `
        -Capabilities @('registryRead')
    $withLog = Join-Path $ScratchRoot 'logs\cap-registry-with.log'
    $with = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $withCfg -LogPath $withLog -TimeoutSec 30
    $withOk = [bool]("$($with.Stdout)" -match 'MXC-REG-OK')
    Record-Result -Phase 'P12c' -Name 'registryRead granted -> workload can read HKLM' `
        -Pass $withOk -Detail "exit=$($with.ExitCode); stdout=$(($with.Stdout -replace '\s+', ' ').Trim())"

    $withoutCfg = New-Config -Name 'cap-registry-without' -CommandLine $cmd -ReadWrite @($rw)
    $withoutLog = Join-Path $ScratchRoot 'logs\cap-registry-without.log'
    $without = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $withoutCfg -LogPath $withoutLog -TimeoutSec 30
    $withoutOk = [bool]("$($without.Stdout)" -match 'MXC-REG-OK')
    Record-Result -Phase 'P12c' -Name 'baseline: same read without the capability' -Status 'warn' `
        -Detail ("readable=$withoutOk; exit=$($without.ExitCode); informational only -- AppContainers " +
                 'inherit HKLM read through ALL APPLICATION PACKAGES, so this is not asserted either way')
}


Invoke-WpcPhase -Key 'CapabilityRejections' -Body { Phase-CapabilityRejections }
Invoke-WpcPhase -Key 'CapabilityContract'   -Body { Phase-CapabilityContract }
Invoke-WpcPhase -Key 'RegistryReadCap'      -Body { Phase-RegistryReadCapability }
Complete-WpcChild
