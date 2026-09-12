# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# lifecycle.* and the process.* knobs no other area sets.
#
# Covers `lifecycle.destroyOnExit`, `lifecycle.preservePolicy`,
# `process.inheritDefaultEnv`, `telemetry.enabled` and the
# `containment: "process"` intent alias.
#
# The key assertion is the `inheritDefaultEnv` version gate. docs/schema.md
# (updated 2026-09-10) marks the field `0.9.0-alpha+`, and the stable surface
# uses deny_unknown_fields, so at 0.8 it must be REJECTED. A silently dropped
# field is the worst outcome for a caller: the config looks accepted and the
# environment is wrong. Phase 13b pins both sides.
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

$Script:LifecycleMarker = 'MXC-LC-RAN'
$Script:LifecycleCmd    = "cmd /c echo $Script:LifecycleMarker"


# Phase 13a -- lifecycle.* acceptance
#
# All four combinations. The one-shot process container tears down when the
# process exits, so `destroyOnExit: false` has nothing to keep alive; the
# documented wording is permissive ("Retain container policies after exit if
# applicable"), so these are acceptance assertions rather than behavioral
# ones. Asserting a behavioral difference here would be inventing a contract.
function Phase-Lifecycle {
    Section 'Phase 13a: lifecycle.destroyOnExit / preservePolicy'

    $rw = Join-Path $ScratchRoot 'rw'

    $cases = @(
        @{ Name = 'lifecycle.destroyOnExit=true is accepted';  Destroy = $true;  Preserve = $null }
        @{ Name = 'lifecycle.destroyOnExit=false is accepted'; Destroy = $false; Preserve = $null }
        @{ Name = 'lifecycle.preservePolicy=true is accepted';  Destroy = $null; Preserve = $true }
        @{ Name = 'lifecycle.preservePolicy=false is accepted'; Destroy = $null; Preserve = $false }
        @{ Name = 'lifecycle with both fields set is accepted'; Destroy = $true; Preserve = $false }
    )

    foreach ($case in $cases) {
        $slug = ($case.Name -replace '[^a-zA-Z0-9]+', '-').Trim('-').ToLowerInvariant()
        $cfgArgs = @{
            Name        = "lc-$slug"
            CommandLine = $Script:LifecycleCmd
            ReadWrite   = @($rw)
        }
        if ($null -ne $case.Destroy)  { $cfgArgs['DestroyOnExit']  = $case.Destroy }
        if ($null -ne $case.Preserve) { $cfgArgs['PreservePolicy'] = $case.Preserve }

        $cfg = New-Config @cfgArgs
        $log = Join-Path $ScratchRoot "logs\lc-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        $ran = [bool]("$($r.Stdout)" -match $Script:LifecycleMarker)
        Record-Result -Phase 'P13a' -Name $case.Name -Pass (-not $rejected) `
            -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected; workloadRan=$ran"
    }
}


# Phase 13b -- process.inheritDefaultEnv and the 0.9 version gate
#
# Documented as 0.9.0-alpha+. The stable surface is closed, so on 0.8 the
# field must be rejected outright. The pair of assertions matters more than
# either alone: "rejected at 0.8" is only meaningful next to "accepted at
# 0.9", which proves the rejection is the version gate and not a typo in the
# fixture.
function Phase-InheritDefaultEnv {
    Section 'Phase 13b: process.inheritDefaultEnv (0.9.0-alpha+)'

    $rw = Join-Path $ScratchRoot 'rw'
    # Print one caller-supplied variable and one that only the backend default
    # provides, so the two inheritance modes are distinguishable.
    $cmd = 'cmd /c echo MINE=[%MXC_LC_MINE%] && echo SYSROOT=[%SystemRoot%]'

    $cfg = New-Config -Name 'lc-inherit-0800' -CommandLine $cmd -ReadWrite @($rw) `
        -Env @('MXC_LC_MINE=yes') -InheritDefaultEnv $true -SchemaVersion '0.8.0-alpha'
    $log = Join-Path $ScratchRoot 'logs\lc-inherit-0800.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
    $logText = Read-Log $log
    # The config echo contains the field name verbatim, so match the runner's
    # own output only -- otherwise "the error names the field" is satisfied by
    # the config being read back and proves nothing.
    $all = Remove-ConfigEcho "$logText`n$($r.Stderr)"
    $namedField = [bool]($all -match '(?i)inheritDefaultEnv')
    Record-Result -Phase 'P13b' -Name 'inheritDefaultEnv is rejected on schema 0.8.0-alpha' `
        -Pass ((Test-WasRejected -Run $r -Log $logText) -and $namedField) `
        -Detail ("exit=$($r.ExitCode); errorNamesTheField=$namedField; " +
                 'documented 0.9.0-alpha+, and the stable surface is closed, so 0.8 must reject rather than ignore')

    $versionCases = @(
        @{ Name = 'inheritDefaultEnv=true is accepted on schema 0.9.0-alpha';  Inherit = $true }
        @{ Name = 'inheritDefaultEnv=false is accepted on schema 0.9.0-alpha'; Inherit = $false }
    )
    foreach ($case in $versionCases) {
        $slug = $(if ($case.Inherit) { 'true' } else { 'false' })
        $cfg = New-Config -Name "lc-inherit-0900-$slug" -CommandLine $cmd -ReadWrite @($rw) `
            -Env @('MXC_LC_MINE=yes') -InheritDefaultEnv $case.Inherit -SchemaVersion '0.9.0-alpha'
        $log = Join-Path $ScratchRoot "logs\lc-inherit-0900-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        Record-Result -Phase 'P13b' -Name $case.Name -Pass (-not $rejected) `
            -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"
    }

    # The behavioral half: layering means the caller's variable AND the
    # backend default are both present. Only meaningful once a container can
    # actually start, so it reports what it saw either way.
    $cfg = New-Config -Name 'lc-inherit-layered' -CommandLine $cmd -ReadWrite @($rw) `
        -Env @('MXC_LC_MINE=yes') -InheritDefaultEnv $true -SchemaVersion '0.9.0-alpha'
    $log = Join-Path $ScratchRoot 'logs\lc-inherit-layered.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
    $out = "$($r.Stdout)"
    $sawMine = [bool]($out -match 'MINE=\[yes\]')
    $sawDefault = [bool]($out -match 'SYSROOT=\[[^\]]+\]')
    Record-Result -Phase 'P13b' -Name 'inheritDefaultEnv=true layers process.env over the backend default' `
        -Pass ($sawMine -and $sawDefault) `
        -Detail "callerVar=$sawMine; backendDefaultVar=$sawDefault; exit=$($r.ExitCode)"
}


# Phase 13c -- process.env without inheritDefaultEnv
#
# Documented: "Omitted: backend default; supplied: used verbatim". Verbatim is
# the claim under test -- a supplied env that still carried the launcher's
# variables would be a containment leak, not a convenience.
function Phase-ProcessEnv {
    Section 'Phase 13c: process.env supplied vs omitted'

    $rw = Join-Path $ScratchRoot 'rw'
    $cmd = 'cmd /c echo MINE=[%MXC_LC_MINE%] && echo LEAK=[%MXC_LC_LEAK%]'

    # A variable present in THIS process but not in the config. If it shows up
    # inside the container, the supplied env was not used verbatim.
    $env:MXC_LC_LEAK = 'leaked'
    try {
        $cfg = New-Config -Name 'lc-env-verbatim' -CommandLine $cmd -ReadWrite @($rw) `
            -Env (Get-MinimalEnv -Extra @('MXC_LC_MINE=yes'))
        $log = Join-Path $ScratchRoot 'logs\lc-env-verbatim.log'
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $out = "$($r.Stdout)"
        $sawMine = [bool]($out -match 'MINE=\[yes\]')
        # cmd.exe leaves an unset variable as the literal %NAME%.
        $leaked = [bool]($out -match 'LEAK=\[leaked\]')
        Record-Result -Phase 'P13c' -Name 'a supplied process.env is used verbatim' `
            -Pass ($sawMine -and (-not $leaked)) `
            -Detail "callerVar=$sawMine; launcherVarLeaked=$leaked; exit=$($r.ExitCode)"

        $cfg = New-Config -Name 'lc-env-omitted' -CommandLine $cmd -ReadWrite @($rw)
        $log = Join-Path $ScratchRoot 'logs\lc-env-omitted.log'
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        Record-Result -Phase 'P13c' -Name 'an omitted process.env is accepted (backend default)' `
            -Pass (-not $rejected) -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"

        $cfg = New-Config -Name 'lc-env-empty' -CommandLine $Script:LifecycleCmd -ReadWrite @($rw) `
            -Env (Get-MinimalEnv -Extra @('MXC_LC_EMPTY='))
        $log = Join-Path $ScratchRoot 'logs\lc-env-empty.log'
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        Record-Result -Phase 'P13c' -Name 'an env entry with an empty value is accepted' `
            -Pass (-not $rejected) -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"
    }
    finally {
        Remove-Item Env:\MXC_LC_LEAK -ErrorAction SilentlyContinue
    }
}


# Phase 13d -- containment intent, telemetry kill-switch, version range
#
# `containment: "process"` is the intent alias; on Windows it must resolve to
# the same backend as `processcontainer`, asserted by comparing the selected
# tier under both spellings so it cannot pass where neither runs.
#
# `telemetry.enabled` can only ever subtract from consent, so the only safe
# assertion is that both values are accepted. true is not consent.
function Phase-IntentTelemetryVersion {
    Section 'Phase 13d: containment intent, telemetry kill-switch, version range'

    $rw = Join-Path $ScratchRoot 'rw'

    $tiers = @{}
    foreach ($name in 'process', 'processcontainer') {
        $cfg = New-Config -Name "lc-intent-$name" -CommandLine $Script:LifecycleCmd -ReadWrite @($rw) `
            -Containment $name
        $log = Join-Path $ScratchRoot "logs\lc-intent-$name.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $logText = Remove-ConfigEcho (Read-Log $log)
        $rejected = Test-WasRejected -Run $r -Log $logText
        Record-Result -Phase 'P13d' -Name "containment '$name' is accepted on Windows" `
            -Pass (-not $rejected) -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"
        $m = [regex]::Match($logText, '(?im)selected\s+(?:isolation\s+)?tier\s*[:=]?\s*([A-Za-z0-9_\-]+)')
        $tiers[$name] = $(if ($m.Success) { $m.Groups[1].Value.Trim() } else { '' })
    }
    $bothReported = ($tiers['process'] -and $tiers['processcontainer'])
    Record-Result -Phase 'P13d' -Name "containment 'process' resolves to the same tier as 'processcontainer'" `
        -Pass ($bothReported -and ($tiers['process'] -eq $tiers['processcontainer'])) `
        -Detail ("process=[$($tiers['process'])]; processcontainer=[$($tiers['processcontainer'])]; " +
                 'requires both to report a tier, so two non-starting runs cannot match on empty strings')

    foreach ($enabled in $true, $false) {
        $slug = $(if ($enabled) { 'true' } else { 'false' })
        $cfg = New-Config -Name "lc-telemetry-$slug" -CommandLine $Script:LifecycleCmd -ReadWrite @($rw) `
            -TelemetryEnabled $enabled -SchemaVersion '0.9.0-alpha'
        $log = Join-Path $ScratchRoot "logs\lc-telemetry-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        Record-Result -Phase 'P13d' -Name "telemetry.enabled=$slug is accepted on 0.9.0-alpha" `
            -Pass (-not $rejected) `
            -Detail ("exit=$($r.ExitCode); rejectedAtValidation=$rejected; " +
                     'acceptance only -- the kill-switch can subtract from consent but never grant it')
    }

    # docs/schema.md marks telemetry as 0.9.0-alpha+, so emitting it on an
    # earlier version must be refused outright. Silently ignoring it would be
    # the damaging outcome: a caller asking for telemetry on 0.8 would believe
    # the request took effect.
    #
    # The error must name the field. A run that failed for an unrelated reason
    # would otherwise satisfy a bare "was rejected" check and prove nothing.
    $cfg = New-Config -Name 'lc-telemetry-0800' -CommandLine $Script:LifecycleCmd -ReadWrite @($rw) `
        -TelemetryEnabled $true -SchemaVersion '0.8.0-alpha'
    $log = Join-Path $ScratchRoot 'logs\lc-telemetry-0800.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
    $logText = Read-Log $log
    $gated = [bool]((Remove-ConfigEcho "$logText`n$($r.Stderr)") -match "(?i)telemetry.{0,60}schema version")
    Record-Result -Phase 'P13d' -Name 'telemetry is rejected on schema 0.8.0-alpha (0.9.0-alpha+ only)' `
        -Pass ((Test-WasRejected -Run $r -Log $logText) -and $gated) `
        -Detail "exit=$($r.ExitCode); errorNamesTheVersionGate=$gated"

    # The supported range is 0.6.0-alpha through 0.9.0-alpha inclusive
    # (schemas/schema-version.json). Both ends must be accepted and both
    # neighbours rejected, or the range is not actually a range.
    $versions = @(
        @{ V = '0.6.0-alpha'; Accept = $true;  Why = 'min supported' }
        @{ V = '0.7.0-alpha'; Accept = $true;  Why = 'in range' }
        @{ V = '0.8.0-alpha'; Accept = $true;  Why = 'in range, latest stable' }
        @{ V = '0.9.0-alpha'; Accept = $true;  Why = 'maxSupported' }
        @{ V = '0.5.0-alpha'; Accept = $false; Why = 'below min supported' }
        @{ V = '1.0.0';       Accept = $false; Why = 'above maxSupported' }
        @{ V = 'not-a-version'; Accept = $false; Why = 'unparseable' }
    )
    foreach ($case in $versions) {
        $slug = ($case.V -replace '[^a-zA-Z0-9]+', '-')
        $cfg = New-Config -Name "lc-version-$slug" -CommandLine $Script:LifecycleCmd -ReadWrite @($rw) `
            -SchemaVersion $case.V
        $log = Join-Path $ScratchRoot "logs\lc-version-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $rejected = Test-WasRejected -Run $r -Log (Read-Log $log)
        $verb = $(if ($case.Accept) { 'accepted' } else { 'rejected' })
        Record-Result -Phase 'P13d' -Name "schema version $($case.V) is $verb ($($case.Why))" `
            -Pass ($rejected -ne $case.Accept) `
            -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"
    }
}


Invoke-WpcPhase -Key 'Lifecycle'          -Body { Phase-Lifecycle }
Invoke-WpcPhase -Key 'InheritDefaultEnv'  -Body { Phase-InheritDefaultEnv }
Invoke-WpcPhase -Key 'ProcessEnv'         -Body { Phase-ProcessEnv }
Invoke-WpcPhase -Key 'IntentTelemetryVer' -Body { Phase-IntentTelemetryVersion }
Complete-WpcChild
