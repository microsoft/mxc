# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# lifecycle.* and the process.* knobs no other area sets.
#
# Covers `lifecycle.destroyOnExit`, `lifecycle.preservePolicy`,
# `process.inheritDefaultEnv`, `telemetry.enabled` and the
# `containment: "process"` intent alias.
#
# Phase 13b checks both the supported v0.9 field and its behavior. A retired
# v0.8 request must fail at version dispatch, before any workload starts.
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


# Phase 13b -- process.inheritDefaultEnv and the supported contract floor
#
# Supported on 0.9.0-alpha and later. Retired versions fail before the
# parser inspects individual fields; the positive cases below check that
# the supported field is accepted and layers the environment correctly.
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
    # The old contract is refused at version dispatch, before field parsing.
    # A workload failure or a config echo is not evidence of this rejection.
    $all = Remove-ConfigEcho "$logText`n$($r.Stderr)"
    $unsupported = [bool]($all -match 'Unsupported contract version')
    $ran = [bool]("$($r.Stdout)" -match 'MINE=\[yes\]')
    Record-Result -Phase 'P13b' -Name 'retired schema 0.8 is rejected before inheritDefaultEnv runs' `
        -Pass ((Test-WasRejected -Run $r -Log $logText) -and $unsupported -and (-not $ran)) `
        -Detail "exit=$($r.ExitCode); unsupportedVersion=$unsupported; workloadRan=$ran"

    $versionCases = @(
        @{ Name = 'inheritDefaultEnv=true is accepted on schema 0.9.0-alpha';  Inherit = $true }
        @{ Name = 'inheritDefaultEnv=false is accepted on schema 0.9.0-alpha'; Inherit = $false }
    )
    foreach ($case in $versionCases) {
        $slug = $(if ($case.Inherit) { 'true' } else { 'false' })
        # A verbatim environment still has to carry the variables Windows needs
        # to launch a container; these cases are about whether the schema
        # accepts the field, so don't let an unrelated env check decide them.
        $envList = $(if ($case.Inherit) {
            @('MXC_LC_MINE=yes')
        } else {
            Get-MinimalEnv -Extra @('MXC_LC_MINE=yes')
        })
        $cfg = New-Config -Name "lc-inherit-0900-$slug" -CommandLine $cmd -ReadWrite @($rw) `
            -Env $envList -InheritDefaultEnv $case.Inherit -SchemaVersion '0.9.0-alpha'
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
        -Env @('MXC_LC_MINE=yes') -InheritDefaultEnv $true
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
        $tiers[$name] = Get-SelectedTier -LogContent $logText
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

    # A retired version must fail at dispatch before telemetry policy or the
    # workload runs; the positive v0.9 cases above cover the supported field.
    $cfg = New-Config -Name 'lc-telemetry-0800' -CommandLine $Script:LifecycleCmd -ReadWrite @($rw) `
        -TelemetryEnabled $true -SchemaVersion '0.8.0-alpha'
    $log = Join-Path $ScratchRoot 'logs\lc-telemetry-0800.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
    $logText = Read-Log $log
    $unsupported = [bool]((Remove-ConfigEcho "$logText`n$($r.Stderr)") -match
        'Unsupported contract version')
    $ran = [bool]("$($r.Stdout)" -match $Script:LifecycleMarker)
    Record-Result -Phase 'P13d' -Name 'retired schema 0.8 is rejected before telemetry runs' `
        -Pass ((Test-WasRejected -Run $r -Log $logText) -and $unsupported -and (-not $ran)) `
        -Detail "exit=$($r.ExitCode); unsupportedVersion=$unsupported; workloadRan=$ran"

    # Every exact registered version in schemas/schema-version.json must be
    # accepted. Versions outside that closed set must be rejected, including
    # neighbors below the minimum and above the development contract.
    $versions = @(
        @{ V = '0.9.0-alpha'; Accept = $true;  Why = 'min supported' }
        @{ V = '1.0.0';       Accept = $true;  Why = 'latest stable' }
        @{ V = '1.1.0-alpha'; Accept = $true;  Why = 'development contract' }
        @{ V = '0.6.0-alpha'; Accept = $false; Why = 'retired contract' }
        @{ V = '0.7.0-alpha'; Accept = $false; Why = 'retired contract' }
        @{ V = '0.8.0-alpha'; Accept = $false; Why = 'retired contract' }
        @{ V = '0.10.0-alpha'; Accept = $false; Why = 'unregistered contract' }
        @{ V = '0.5.0-alpha'; Accept = $false; Why = 'below min supported' }
        @{ V = '1.2.0-alpha'; Accept = $false; Why = 'above development contract' }
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
