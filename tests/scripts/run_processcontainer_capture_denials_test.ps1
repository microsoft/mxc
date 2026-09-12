# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# processContainer.captureDenials -- Windows denial capture (Learning Mode).
#
# `outputPath` is validated by validate_capture_denials_output_path during
# config parsing, so Phase 14a's four rejections never reach the launch API —
# rare process-container coverage that still produces signal on a host which
# cannot start a container. The behavioral half (14b/14c) is host-dependent
# and fails honestly where a run cannot start.
#
# Documented contract (docs/schema.md, updated 2026-09-10):
#   * mode "block" (default) keeps access denied and logs it; "allow" permits
#     and logs it, relaxing deny-by-default and emitting a security warning
#   * outputPath must be absolute, not a root or existing directory, and its
#     parent must already exist
#   * a unique per-run id is stamped into the output stem, and the actual path
#     is printed on stderr
#   * retainEtl defaults to false
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


# Phase 14a -- outputPath validation
#
# Decided before launch, so these assertions hold on any host. Each one
# matches the documented error text as well as the rejection itself: a config
# that was rejected for an unrelated reason (a schema-shape mistake in the
# fixture, say) would otherwise score green and hide a broken test.
function Phase-CaptureDenialsOutputPath {
    Section 'Phase 14a: captureDenials.outputPath validation'

    $rw = Join-Path $ScratchRoot 'rw'
    $marker = 'MXC-CD-RAN'
    $cmd = "cmd /c echo $marker"
    $missingParent = Join-Path $ScratchRoot 'no-such-dir-here\denials.json'

    $cases = @(
        @{ Name    = 'relative outputPath is rejected'
           Path    = 'denials.json'
           Expect  = 'must be an absolute path' }
        @{ Name    = 'outputPath naming a drive root is rejected'
           Path    = 'C:\'
           Expect  = 'must name a file, not a directory root' }
        @{ Name    = 'outputPath with a missing parent directory is rejected'
           Path    = $missingParent
           Expect  = 'parent directory does not exist' }
        @{ Name    = 'outputPath naming an existing directory is rejected'
           Path    = $rw
           Expect  = 'must name a file, not an existing directory' }
    )

    foreach ($case in $cases) {
        $slug = ($case.Name -replace '[^a-zA-Z0-9]+', '-').Trim('-').ToLowerInvariant()
        $cfg = New-Config -Name "cd-path-$slug" -CommandLine $cmd -ReadWrite @($rw) `
            -CaptureDenialsOutputPath $case.Path
        $log = Join-Path $ScratchRoot "logs\cd-path-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $logText = Read-Log $log
        $all = "$logText`n$($r.Stderr)"
        $rejected = Test-WasRejected -Run $r -Log $logText
        $sawMsg = [bool]($all -match [regex]::Escape($case.Expect))
        $ranAnyway = [bool]("$($r.Stdout)" -match $marker)
        Record-Result -Phase 'P14a' -Name $case.Name `
            -Pass ($rejected -and $sawMsg -and (-not $ranAnyway)) `
            -Detail "exit=$($r.ExitCode); rejected=$rejected; sawDocumentedMessage=$sawMsg; workloadRan=$ranAnyway"
    }

    # An absolute path under an existing directory must pass validation. This
    # is the control for the four rejections above AND the proof that the
    # validator is not simply rejecting every outputPath.
    $okPath = Join-Path $ScratchRoot 'rw\denials-ok.json'
    $cfg = New-Config -Name 'cd-path-valid' -CommandLine $cmd -ReadWrite @($rw) `
        -CaptureDenialsOutputPath $okPath
    $log = Join-Path $ScratchRoot 'logs\cd-path-valid.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $logText = Read-Log $log
    $all = "$logText`n$($r.Stderr)"
    $pathComplaint = [bool]($all -match 'captureDenials\.outputPath')
    # Requires the run not to have been refused at all, not merely the absence
    # of one message: an unrelated rejection would otherwise score green.
    $wasRejected = Test-WasRejected -Run $r -Log $logText
    Record-Result -Phase 'P14a' -Name 'control: a valid absolute outputPath passes validation' `
        -Pass ((-not $pathComplaint) -and (-not $wasRejected)) `
        -Detail ("exit=$($r.ExitCode); rejected=$wasRejected; outputPath complaint in log=$pathComplaint; " +
                 'asserts validation only -- whether capture itself can run is P14b')
}


# Phase 14b -- mode and retainEtl are accepted
#
# Both spellings of `mode` plus both `retainEtl` values. These are acceptance
# assertions: they prove the section parses and the run proceeds, which is the
# part that does not depend on Learning Mode being available on the host.
function Phase-CaptureDenialsModes {
    Section 'Phase 14b: captureDenials mode / retainEtl acceptance'

    $rw = Join-Path $ScratchRoot 'rw'
    $marker = 'MXC-CD-RAN'
    $cmd = "cmd /c echo $marker"

    $cases = @(
        @{ Name = 'captureDenials mode=block is accepted'; Mode = 'block'; Retain = $null }
        @{ Name = 'captureDenials mode=allow is accepted'; Mode = 'allow'; Retain = $null }
        @{ Name = 'captureDenials with no mode (defaults to block) is accepted'; Mode = $null; Retain = $null }
        @{ Name = 'captureDenials retainEtl=false is accepted'; Mode = 'block'; Retain = $false }
        @{ Name = 'captureDenials retainEtl=true is accepted'; Mode = 'block'; Retain = $true }
    )

    foreach ($case in $cases) {
        $slug = ($case.Name -replace '[^a-zA-Z0-9]+', '-').Trim('-').ToLowerInvariant()
        $cfgArgs = @{
            Name        = "cd-mode-$slug"
            CommandLine = $cmd
            ReadWrite   = @($rw)
        }
        if ($case.Mode) { $cfgArgs['CaptureDenialsMode'] = $case.Mode }
        if ($null -ne $case.Retain) { $cfgArgs['CaptureDenialsRetainEtl'] = $case.Retain }
        # Every case must set at least one captureDenials field, or the
        # section is omitted entirely and the assertion tests nothing. The
        # no-mode case gets retainEtl=false to keep the section present.
        if (-not $case.Mode -and $null -eq $case.Retain) { $cfgArgs['CaptureDenialsRetainEtl'] = $false }

        $cfg = New-Config @cfgArgs
        $log = Join-Path $ScratchRoot "logs\cd-mode-$slug.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
        $logText = Read-Log $log
        # Acceptance means "not rejected during validation". The run may still
        # fail for host reasons, which the detail records without masking.
        $rejected = Test-WasRejected -Run $r -Log $logText
        Record-Result -Phase 'P14b' -Name $case.Name -Pass (-not $rejected) `
            -Detail "exit=$($r.ExitCode); rejectedAtValidation=$rejected"
    }

    # Documented: allow mode "relaxes deny-by-default, emits a security
    # warning". The warning is the user-visible half of that contract, and a
    # silent relaxation of deny-by-default is exactly the regression worth
    # catching. Asserted only when the run got far enough to emit it.
    $cfg = New-Config -Name 'cd-allow-warning' -CommandLine $cmd -ReadWrite @($rw) `
        -CaptureDenialsMode 'allow'
    $log = Join-Path $ScratchRoot 'logs\cd-allow-warning.log'
    $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
    $all = "$(Read-Log $log)`n$($r.Stderr)"
    $sawWarning = [bool]($all -match '(?i)warn.{0,80}(denial|deny|audit|allow)|(?i)(denial|audit).{0,80}warn')
    Record-Result -Phase 'P14b' -Name 'captureDenials mode=allow emits a security warning' `
        -Pass $sawWarning `
        -Detail ("exit=$($r.ExitCode); sawWarning=$sawWarning; " +
                 'allow mode relaxes deny-by-default, so the warning is the documented user-visible signal')
}


# Phase 14c -- the per-run stamped output path
#
# Documented: "a unique per-run id is stamped into the stem and the actual
# path is printed on stderr". Both halves are checked, and the uniqueness
# claim is checked the only way it can be -- by running twice and comparing.
#
# Two runs that both fail to start produce no path at all, which fails here
# rather than passing vacuously on two equal empty strings.
function Phase-CaptureDenialsStampedPath {
    Section 'Phase 14c: captureDenials per-run output path'

    $rw = Join-Path $ScratchRoot 'rw'
    $requested = Join-Path $ScratchRoot 'rw\stamped.json'
    $cmd = 'cmd /c echo MXC-CD-RAN'

    # The stem is stamped, so the reported path contains "stamped" plus
    # something else before the extension.
    $pattern = '(?im)^.*?([A-Za-z]:\\[^\r\n"]*stamped[^\r\n"]*\.json).*$'

    $observed = @()
    foreach ($i in 1, 2) {
        $cfg = New-Config -Name "cd-stamped-$i" -CommandLine $cmd -ReadWrite @($rw) `
            -CaptureDenialsOutputPath $requested
        $log = Join-Path $ScratchRoot "logs\cd-stamped-$i.log"
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 60
        # The config echo repeats the REQUESTED path verbatim, so matching the
        # raw log would find the un-stamped path and score the uniqueness
        # assertion against two identical strings. Strip it first and read
        # only what the runner reported.
        $all = Remove-ConfigEcho "$($r.Stderr)`n$(Read-Log $log)"
        $m = [regex]::Match($all, $pattern)
        $observed += $(if ($m.Success) { $m.Groups[1].Value } else { '' })
    }

    $both = @($observed | Where-Object { $_ })
    Record-Result -Phase 'P14c' -Name 'the actual denials output path is reported on stderr' `
        -Pass ($both.Count -eq 2) `
        -Detail "reportedPaths=$($both.Count)/2; [$($observed -join ' | ')]"

    Record-Result -Phase 'P14c' -Name 'the reported path is not the verbatim requested path (a per-run id is stamped in)' `
        -Pass (($both.Count -eq 2) -and ($observed[0] -ne $requested)) `
        -Detail "requested=$requested; reported=$($observed[0])"

    Record-Result -Phase 'P14c' -Name 'two runs of the same config report different output paths' `
        -Pass (($both.Count -eq 2) -and ($observed[0] -ne $observed[1])) `
        -Detail ("run1=$($observed[0]); run2=$($observed[1]); " +
                 'requires two reported paths, so two failed launches cannot pass this on empty strings')
}


Invoke-WpcPhase -Key 'CaptureDenialsOutputPath' -Body { Phase-CaptureDenialsOutputPath }
Invoke-WpcPhase -Key 'CaptureDenialsModes'      -Body { Phase-CaptureDenialsModes }
Invoke-WpcPhase -Key 'CaptureDenialsStamped'    -Body { Phase-CaptureDenialsStampedPath }
Complete-WpcChild
