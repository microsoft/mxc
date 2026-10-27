# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Config values the executor must refuse before a container exists.
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

function ConvertTo-JsonStringLiteral {
    param([Parameter(Mandatory)][string]$Value)
    return $Value.Replace('\', '\\').Replace('"', '\"')
}

function Write-LiteralConfig {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Json
    )
    $path = Join-Path (Join-Path $ScratchRoot 'configs') "$Name.json"
    [System.IO.File]::WriteAllText($path, $Json, [System.Text.UTF8Encoding]::new($false))
    return $path
}

function Test-HasRawNul {
    param([string]$Text, [string]$Path)
    if ($Text -and $Text.Contains([char]0)) { return $true }
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        return [System.Array]::IndexOf($bytes, [byte]0) -ge 0
    }
    return $false
}

# Refused at parse time, before any container or host-file change.
#
# The JSON file must contain the six-character escape, not a raw NUL.
# ConvertTo-Json is not used for this case. The control is the same shape
# with an ordinary id, so a host where nothing launches cannot turn the
# rejection green.
function Phase-ConfigRejections {
    Section 'Config rejections: containerId embedded NUL'

    $marker = 'CFG-REJECT-RAN'
    $cmd = "$env:SystemRoot\System32\cmd.exe /c echo $marker"
    $rw = Join-Path $ScratchRoot 'rw'
    $version = $Script:SchemaVersion
    $cmdJson = ConvertTo-JsonStringLiteral $cmd
    $rwJson = ConvertTo-JsonStringLiteral $rw
    $sysJson = ConvertTo-JsonStringLiteral $env:SystemRoot

    $nulPath = Write-LiteralConfig -Name 'cfg-rej-nul' -Json @"
{
  "version": "$version",
  "containerId": "alpha\u0000evil",
  "containment": "processcontainer",
  "process": { "commandLine": "$cmdJson", "timeout": 20000 },
  "filesystem": { "readwritePaths": ["$rwJson"], "readonlyPaths": ["$sysJson"] },
  "ui": { "disable": false }
}
"@
    $nulText = [System.IO.File]::ReadAllText($nulPath)
    $escapePreserved = ($nulText -match 'alpha\\u0000evil') -and -not (Test-HasRawNul -Path $nulPath)
    Record-Result -Phase 'P8g' -Name 'rejection config keeps the JSON NUL escape' `
        -Pass $escapePreserved `
        -Detail $(if ($escapePreserved) { 'literal \u0000 preserved; no raw NUL in the config file' } else { 'config file lost the escape or contains a raw NUL' })

    $log = Join-Path $ScratchRoot 'logs\cfg-rej-nul.log'
    $run = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $nulPath -LogPath $log -TimeoutSec 30
    $logText = $(if (Test-Path -LiteralPath $log) { [System.IO.File]::ReadAllText($log) } else { '' })
    $combined = "$logText`n$($run.Stdout)`n$($run.Stderr)"
    $ranAnyway = [bool]("$($run.Stdout)" -match [regex]::Escape($marker))
    $namedRejection = $combined.Contains('containerId must not contain null bytes')
    $rawNul = Test-HasRawNul -Text $combined -Path $log
    Record-Result -Phase 'P8g' -Name 'embedded NUL containerId is rejected before the workload runs' `
        -Pass ((Test-WasRejected -Run $run -Log $logText) -and $namedRejection -and -not $ranAnyway -and -not $rawNul) `
        -Detail "exit=$($run.ExitCode); timedOut=$($run.TimedOut); workloadRan=$ranAnyway; messagePresent=$namedRejection; rawNul=$rawNul"

    $ctlPath = New-Config -Name 'cfg-rej-control' -CommandLine $cmd -ReadWrite @($rw) -ReadOnly @($env:SystemRoot) -TimeoutMs 20000
    $ctlLog = Join-Path $ScratchRoot 'logs\cfg-rej-control.log'
    $ctl = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $ctlPath -LogPath $ctlLog -TimeoutSec 60
    $ctlRan = [bool]("$($ctl.Stdout)" -match [regex]::Escape($marker))
    Record-Result -Phase 'P8g' -Name 'positive control: ordinary containerId runs' `
        -Pass (($ctl.ExitCode -eq 0) -and $ctlRan -and -not $ctl.TimedOut) `
        -Detail ("exit=$($ctl.ExitCode); timedOut=$($ctl.TimedOut); workloadRan=$ctlRan; " +
                 'without this, the rejection above is indistinguishable from a host on which nothing launches')
}

Invoke-WpcPhase -Key 'ConfigRejections' -Body { Phase-ConfigRejections }
Complete-WpcChild
