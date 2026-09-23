# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# processContainer.filesystem.enumeratePaths — enumeration-only filesystem
# access (FindFirstFile/FindNextFile without content read).
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


# Phase 4e — enumeratePaths
#
# The field is 0.9-only and has NO fallback tier: the detector refuses the
# request outright unless the host selects base-container AND advertises
# PSE_SUPPORT_FS_ENUMERATE under PSEC 1.1 (FallbackError::
# EnumeratePathsUnsupported / PSEC_ENUMERATE_PATHS_UNSUPPORTED_MSG). So this
# area asserts three separable properties, and only the last needs a capable
# host:
#
#   1. the 0.9 version gate — the same policy authored at 0.8 is rejected;
#   2. probe/detector agreement — the request-scoped `--probe` verdict matches
#      the capability the empty-policy probe advertised;
#   3. enforcement — on a capable host, the grant lists the directory and does
#      NOT confer content read; on an incapable one the request is refused with
#      an attributed message rather than running unenforced.
function Phase-FsEnumerate {
    Section 'Phase 4e: processContainer.filesystem.enumeratePaths'
    Reset-StateFileBaseline

    $enum    = Join-Path $ScratchRoot 'enumerate'
    $control = Join-Path $ScratchRoot 'enumerate-control'

    # Distinct names so a listing proves WHICH directory was enumerated.
    $visibleName = 'enum-visible.txt'
    $hiddenName  = 'control-hidden.txt'
    # If the child ever echoes this, the grant conferred content read and
    # enumeration-only access is not what shipped.
    $sentinel = 'ENUM_CONTENT_SENTINEL_9f31c2'
    Set-Content -LiteralPath (Join-Path $enum $visibleName)    -Value $sentinel -Encoding utf8 -Force
    Set-Content -LiteralPath (Join-Path $control $hiddenName)  -Value $sentinel -Encoding utf8 -Force

    $aclEnumBefore    = Get-Acl-Snapshot $enum
    $aclControlBefore = Get-Acl-Snapshot $control

    # --- 1. version gate ------------------------------------------------
    # 0.8's processContainer contract is closed and has no `filesystem` member,
    # so authoring the field there must be refused. Without this, a silent
    # acceptance at 0.8 would look identical to a correct 0.9 run.
    $cfgV08 = New-Config -Name 'fsenum-v08-gate' `
        -CommandLine 'cmd /c exit 0' -EnumeratePaths @($enum) -SchemaVersion $Script:SchemaVersion
    $logV08 = Join-Path $ScratchRoot 'logs\fsenum-v08-gate.log'
    $rV08 = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgV08 -LogPath $logV08 -TimeoutSec 30
    Record-Result -Phase 'P4e' -Name "enumeratePaths is rejected at $($Script:SchemaVersion) (0.9-only field)" `
        -Pass (Test-WasRejected -Run $rV08 -Log (Read-Log $logV08)) `
        -Detail "exit=$($rV08.ExitCode); stderr=$(Format-Snippet $rV08.Stderr)"

    # --- 2. probe / detector agreement ----------------------------------
    $cfg = New-Config -Name 'fsenum' `
        -CommandLine (New-ProbeCommand -Body "dir /b `"$enum`"") `
        -EnumeratePaths @($enum) -ReadOnly @($env:SystemRoot)
    $probe = Invoke-Probe -Wxc $WxcRelease -ConfigPath $cfg -Phase 'P4e' -Name 'fsenum-probe'
    if (-not $probe) {
        Record-Result -Phase 'P4e' -Name 'enumeratePaths probe succeeded' -Pass $false -Detail 'probe returned null; cannot proceed'
        return
    }
    # Under Set-StrictMode, reading an absent property throws; the detector
    # omits `tier` entirely when it refuses the request.
    $probeTier  = if ($probe.PSObject.Properties['tier'])  { [string]$probe.tier }  else { '' }
    $probeError = if ($probe.PSObject.Properties['error']) { [string]$probe.error } else { '' }

    if ($Script:Caps.SupportsEnumeratePaths) {
        Record-Result -Phase 'P4e' -Name 'enumeratePaths probe resolves to base-container' `
            -Pass ($probeTier -eq 'base-container') -Detail "tier=$probeTier; error=$probeError"
        $expAug = Get-ExpectedDaclAug -HasDenied:$false
        $probeAug = if ($probe.PSObject.Properties['needsDaclAugmentation']) { $probe.needsDaclAugmentation } else { '<missing>' }
        Record-Result -Phase 'P4e' -Name "enumeratePaths probe -> needsDaclAugmentation=$expAug (PSEC-native, no host ACEs)" `
            -Pass ($probeAug -eq $expAug) -Detail "needsDaclAugmentation=$probeAug"
    } else {
        # The refusal must name the field. A bare "no tier" would also be
        # produced by an unrelated detector failure, which would let a broken
        # host score this green.
        Record-Result -Phase 'P4e' -Name 'enumeratePaths probe refuses the request (no tier)' `
            -Pass ([string]::IsNullOrEmpty($probeTier)) -Detail "tier=$probeTier"
        Record-Result -Phase 'P4e' -Name 'enumeratePaths probe attributes the refusal to enumeratePaths' `
            -Pass ($probeError -match '(?i)enumeratePaths') -Detail "error=$(Format-Snippet $probeError)"
    }

    # --- 3. enforcement --------------------------------------------------
    if (-not $Script:Caps.SupportsEnumeratePaths) {
        # Not a skip: the documented refusal is itself testable, and it is the
        # property that matters most here. enumeratePaths cannot degrade to an
        # AppContainer tier, so a host that quietly ran the workload without
        # the grant would be the real defect.
        $log = Join-Path $ScratchRoot 'logs\fsenum-unsupported.log'
        $r = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfg -LogPath $log -TimeoutSec 30
        $combined = "$($r.Stdout)`n$($r.Stderr)`n$(Read-Log $log)"

        # wxc-exec exits 1 when it refuses a request; -1 means a launch API
        # failed, which would mean the policy was never judged.
        Record-Result -Phase 'P4e' -Name 'unsupported host refuses the run (exit=1)' `
            -Pass (-not $r.TimedOut -and $r.ExitCode -eq 1) `
            -Detail "exit=$($r.ExitCode); timedOut=$($r.TimedOut)"
        Record-Result -Phase 'P4e' -Name 'refusal is attributed to enumeratePaths, not generic' `
            -Pass ($combined -match '(?i)enumeratePaths') `
            -Detail "stderr=$(Format-Snippet $r.Stderr)"
        Record-Result -Phase 'P4e' -Name 'refused run never started the workload' `
            -Pass (-not (Test-WorkloadRan $r)) -Detail 'the refusal must precede CreateProcess'
        Record-Result -Phase 'P4e' -Name 'refused run disclosed no file content' `
            -Pass (-not ($combined -match [regex]::Escape($sentinel)))
        Record-Result -Phase 'P4e' -Name 'refused run left enumerate ACL untouched' `
            -Pass ($aclEnumBefore -eq (Get-Acl-Snapshot $enum))
        Record-Result -Phase 'P4e' -Name 'refused run left no orphan state files' `
            -Pass (@(Get-NewStateFiles).Count -eq 0)
        return
    }

    # Capable host: prove the grant enumerates and nothing more.
    #
    # No `>nul` redirects — AppContainer does not reliably grant the NUL
    # device, and the parser only consumes ^(TAG)=(PASS|FAIL)$, so letting
    # `dir` and `type` write to stdout/stderr is harmless and keeps their
    # output available for the name/sentinel assertions below.
    $clauses = @(
        "(dir /b ""$enum"") && echo ENUM_LIST=PASS || echo ENUM_LIST=FAIL"
        "(type ""$enum\$visibleName"") && echo ENUM_READ=PASS || echo ENUM_READ=FAIL"
        # A directory named by no policy must not be enumerable. Without this
        # row, an ambient-access host would score ENUM_LIST green having proven
        # nothing about the grant.
        "(dir /b ""$control"") && echo CTL_LIST=PASS || echo CTL_LIST=FAIL"
    )
    $cfgMatrix = New-Config -Name 'fsenum-matrix' `
        -CommandLine (New-ProbeCommand -Body ($clauses -join ' & ')) `
        -EnumeratePaths @($enum) -ReadOnly @($env:SystemRoot)
    $logMatrix = Join-Path $ScratchRoot 'logs\fsenum-matrix.log'
    $rMatrix = Invoke-Wxc -Wxc $WxcDebug -ConfigPath $cfgMatrix -LogPath $logMatrix
    $logContent = Read-Log $logMatrix
    $ran = Test-WorkloadRan $rMatrix

    $matrix = @{}
    foreach ($line in ($rMatrix.Stdout -split "`r?`n")) {
        if ($line -match '^(?<k>ENUM_LIST|ENUM_READ|CTL_LIST)=(?<v>PASS|FAIL)\s*$') {
            $matrix[$matches['k']] = $matches['v']
        }
    }
    $matrixSummary = ($matrix.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '

    function Assert-EnumMatrix {
        param([string]$Key, [string]$Want, [string]$Reason)
        $got = if ($matrix.ContainsKey($Key)) { $matrix[$Key] } else { '<missing>' }
        $wantV = Format-Verdict $Want 'allowed' 'denied'
        $gotV  = Format-Verdict $got  'allowed' 'denied'
        $fullV = Format-VerdictSummary $matrixSummary 'allowed' 'denied'
        # AND-ed with $ran: every negative row is satisfied by a workload that
        # never started.
        Record-Result -Phase 'P4e' -Name "matrix $Key ($Reason)" -Pass ($ran -and $got -eq $Want) `
            -Detail "ran=$ran; expected=$wantV; got=$gotV; full=$fullV"
    }

    Record-Result -Phase 'P4e' -Name 'workload actually started' -Pass $ran `
        -Detail "marker seen=$ran; the rows below are only meaningful if it did"
    Record-Result -Phase 'P4e' -Name "selected isolation tier: base-container" `
        -Pass ([bool]($logContent -match '(?im)selected isolation tier:.*?base-container')) `
        -Detail 'enumeratePaths has no AppContainer fallback'

    Assert-EnumMatrix 'ENUM_LIST' 'PASS' 'the grant must allow directory enumeration'
    Assert-EnumMatrix 'ENUM_READ' 'FAIL' 'enumeration-only must NOT confer content read'
    Assert-EnumMatrix 'CTL_LIST'  'FAIL' 'a directory in no policy must stay unenumerable'

    Record-Result -Phase 'P4e' -Name 'listing actually named the granted file' `
        -Pass ($ran -and $rMatrix.Stdout -match [regex]::Escape($visibleName)) `
        -Detail "ran=$ran; looked for '$visibleName' in the child's dir output"
    Record-Result -Phase 'P4e' -Name 'listing did not name the control file' `
        -Pass ($ran -and -not ($rMatrix.Stdout -match [regex]::Escape($hiddenName))) `
        -Detail "ran=$ran; '$hiddenName' must not appear"
    Record-Result -Phase 'P4e' -Name 'child never disclosed file content' `
        -Pass ($ran -and -not ("$($rMatrix.Stdout)`n$($rMatrix.Stderr)" -match [regex]::Escape($sentinel))) `
        -Detail "ran=$ran; sentinel must not appear on either stream"

    # enumeratePaths is enforced natively by PSEC, so neither fixture may be
    # touched host-side.
    Record-Result -Phase 'P4e' -Name 'enumerate ACL untouched (no host DACL augmentation)' `
        -Pass ($aclEnumBefore -eq (Get-Acl-Snapshot $enum))
    Record-Result -Phase 'P4e' -Name 'control ACL untouched' `
        -Pass ($aclControlBefore -eq (Get-Acl-Snapshot $control))
    Record-Result -Phase 'P4e' -Name 'no orphan state files' `
        -Pass (@(Get-NewStateFiles).Count -eq 0) -Detail "files=$(@(Get-NewStateFiles).Count)"
}

Invoke-WpcPhase -Key 'FsEnumerate' -Body { Phase-FsEnumerate }
Complete-WpcChild
