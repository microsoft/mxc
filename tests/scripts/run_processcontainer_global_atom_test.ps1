# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# run_processcontainer_global_atom_test.ps1
#
# Bidirectional global atom table isolation.
#
# Normally invoked by run_processcontainer_all_tests.ps1; runs standalone too:
#
#   .\run_processcontainer_global_atom_test.ps1 -RequireTier base-container
#
# Exit codes: 0 = all passed, 1 = a failure or zero assertions, 78 = fatal.

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
    [string]$CapsJson,
    [string]$RequireTier,
    [string]$ExternalAnchorUrl,
    [string]$UnlistedDestinationUrl,
    [switch]$SkipNetwork,
    [switch]$SkipReleaseLane,
    [switch]$KeepArtifacts,
    [switch]$ReuseScratch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')
. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Native.ps1')

Initialize-WpcContext @PSBoundParameters


# -----------------------------------------------------------------------
# Phase 4c — GLOBALATOMS bidirectional isolation (host baseline tier)
#
# GLOBALATOMS does not make the atom APIs fail — each job gets its own
# private atom table, so GlobalAddAtomW still succeeds inside the container.
# The restriction is verified as isolation, in both directions:
#
#   * host -> guest: the host plants a global atom; the probe must not find
#     it (GLOBALATOMS_HOST_TO_GUEST=PASS|FAIL).
#   * guest -> host: the probe adds an atom and blocks on a release file
#     while the host checks its own table. The handshake is required — the
#     job-private table is torn down when the container exits.
# -----------------------------------------------------------------------
function Invoke-GlobalAtomProbe {
    # Runs the GLOBALATOMS bidirectional handshake once with the given
    # isolation mode and returns the observed results so the caller can assert
    # either the isolated (container) or non-isolated (desktop) expectation.
    # Returns: HostToGuest (PASS|FAIL|<missing>), GuestFound (UInt16 atom, or
    # $null if the probe never signalled ready), TierMatch (bool), Detail.
    param(
        [Parameter(Mandatory)] [string]$Isolation,
        [Parameter(Mandatory)] [string]$Name
    )
    $rw = Join-Path $ScratchRoot 'rw'
    New-Item -ItemType Directory -Path $rw -Force | Out-Null

    $suffix      = [guid]::NewGuid().ToString('N')
    $hostName    = "MxcWinPCHostAtom_$suffix"
    $guestName   = "MxcWinPCGuestAtom_$suffix"
    $readyFile   = Join-Path $rw "globalatom-ready-$suffix"
    $releaseFile = Join-Path $rw "globalatom-release-$suffix"
    Remove-Item -LiteralPath $readyFile, $releaseFile -ErrorAction SilentlyContinue

    # Plant the host-side global atom (the direction-1 reference). Held alive
    # until the finally block — PowerShell stays running, so it persists for
    # the whole contained run.
    $hostAtom = [Mxc.AtomNative]::GlobalAddAtomW($hostName)
    if ($hostAtom -eq 0) {
        return [pscustomobject]@{ HostToGuest = '<missing>'; GuestFound = $null; TierMatch = $false; Detail = 'host GlobalAddAtomW returned 0' }
    }

    $cmd = "`"$UiProbeDebug`" GLOBALATOMS " +
        "--atom-host-name=$hostName --atom-guest-name=$guestName " +
        "--atom-ready-file=`"$readyFile`" --atom-release-file=`"$releaseFile`""
    $cfg = New-Config -Name $Name `
        -CommandLine $cmd `
        -ReadWrite @($rw) `
        -UiDisable $false `
        -BpUiIsolation $Isolation
    $log = Join-Path $ScratchRoot "logs\$Name.log"

    # Match Invoke-Wxc's defensive scrub of the test-only tier override.
    Remove-Item Env:\MXC_FORCE_TIER -ErrorAction SilentlyContinue

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $WxcDebug
    $psi.Arguments = "--config `"$cfg`" --experimental --log-file `"$log`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    # The probe blocks mid-run waiting on the release file, so we cannot use
    # the synchronous Invoke-Wxc (which reads stdout only after exit). Drain
    # both streams asynchronously to avoid a pipe-buffer deadlock while the
    # child is parked.
    $sbOut = New-Object System.Text.StringBuilder
    $sbErr = New-Object System.Text.StringBuilder
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    # Use explicit SourceIdentifiers so the finally block can unregister the
    # subscriptions AND remove the backing PSEventJobs unambiguously.
    # Unregister-Event removes only the subscription, not the job it created,
    # so without Remove-Job the jobs accumulate across same-session re-runs.
    $outSid = "MxcGAOut_$suffix"
    $errSid = "MxcGAErr_$suffix"
    $outEvt = Register-ObjectEvent -InputObject $p -EventName OutputDataReceived -SourceIdentifier $outSid -MessageData $sbOut -Action {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    }
    $errEvt = Register-ObjectEvent -InputObject $p -EventName ErrorDataReceived -SourceIdentifier $errSid -MessageData $sbErr -Action {
        if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    }

    $guestFound = $null
    try {
        [void]$p.Start()
        $p.BeginOutputReadLine()
        $p.BeginErrorReadLine()

        # Wait for the probe to signal that its atom now exists.
        $deadline = (Get-Date).AddSeconds(30)
        $ready = $false
        while ((Get-Date) -lt $deadline) {
            if (Test-Path -LiteralPath $readyFile) { $ready = $true; break }
            if ($p.HasExited) { break }
            Start-Sleep -Milliseconds 100
        }

        if ($ready) {
            # Direction 2: does the host find the contained process's atom?
            $guestFound = [Mxc.AtomNative]::GlobalFindAtomW($guestName)
        }

        # Release the probe so it deletes its atom and exits.
        Set-Content -LiteralPath $releaseFile -Value 'go' -ErrorAction SilentlyContinue

        if (-not $p.WaitForExit(30000)) {
            try { $p.Kill() } catch {}
        }
        $p.WaitForExit()   # ensure async stdout/stderr handlers flush
    }
    finally {
        # Remove the host-planted atom regardless of outcome.
        [void][Mxc.AtomNative]::GlobalDeleteAtom($hostAtom)
        # Unregister the subscriptions, then remove the PSEventJobs they
        # created (Unregister-Event leaves the job behind).
        foreach ($sid in @($outSid, $errSid)) {
            Unregister-Event -SourceIdentifier $sid -ErrorAction SilentlyContinue
            Remove-Job -Name $sid -Force -ErrorAction SilentlyContinue
        }
    }

    $stdout = $sbOut.ToString()
    $logContent = Read-Log $log
    Assert-NoBfscfg -LogContent $logContent -Phase 'P4c' -Name $Name
    $tierMatch = Test-SelectedTier -LogContent $logContent
    $h2g = if ($stdout -match '(?m)^GLOBALATOMS_HOST_TO_GUEST=(?<v>PASS|FAIL)\s*$') { $matches['v'] } else { '<missing>' }
    return [pscustomobject]@{ HostToGuest = $h2g; GuestFound = $guestFound; TierMatch = $tierMatch; Detail = "stdout=$(Format-VerdictSummary ($stdout.Trim()) 'blocked' 'allowed')" }
}

function Phase-GlobalAtomIsolation {
    Section 'Phase 4c: GLOBALATOMS bidirectional isolation (host baseline tier)'

    # ---- Positive: isolation=container sets UILIMIT_GLOBALATOMS -> isolated.
    $pos = Invoke-GlobalAtomProbe -Isolation 'container' -Name 'ui-globalatoms'
    Record-Result -Phase 'P4c' -Name "selected isolation tier: $($Script:ExpectedTier)" -Pass $pos.TierMatch
    Record-Result -Phase 'P4c' -Name 'host atom NOT visible to contained process (host->guest)' -Pass ($pos.HostToGuest -eq 'PASS') -Detail "expected=blocked; got=$(Format-Verdict $pos.HostToGuest 'blocked' 'allowed'); $($pos.Detail)"
    if ($null -eq $pos.GuestFound) {
        Record-Result -Phase 'P4c' -Name 'contained atom NOT visible to host (guest->host)' -Pass $false -Detail 'probe never signalled ready; no guest-atom check performed'
    } else {
        Record-Result -Phase 'P4c' -Name 'contained atom NOT visible to host (guest->host)' -Pass ($pos.GuestFound -eq 0) -Detail "GlobalFindAtomW=$($pos.GuestFound) (0 = not found = isolated)"
    }

    # ---- Negative control: isolation=desktop sets NO UILIMIT_GLOBALATOMS, so
    # the global atom table is shared. The probe MUST see the host atom and the
    # host MUST see the guest atom — proving the positive results above are not
    # vacuous (e.g. an atom API silently failing would otherwise read as PASS).
    $neg = Invoke-GlobalAtomProbe -Isolation 'desktop' -Name 'ui-globalatoms-neg'
    Record-Result -Phase 'P4c' -Name 'negative control: host atom visible without UILIMIT_GLOBALATOMS (host->guest)' -Pass ($neg.HostToGuest -eq 'FAIL') -Detail "expected=allowed; got=$(Format-Verdict $neg.HostToGuest 'blocked' 'allowed'); $($neg.Detail)"
    if ($null -eq $neg.GuestFound) {
        Record-Result -Phase 'P4c' -Name 'negative control: contained atom VISIBLE to host without UILIMIT_GLOBALATOMS' -Pass $false -Detail 'probe never signalled ready; no guest-atom check performed'
    } else {
        Record-Result -Phase 'P4c' -Name 'negative control: contained atom VISIBLE to host without UILIMIT_GLOBALATOMS' -Pass ($neg.GuestFound -ne 0) -Detail "GlobalFindAtomW=$($neg.GuestFound) (nonzero = found = NOT isolated)"
    }
}

Invoke-WpcPhase -Key 'GlobalAtomIsolation' -Body { Phase-GlobalAtomIsolation }
Complete-WpcChild

