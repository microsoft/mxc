<#
.SYNOPSIS
    Runs nanvixd directly to isolate MicroVM boot failures from MXC.

.DESCRIPTION
    MicroVM tests can hang or time out without revealing whether the fault is
    in nanvixd (the VM monitor) or in how wxc-exec invokes it. This probe skips
    MXC entirely and boots nanvixd itself, bounded by a timeout so it can never
    hang a job.

    Two boot paths are exercised because they fail independently:

      - cold: `-kernel-args snapshot`, the path that builds a snapshot from
              scratch. This is what the build machine runs.
      - warm: `-snapshot snapshots\kernel.whp.cbor`, the path wxc-exec actually
              uses at runtime. MXC ships snapshots produced on the *build*
              machine, so a warm start can fail on a test host even when a cold
              boot succeeds.

    Getting diagnostics out of nanvixd requires care: by default it writes its
    trace to a file under `-log-dir` (default `<cwd>/logs`), so its stdout and
    stderr are empty on a *successful* run as well as a hung one. This probe
    passes `-log-to-stdout` and `-console-file` so the boot trace and guest
    console are actually captured, keeps everything it collects, and takes a
    minidump of a hung process so its thread stacks can be inspected offline.

    Diagnostic only: always exits 0 so it reports findings without failing the
    lane. Interpretation:

      - Exit 0 with snapshot files -> that boot path works on this host.
      - Non-zero exit             -> the captured trace names the reason.
      - Timeout                   -> nanvixd hangs; the trace's last line shows
                                     how far the boot got, and the minidump
                                     shows where the threads are parked.

.PARAMETER BinDir
    Directory holding nanvixd.exe and its payload files.

.PARAMETER Mode
    Which boot path(s) to exercise: cold, warm, or both (default).

.PARAMETER TimeoutSeconds
    How long to wait before declaring a hang.

.PARAMETER OutputDirectory
    Where to keep collected artifacts. Defaults to
    `$env:RUNNER_TEMP\mxc-microvm-logs\nanvixd-probe`, which CI already uploads.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BinDir,

    [ValidateSet('cold', 'warm', 'both')]
    [string]$Mode = 'both',

    [int]$TimeoutSeconds = 120,

    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$binPath = (Resolve-Path -LiteralPath $BinDir).Path
$nanvixd = Join-Path $binPath 'nanvixd.exe'

Write-Host '=== Direct nanvixd probe ==='

if (-not (Test-Path -LiteralPath $nanvixd -PathType Leaf)) {
    Write-Host "nanvixd.exe not found at $nanvixd - skipping probe."
    exit 0
}

if (-not $OutputDirectory) {
    $OutputDirectory = if ($env:RUNNER_TEMP) {
        Join-Path $env:RUNNER_TEMP 'mxc-microvm-logs\nanvixd-probe'
    } else {
        Join-Path ([System.IO.Path]::GetTempPath()) "nanvixd-probe-$([guid]::NewGuid().ToString('N'))"
    }
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
Write-Host "Artifacts: $OutputDirectory"

# MiniDumpWriteDump lets a hung run be diagnosed after the fact: the boot trace
# says how far nanvixd got, the dump says where its threads are parked.
$dumpSignature = @'
using System;
using System.Runtime.InteropServices;

public static class MiniDump
{
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint ProcessId,
        IntPtr hFile,
        uint DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam);
}
'@

$dumpAvailable = $true
try {
    Add-Type -TypeDefinition $dumpSignature -ErrorAction Stop
} catch {
    $dumpAvailable = $false
    Write-Host "Minidump capture unavailable: $($_.Exception.Message)"
}

function Save-HungProcessDump {
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not $dumpAvailable) { return }

    try {
        # MiniDumpNormal (thread stacks) | MiniDumpWithThreadInfo. Deliberately
        # not WithFullMemory: nanvixd maps a 256 MB guest and the stacks are
        # what identify a hang.
        $dumpType = 0x00000000 -bor 0x00001000
        $stream = [System.IO.File]::Create($Path)
        try {
            $ok = [MiniDump]::MiniDumpWriteDump(
                $Process.Handle,
                [uint32]$Process.Id,
                $stream.SafeFileHandle.DangerousGetHandle(),
                $dumpType,
                [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        } finally {
            $stream.Dispose()
        }
        if ($ok) {
            $size = (Get-Item -LiteralPath $Path).Length
            Write-Host "  Minidump written: $Path ($size bytes)"
        } else {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "  Minidump failed (win32 error $code)"
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "  Minidump failed: $($_.Exception.Message)"
    }
}

function Show-CapturedFile {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Path
    )

    Write-Host ''
    Write-Host "--- $Label ---"
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host '(not captured)'
        return
    }
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) {
        Write-Host '(empty)'
        return
    }
    Write-Host $content.TrimEnd()
}

function Invoke-NanvixdBoot {
    param(
        [Parameter(Mandatory)][ValidateSet('cold', 'warm')][string]$BootMode
    )

    Write-Host ''
    Write-Host "=== $BootMode boot ==="

    $runDir = Join-Path $OutputDirectory $BootMode
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null

    $stdoutFile = Join-Path $runDir 'stdout.log'
    $stderrFile = Join-Path $runDir 'stderr.log'
    $consoleFile = Join-Path $runDir 'guest-console.log'

    # `-log-to-stdout` is essential: without it nanvixd logs to a file under
    # `-log-dir` and both stdout and stderr stay empty even on a healthy run,
    # which makes an empty capture indistinguishable from an early hang.
    $arguments = @(
        '-bin-dir', (Join-Path $binPath 'bin'),
        '-ramfs', (Join-Path $binPath 'nanvix_rootfs.img'),
        '-log-to-stdout',
        '-console-file', $consoleFile
    )

    if ($BootMode -eq 'cold') {
        # Mirrors nanvix_common::generate_snapshot. Runs in its own directory so
        # it never disturbs the artifact's shipped snapshots.
        $workingDirectory = Join-Path $runDir 'home'
        New-Item -ItemType Directory -Force -Path $workingDirectory | Out-Null
        $arguments += @('-kernel-args', 'snapshot')
    } else {
        # Mirrors nanvix_runner::spawn_nanvixd: cwd is the snapshot home and the
        # snapshot path is relative to it.
        $snapshot = Join-Path $binPath 'snapshots\kernel.whp.cbor'
        if (-not (Test-Path -LiteralPath $snapshot)) {
            Write-Host "No shipped snapshot at $snapshot - skipping warm boot."
            return
        }
        $workingDirectory = $binPath

        # The guest runs the bootstrap script from the mounted staging dir, so
        # stage one exactly as wxc_common::microvm_staging does. Without it
        # CPython would wait on stdin and look like a hang.
        $stagingDir = Join-Path $runDir 'staging'
        New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null
        @(
            'import sys'
            "sys.argv = ['/mnt/bootstrap.py']"
            "print('nanvixd-probe-ok')"
        ) -join "`n" | Set-Content -LiteralPath (Join-Path $stagingDir 'bootstrap.py') -Encoding ascii

        $arguments += @('-snapshot', 'snapshots\kernel.whp.cbor', '-mount', $stagingDir)
    }

    $arguments += @('--', (Join-Path $binPath 'python3.initrd'))

    Write-Host "Command: nanvixd.exe $($arguments -join ' ')"
    Write-Host "Working directory: $workingDirectory"
    Write-Host "Timeout: ${TimeoutSeconds}s"

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $nanvixd `
        -ArgumentList $arguments `
        -WorkingDirectory $workingDirectory `
        -PassThru `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile

    $hung = -not $process.WaitForExit($TimeoutSeconds * 1000)
    $stopwatch.Stop()

    if ($hung) {
        Write-Host "::warning::nanvixd did not exit within ${TimeoutSeconds}s - it HANGS on this host ($BootMode boot)."
        Save-HungProcessDump -Process $process -Path (Join-Path $runDir 'nanvixd-hang.dmp')
        try { $process.Kill($true) } catch { }
    } else {
        Write-Host "nanvixd exited with code $($process.ExitCode) after $($stopwatch.Elapsed.TotalSeconds.ToString('0.0'))s"
    }

    Show-CapturedFile -Label 'nanvixd stdout' -Path $stdoutFile
    Show-CapturedFile -Label 'nanvixd stderr (boot trace)' -Path $stderrFile
    Show-CapturedFile -Label 'guest console' -Path $consoleFile

    # Fallback for a nanvixd build that ignores -log-to-stdout.
    $logDir = Join-Path $workingDirectory 'logs'
    if (Test-Path -LiteralPath $logDir) {
        Write-Host ''
        Write-Host '--- nanvixd log directory ---'
        foreach ($file in Get-ChildItem -LiteralPath $logDir -File) {
            Write-Host "  $($file.Name) ($($file.Length) bytes)"
            Copy-Item -LiteralPath $file.FullName -Destination $runDir -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ''
    Write-Host '--- Generated snapshot files ---'
    $snapshotDir = Join-Path $workingDirectory 'snapshots'
    if (Test-Path -LiteralPath $snapshotDir) {
        Get-ChildItem -LiteralPath $snapshotDir | Format-Table Name, Length | Out-String | Write-Host
    } else {
        Write-Host '(no snapshots directory created)'
    }

    Write-Host ''
    if ($hung) {
        Write-Host "RESULT ($BootMode): nanvixd HANGS on this host - the fault is below MXC."
        Write-Host '        The last line of the boot trace above shows how far it got.'
    } elseif ($process.ExitCode -eq 0) {
        Write-Host "RESULT ($BootMode): nanvixd booted successfully."
    } else {
        Write-Host "RESULT ($BootMode): nanvixd failed - see the boot trace above for the reason."
    }
}

$modes = if ($Mode -eq 'both') { @('cold', 'warm') } else { @($Mode) }
foreach ($bootMode in $modes) {
    try {
        Invoke-NanvixdBoot -BootMode $bootMode
    } catch {
        Write-Host "::warning::$bootMode probe raised: $($_.Exception.Message)"
    }
}

# Diagnostic only: never fail the job on the probe's outcome.
exit 0
