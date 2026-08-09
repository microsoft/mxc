<#
.SYNOPSIS
    Runs nanvixd directly to isolate MicroVM boot failures from MXC.

.DESCRIPTION
    MicroVM tests can hang or time out without revealing whether the fault is
    in nanvixd (the VM monitor) or in how wxc-exec invokes it. This probe skips
    MXC entirely and cold-boots nanvixd itself, bounded by a timeout so it can
    never hang a job.

    Diagnostic only: always exits 0 so it reports findings without failing the
    lane. Interpretation:

      - Snapshot files produced   -> nanvixd works; suspect MXC's invocation.
      - Non-zero exit with stderr -> nanvixd fails; stderr names the reason.
      - Timeout, no output        -> nanvixd hangs on this host (e.g. WHP
                                     partition creation never returns).

.PARAMETER BinDir
    Directory holding nanvixd.exe and its payload files.

.PARAMETER TimeoutSeconds
    How long to wait before declaring a hang.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BinDir,

    [int]$TimeoutSeconds = 120
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

# Generate into a scratch directory so the probe never disturbs the artifact's
# own snapshots, which the real tests rely on.
$probeHome = Join-Path ([System.IO.Path]::GetTempPath()) "nanvixd-probe-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $probeHome | Out-Null

$stdoutFile = Join-Path $probeHome 'stdout.log'
$stderrFile = Join-Path $probeHome 'stderr.log'

# Mirrors nanvix_common::generate_snapshot: cold boot with -kernel-args snapshot.
$arguments = @(
    '-bin-dir', (Join-Path $binPath 'bin'),
    '-ramfs', (Join-Path $binPath 'nanvix_rootfs.img'),
    '-kernel-args', 'snapshot',
    '--', (Join-Path $binPath 'python3.initrd')
)

Write-Host "Command: nanvixd.exe $($arguments -join ' ')"
Write-Host "Working directory: $probeHome"
Write-Host "Timeout: ${TimeoutSeconds}s"
Write-Host ''

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
# RUST_LOG surfaces nanvixd's tracing, which the MXC runner suppresses by
# default - that suppression is why earlier hangs produced no diagnostics.
$previousRustLog = $env:RUST_LOG
$env:RUST_LOG = 'debug'
try {
    $process = Start-Process -FilePath $nanvixd `
        -ArgumentList $arguments `
        -WorkingDirectory $probeHome `
        -PassThru `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile
} finally {
    $env:RUST_LOG = $previousRustLog
}

if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    $stopwatch.Stop()
    Write-Host "::warning::nanvixd did not exit within ${TimeoutSeconds}s - it HANGS on this host."
    try { $process.Kill($true) } catch { }
    $hung = $true
} else {
    $stopwatch.Stop()
    $hung = $false
    Write-Host "nanvixd exited with code $($process.ExitCode) after $($stopwatch.Elapsed.TotalSeconds.ToString('0.0'))s"
}

foreach ($stream in @(@{ Name = 'stdout'; Path = $stdoutFile }, @{ Name = 'stderr'; Path = $stderrFile })) {
    Write-Host ''
    Write-Host "--- nanvixd $($stream.Name) ---"
    if (Test-Path -LiteralPath $stream.Path) {
        $content = Get-Content -LiteralPath $stream.Path -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Host '(empty)'
        } else {
            Write-Host $content.TrimEnd()
        }
    } else {
        Write-Host '(not captured)'
    }
}

Write-Host ''
Write-Host '--- Generated snapshot files ---'
$snapshotDir = Join-Path $probeHome 'snapshots'
if (Test-Path -LiteralPath $snapshotDir) {
    Get-ChildItem -LiteralPath $snapshotDir | Format-Table Name, Length | Out-String | Write-Host
} else {
    Write-Host '(no snapshots directory created)'
}

Write-Host ''
if ($hung) {
    Write-Host 'RESULT: nanvixd hangs on this host - the fault is below MXC.'
} elseif ($process.ExitCode -eq 0) {
    Write-Host 'RESULT: nanvixd cold-booted successfully - suspect MXC''s invocation instead.'
} else {
    Write-Host 'RESULT: nanvixd failed - see its stderr above for the reason.'
}

Remove-Item -LiteralPath $probeHome -Recurse -Force -ErrorAction SilentlyContinue

# Diagnostic only: never fail the job on the probe's outcome.
exit 0
