# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
End-to-end test for the captureDenials feature.

.DESCRIPTION
Runs wxc-exec against a config that
  - has captureDenials enabled,
  - denies all filesystem access by default,
  - asks the workload to read a path under the user profile.

Parses the NDJSON denial stream that wxc-exec writes to stderr
(0x1E-prefixed records, terminated by a "summary" envelope) and
asserts:
  1. At least one denial line was streamed.
  2. The trailing summary line is present and reports totalDenials >= 1.
  3. The expected target path (or its parent directory) appears in the
     streamed denial paths.
  4. Workload exit code is 0 (we tell `cmd` to swallow errors and exit
     0 so the denial capture, not the workload's exit, is what we
     verify).

Preconditions:
  - Running on Windows.
  - The MxcDenialShim service is installed and running. If not present,
    the script fails fast with an actionable message pointing at
    `wxc-host-prep install-denial-shim`.

.PARAMETER Release
Use the release build instead of debug.

.PARAMETER BinDir
Override the binary directory (defaults to src\target\{release,debug}).

.EXAMPLE
.\run_capture_denials_test.ps1 -Release
#>

param(
    [switch]$Release,
    [string]$BinDir,
    [string]$ConfigPath
)

$ErrorActionPreference = "Stop"

# When the script lives at <repo>\tests\scripts\, PSScriptRoot's
# grandparent is the repo root and we can locate config + bin
# relative to it. When the script is deployed standalone (e.g. to
# C:\mxc-test on a test VM), PSScriptRoot has no grandparent and we
# fall back to caller-supplied -BinDir / -ConfigPath.
$RepoRoot = ''
if ($PSScriptRoot) {
    $parent = Split-Path -Parent $PSScriptRoot
    if ($parent) {
        $grandparent = Split-Path -Parent $parent
        if ($grandparent) { $RepoRoot = $grandparent }
    }
}

if (-not $BinDir) {
    if (-not $RepoRoot) {
        Write-Host "ERROR: -BinDir is required when running outside the repo." -ForegroundColor Red
        exit 1
    }
    $sub = if ($Release) { 'release' } else { 'debug' }
    $BinDir = Join-Path $RepoRoot "src\target\$sub"
}

$WxcExec = Join-Path $BinDir "wxc-exec.exe"

if (-not $ConfigPath) {
    # Two layouts:
    #   - in-repo  : <repo>\tests\configs\capture_denials_e2e.json
    #   - deployed : <BinDir>\capture_denials_e2e.json (alongside the
    #     wxc-exec binary in a flat test directory like C:\mxc-test).
    $sideBySide = Join-Path $BinDir "capture_denials_e2e.json"
    $repoConfig = if ($RepoRoot) {
        Join-Path $RepoRoot "tests\configs\capture_denials_e2e.json"
    } else { '' }

    if ($repoConfig -and (Test-Path $repoConfig)) {
        $ConfigPath = $repoConfig
    } elseif (Test-Path $sideBySide) {
        $ConfigPath = $sideBySide
    } else {
        Write-Host "ERROR: capture_denials_e2e.json not found." -ForegroundColor Red
        if ($repoConfig) { Write-Host "  Tried: $repoConfig" -ForegroundColor Yellow }
        Write-Host "  Tried: $sideBySide" -ForegroundColor Yellow
        Write-Host "Pass -ConfigPath <path> to override." -ForegroundColor Yellow
        exit 1
    }
}
$TestConfig = $ConfigPath

# ---- Preconditions --------------------------------------------------------

if (-not (Test-Path $WxcExec)) {
    Write-Host "ERROR: wxc-exec.exe not found at $WxcExec" -ForegroundColor Red
    Write-Host "Run 'cargo build$(if ($Release) { ' --release' })' first." -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $TestConfig)) {
    Write-Host "ERROR: test config not found at $TestConfig" -ForegroundColor Red
    exit 1
}

$shim = Get-Service -Name 'MxcDenialShim' -ErrorAction SilentlyContinue
if (-not $shim) {
    Write-Host "ERROR: MxcDenialShim service is not installed." -ForegroundColor Red
    Write-Host "Install it with: wxc-host-prep install-denial-shim" -ForegroundColor Yellow
    Write-Host "(captureDenials requires the shim to be running as a service so" -ForegroundColor Yellow
    Write-Host " unelevated wxc-exec invocations can open ETW sessions.)" -ForegroundColor Yellow
    exit 2
}
if ($shim.Status -ne 'Running') {
    Write-Host "ERROR: MxcDenialShim service exists but is not Running (Status=$($shim.Status))." -ForegroundColor Red
    Write-Host "Start it with: Start-Service MxcDenialShim" -ForegroundColor Yellow
    exit 2
}

Write-Host "[capture-denials-e2e] wxc-exec : $WxcExec" -ForegroundColor Cyan
Write-Host "[capture-denials-e2e] config   : $TestConfig" -ForegroundColor Cyan
Write-Host "[capture-denials-e2e] shim     : Running" -ForegroundColor Cyan

# ---- Run wxc-exec, capture stdout + stderr separately ---------------------

$tmpStdout = [System.IO.Path]::GetTempFileName()
$tmpStderr = [System.IO.Path]::GetTempFileName()
try {
    $proc = Start-Process -FilePath $WxcExec `
                          -ArgumentList @('--config', $TestConfig) `
                          -NoNewWindow -Wait -PassThru `
                          -RedirectStandardOutput $tmpStdout `
                          -RedirectStandardError  $tmpStderr
    $exit = $proc.ExitCode

    Write-Host "[capture-denials-e2e] exit code: $exit" -ForegroundColor Cyan

    # ---- Parse the NDJSON stream from stderr ------------------------------
    #
    # Wire format: each MXC envelope is `\x1e<json>\n`. We split the raw
    # bytes on 0x1E and parse each non-empty segment as JSON. Anything
    # that doesn't parse as JSON (or that appears before the first 0x1E)
    # is workload-side passthrough - we keep it for diagnostics but
    # don't assert on it.

    $bytes = [System.IO.File]::ReadAllBytes($tmpStderr)
    if ($bytes.Length -eq 0) {
        Write-Host "FAIL: stderr is empty; expected at least one denial envelope + a summary line." -ForegroundColor Red
        exit 1
    }
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    $segments = $text -split ([char]0x1E)

    $denials   = @()
    $summary   = $null
    $passSegs  = @()

    foreach ($seg in $segments) {
        if ([string]::IsNullOrWhiteSpace($seg)) { continue }
        $trimmed = $seg.TrimEnd("`r", "`n")
        try {
            $obj = $trimmed | ConvertFrom-Json -ErrorAction Stop
            if ($obj.type -eq 'denial') {
                $denials += $obj
            } elseif ($obj.type -eq 'summary') {
                $summary = $obj
            } else {
                $passSegs += $trimmed
            }
        } catch {
            # Not JSON => workload-side passthrough (or wxc-exec's own
            # plaintext stderr like a fallback warning). Keep for diag.
            $passSegs += $trimmed
        }
    }

    Write-Host "[capture-denials-e2e] streamed denial lines : $($denials.Count)" -ForegroundColor Cyan
    Write-Host "[capture-denials-e2e] summary observed      : $($null -ne $summary)" -ForegroundColor Cyan
    Write-Host "[capture-denials-e2e] non-MXC stderr lines  : $($passSegs.Count)" -ForegroundColor Cyan

    # ---- Assertions -------------------------------------------------------

    $failures = @()

    # The workload swallows the failed `type` via `2>&1 & exit 0`, so we
    # expect exit 0 from wxc-exec. A non-zero exit means the runner
    # itself failed (e.g. the shim wasn't reachable), which is a hard
    # failure for this test.
    if ($exit -ne 0) {
        $failures += "wxc-exec exit code was $exit (expected 0)"
    }

    if ($null -eq $summary) {
        $failures += "no summary line observed at end of stream"
    } else {
        if (-not ($summary.PSObject.Properties.Name -contains 'totalDenials')) {
            $failures += "summary line is missing 'totalDenials' field"
        }
        if (-not ($summary.PSObject.Properties.Name -contains 'exitCode')) {
            $failures += "summary line is missing 'exitCode' field"
        }
        if (-not ($summary.PSObject.Properties.Name -contains 'deniedResourcesTruncated')) {
            $failures += "summary line is missing 'deniedResourcesTruncated' field"
        }
        if ($summary.totalDenials -lt 1) {
            $failures += "summary.totalDenials is $($summary.totalDenials); expected >= 1"
        }
        if ($summary.totalDenials -ne $denials.Count) {
            $failures += "summary.totalDenials ($($summary.totalDenials)) does not match streamed denial count ($($denials.Count)) - dedupe semantics broken"
        }
    }

    if ($denials.Count -lt 1) {
        $failures += "no denial envelopes streamed; expected >= 1 for a deny-everything policy"
    } else {
        # Every denial envelope must carry the required wire-format fields.
        foreach ($d in $denials) {
            foreach ($req in @('path', 'resourceType', 'accessType', 'pid', 'filetime')) {
                if (-not ($d.PSObject.Properties.Name -contains $req)) {
                    $failures += "denial envelope missing required field '$req': $($d | ConvertTo-Json -Compress)"
                }
            }
        }

        # The workload tries to read C:\Users\AdminUser\Documents\CaptureDenialsTest_E2E.txt.
        # Because the kernel denies the first parent it can't traverse,
        # we accept *any* path under \??\C:\Users\ or C:\Users\ as proof
        # that the workload's access attempt actually surfaced.
        $targetMatched = $denials | Where-Object {
            $_.path -match '\\Users\\' -or $_.path -match '^\\\?\?\\C:\\Users\\'
        }
        if (-not $targetMatched) {
            $failures += "expected at least one denial path under \Users\ (the workload's parent dir); got: $(($denials | ForEach-Object { $_.path }) -join ', ')"
        }
    }

    if ($failures.Count -gt 0) {
        Write-Host "FAILED:" -ForegroundColor Red
        foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
        Write-Host "--- captured stderr (first 2KB) ---" -ForegroundColor DarkGray
        Write-Host ($text.Substring(0, [Math]::Min(2048, $text.Length))) -ForegroundColor DarkGray
        exit 1
    }

    Write-Host "PASSED: captureDenials end-to-end test" -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmpStdout, $tmpStderr
}
