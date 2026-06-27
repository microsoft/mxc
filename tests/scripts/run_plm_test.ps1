# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# PLM (Permissive Learning Mode) integration test runner.
#
# Runs every config under `tests/configs/plm_configs` through
# `wxc-exec.exe --audit`, locates the resulting `Adjusted_*.json` next to
# `plm.exe`, and emits the set of changes the adjusted config introduces
# relative to the input config.
#
# Each config drives `plmtester.exe` through a Win32 surface probe known
# to trip at least one permissive-learning-mode audit event. The expected
# outcome is that `wxc-exec --audit` produces a non-empty `Adjusted_*.json`
# with one or more of: filesystem paths, capabilities, `ui.disable=false`,
# or relaxed `ui.*` fields per `docs/base-process-container/UIPolicy_Schema.md`.
#
# Usage:
#   .\run_plm_test.ps1                 # debug build, all automatic plm_configs
#   .\run_plm_test.ps1 -Release        # release build
#   .\run_plm_test.ps1 -UI             # only ui_* tests
#   .\run_plm_test.ps1 -Fs             # only fs_* tests
#   .\run_plm_test.ps1 -Capability     # only cap_* tests (includes interactive)
#   .\run_plm_test.ps1 -UI -Fs         # combine: ui_* + fs_*
#   .\run_plm_test.ps1 -Config ui_clipboard_roundtrip
#   .\run_plm_test.ps1 -KeepLogs       # don't delete plm logs after summarizing

[CmdletBinding()]
param(
    [switch]$Release,
    [string]$BinDir,
    [string]$ConfigDir,
    [string[]]$Config,
    [switch]$UI,
    [switch]$Fs,
    [switch]$Capability,
    [switch]$KeepLogs,
    [int]$AuditTimeoutSec = 300
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# `wxc-exec --audit` invokes `plm` which starts an ETW WPR session;
# that requires the caller to be elevated. Fail fast with a clear
# message rather than letting wpr.exe emit a cryptic error.
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run_plm_test.ps1 must be run from an elevated (Administrator) shell." -ForegroundColor Red
    Write-Host "       PLM uses WPR/ETW which requires admin to start a trace session." -ForegroundColor Red
    exit 1
}

if (-not $BinDir) {
    $profile = if ($Release) { 'release' } else { 'debug' }
    $cwd = (Get-Location).Path
    $candidates = @(
        $cwd,
        (Join-Path $RepoRoot "src\target\x86_64-pc-windows-msvc\$profile"),
        (Join-Path $RepoRoot "src\target\$profile")
    )
    $BinDir = $candidates | Where-Object { Test-Path (Join-Path $_ 'wxc-exec.exe') } | Select-Object -First 1
    if (-not $BinDir) {
        Write-Host "ERROR: wxc-exec.exe not found under:" -ForegroundColor Red
        $candidates | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        Write-Host "Build with 'build.bat$(if ($Release) { ' --release' })' or pass -BinDir." -ForegroundColor Yellow
        exit 1
    }
}

$WxcExec = Join-Path $BinDir 'wxc-exec.exe'
$PlmExe  = Join-Path $BinDir 'plm.exe'
if (-not $ConfigDir) {
    $ConfigDir = Join-Path (Get-Location).Path 'plm_configs'
}

foreach ($exe in @($WxcExec, $PlmExe)) {
    if (-not (Test-Path $exe)) {
        Write-Host "ERROR: required binary missing: $exe" -ForegroundColor Red
        exit 1
    }
}
if (-not (Test-Path $ConfigDir)) {
    Write-Host "ERROR: plm_configs directory not found: $ConfigDir" -ForegroundColor Red
    exit 1
}

$configFiles = Get-ChildItem $ConfigDir -Filter *.json

# Tests with deterministic expected adjustments. Each entry pairs a
# config name (no extension) with the list of expected diff lines —
# substrings matched against the field-level changes emitted by
# Compare-JsonObjects. screenshot.json is intentionally excluded: it
# requires interactive picker input, so it can't run unattended.
$AutomaticTests = @(
    @{ Name = 'ui_clipboard_roundtrip';    Expect = @('ui.clipboard: "none" -> "all"') },
    @{ Name = 'ui_display_settings';       Expect = @('ui.systemSettings: "none" -> "display"') },
    @{ Name = 'ui_find_window';            Expect = @('ui.isolation: "handles" -> "desktop"') },
    @{ Name = 'ui_injection_child_window'; Expect = @('ui.injection: false -> true') },
    @{ Name = 'ui_system_param_set';       Expect = @('ui.systemSettings: "none" -> "parameters"') },
    @{
        # PLM filesystem promotion: the config pre-seeds
        # C:\Tessera\plm_fs_test\readonly in readonlyPaths and then the
        # workload writes a file into that directory. PLM should observe
        # the write and add the parent to readwritePaths so the policy
        # widens from read-only to read+write.
        Name   = 'fs_promoted'
        Setup  = {
            New-Item -ItemType Directory -Path 'C:\Tessera\plm_fs_test\readonly' -Force | Out-Null
        }
        Cleanup = {
            Remove-Item -Recurse -Force 'C:\Tessera\plm_fs_test' -ErrorAction SilentlyContinue
        }
        Expect = @(
            'filesystem.readwritePaths[] += "C:\\Tessera\\plm_fs_test\\readonly"'
        )
    },
    @{
        # PLM filesystem add (read-only): the config has no filesystem
        # section at all; the workload reads a file under
        # C:\Tessera\plm_fs_test\src\. PLM should add the file path to
        # readonlyPaths (read events emit the file, not the parent).
        Name   = 'fs_add_readonly'
        Setup  = {
            New-Item -ItemType Directory -Path 'C:\Tessera\plm_fs_test\src' -Force | Out-Null
            Set-Content -Path 'C:\Tessera\plm_fs_test\src\input.txt' -Value 'ro source' -NoNewline
        }
        Cleanup = {
            Remove-Item -Recurse -Force 'C:\Tessera\plm_fs_test' -ErrorAction SilentlyContinue
        }
        Expect = @(
            'filesystem.readonlyPaths[] += "C:\\Tessera\\plm_fs_test\\src'
        )
    },
    @{
        # PLM filesystem add (read+write): the config has no filesystem
        # section; the workload writes a new file under
        # C:\Tessera\plm_fs_test\dst\. PLM should add the parent
        # directory to readwritePaths (write events emit the parent).
        Name   = 'fs_add_readwrite'
        Setup  = {
            New-Item -ItemType Directory -Path 'C:\Tessera\plm_fs_test\dst' -Force | Out-Null
        }
        Cleanup = {
            Remove-Item -Recurse -Force 'C:\Tessera\plm_fs_test' -ErrorAction SilentlyContinue
        }
        Expect = @(
            'filesystem.readwritePaths[] += "C:\\Tessera\\plm_fs_test\\dst"'
        )
    },
    @{
        # Regression for the deny-list filter. The config pre-declares
        # C:\Tessera\plm_fs_test\denied in deniedPaths; the workload
        # tries to read a file there (which the container blocks). PLM
        # MUST NOT promote the denied path into
        # readonlyPaths/readwritePaths — Forbid asserts the absence of
        # any "denied" substring in the field-level diff.
        Name   = 'fs_denied_not_promoted'
        Setup  = {
            New-Item -ItemType Directory -Path 'C:\Tessera\plm_fs_test\denied' -Force | Out-Null
            Set-Content -Path 'C:\Tessera\plm_fs_test\denied\secret.txt' -Value 'sensitive' -NoNewline
        }
        Cleanup = {
            Remove-Item -Recurse -Force 'C:\Tessera\plm_fs_test' -ErrorAction SilentlyContinue
        }
        Expect = @()
        Forbid = @(
            'C:\\Tessera\\plm_fs_test\\denied'
        )
    }
)

# Tests that require human input (e.g. WinRT pickers). Only run when
# -Capability is passed.
$ManualTests = @(
    @{ Name = 'cap_screenshot'; Expect = @('processcontainer = {"capabilities":["graphicsCapture"]}') }
)

# Guard against orphan configs. Every JSON under plm_configs/ MUST be
# referenced by either $AutomaticTests or $ManualTests so it's
# exercised in CI. New fixtures that someone drops in but forgets to
# register fail fast here.
$registeredNames = @($AutomaticTests + $ManualTests | ForEach-Object { $_.Name })
$onDiskNames = $configFiles | ForEach-Object {
    [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
}
$orphans = @($onDiskNames | Where-Object { $_ -notin $registeredNames })
if ($orphans.Count -gt 0) {
    Write-Host "ERROR: plm_configs contains unreferenced configs (add to `$AutomaticTests or `$ManualTests in run_plm_test.ps1):" -ForegroundColor Red
    foreach ($o in $orphans) { Write-Host "  $o" -ForegroundColor Red }
    exit 1
}

if ($Config) {
    $wanted = $Config | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) }
    $configFiles = $configFiles | Where-Object {
        [System.IO.Path]::GetFileNameWithoutExtension($_.Name) -in $wanted
    }
    if (-not $configFiles) {
        Write-Host "ERROR: none of the requested -Config names matched: $($Config -join ', ')" -ForegroundColor Red
        Get-ChildItem $ConfigDir -Filter *.json | ForEach-Object {
            Write-Host "  available: $([System.IO.Path]::GetFileNameWithoutExtension($_.Name))" -ForegroundColor DarkGray
        }
        exit 1
    }
} else {
    $allEntries = $AutomaticTests + $ManualTests
    $categorySelected = ($UI -or $Fs -or $Capability)
    if ($categorySelected) {
        $prefixes = @()
        if ($UI)         { $prefixes += 'ui_' }
        if ($Fs)         { $prefixes += 'fs_' }
        if ($Capability) { $prefixes += 'cap_' }
        $autoNames = @($allEntries | ForEach-Object { $_.Name } | Where-Object {
            $name = $_
            $prefixes | Where-Object { $name.StartsWith($_) } | Select-Object -First 1
        })
    } else {
        # No category flag: run automatic tests only (skip manual /
        # interactive tests like cap_screenshot).
        $autoNames = @($AutomaticTests | ForEach-Object { $_.Name })
    }
    $configFiles = $configFiles | Where-Object {
        [System.IO.Path]::GetFileNameWithoutExtension($_.Name) -in $autoNames
    }
}

$LogsRoot = Join-Path $BinDir 'logs'

# Snapshot existing plm log dirs so we can identify the one created by
# each --audit run without depending on `wxc-exec` printing the path.
function Get-PlmLogDirs {
    if (Test-Path $LogsRoot) {
        Get-ChildItem $LogsRoot -Directory | Select-Object -ExpandProperty FullName
    } else {
        @()
    }
}

# Compare two JSON files and return a human-readable list of changed
# paths. Walks both trees in parallel; missing keys on either side are
# reported as add/remove. Array elements are compared as ordered sets.
function Compare-JsonObjects {
    param(
        [object]$Before,
        [object]$After,
        [string]$Path = ''
    )

    $changes = New-Object System.Collections.Generic.List[string]

    if ($null -eq $Before -and $null -eq $After) { return $changes }

    # One-sided cases: a whole subtree was added or removed. Recurse so
    # the caller sees per-leaf "+ path = value" / "[] += value" entries
    # instead of a single opaque "+ path = {...}" blob.
    if ($null -eq $Before) {
        if ($After -is [System.Management.Automation.PSCustomObject]) {
            foreach ($p in $After.PSObject.Properties) {
                $childPath = if ($Path) { "$Path.$($p.Name)" } else { $p.Name }
                $childChanges = @(Compare-JsonObjects -Before $null -After $p.Value -Path $childPath)
                if ($childChanges.Count -gt 0) { $changes.AddRange([string[]]$childChanges) }
            }
            return $changes
        }
        if ($After -is [System.Collections.IList]) {
            foreach ($el in $After) {
                $changes.Add(("  + {0}[] += {1}" -f $Path, (ConvertTo-Json $el -Compress -Depth 20)))
            }
            return $changes
        }
        $changes.Add(("  + {0} = {1}" -f $Path, (ConvertTo-Json $After -Compress -Depth 20)))
        return $changes
    }
    if ($null -eq $After) {
        if ($Before -is [System.Management.Automation.PSCustomObject]) {
            foreach ($p in $Before.PSObject.Properties) {
                $childPath = if ($Path) { "$Path.$($p.Name)" } else { $p.Name }
                $childChanges = @(Compare-JsonObjects -Before $p.Value -After $null -Path $childPath)
                if ($childChanges.Count -gt 0) { $changes.AddRange([string[]]$childChanges) }
            }
            return $changes
        }
        if ($Before -is [System.Collections.IList]) {
            foreach ($el in $Before) {
                $changes.Add(("  - {0}[] -= {1}" -f $Path, (ConvertTo-Json $el -Compress -Depth 20)))
            }
            return $changes
        }
        $changes.Add(("  - {0}" -f $Path))
        return $changes
    }

    if ($Before -is [System.Management.Automation.PSCustomObject] -and `
        $After  -is [System.Management.Automation.PSCustomObject]) {
        $keys = @($Before.PSObject.Properties.Name) + @($After.PSObject.Properties.Name) | Sort-Object -Unique
        foreach ($k in $keys) {
            $bv = $Before.PSObject.Properties[$k]
            $av = $After.PSObject.Properties[$k]
            $childPath = if ($Path) { "$Path.$k" } else { $k }
            if ($null -eq $bv) {
                # Recurse into newly-added subtrees so the diff emits
                # per-leaf "+= value" / "+ field = value" entries instead
                # of a single opaque "+ field = {...}" blob.
                $childChanges = @(Compare-JsonObjects -Before $null -After $av.Value -Path $childPath)
                if ($childChanges.Count -gt 0) { $changes.AddRange([string[]]$childChanges) }
            } elseif ($null -eq $av) {
                $childChanges = @(Compare-JsonObjects -Before $bv.Value -After $null -Path $childPath)
                if ($childChanges.Count -gt 0) { $changes.AddRange([string[]]$childChanges) }
            } else {
                $childChanges = @(Compare-JsonObjects -Before $bv.Value -After $av.Value -Path $childPath)
                if ($childChanges.Count -gt 0) { $changes.AddRange([string[]]$childChanges) }
            }
        }
        return $changes
    }

    if ($Before -is [System.Collections.IList] -and $After -is [System.Collections.IList]) {
        $beforeSet = @($Before | ForEach-Object { ConvertTo-Json $_ -Compress -Depth 20 })
        $afterSet  = @($After  | ForEach-Object { ConvertTo-Json $_ -Compress -Depth 20 })
        $added   = Compare-Object $beforeSet $afterSet | Where-Object SideIndicator -eq '=>' | Select-Object -ExpandProperty InputObject
        $removed = Compare-Object $beforeSet $afterSet | Where-Object SideIndicator -eq '<=' | Select-Object -ExpandProperty InputObject
        foreach ($a in $added)   { $changes.Add(("  + {0}[] += {1}" -f $Path, $a)) }
        foreach ($r in $removed) { $changes.Add(("  - {0}[] -= {1}" -f $Path, $r)) }
        return $changes
    }

    $bs = ConvertTo-Json $Before -Compress -Depth 20
    $as = ConvertTo-Json $After  -Compress -Depth 20
    if ($bs -ne $as) {
        $changes.Add(("  ~ {0}: {1} -> {2}" -f $Path, $bs, $as))
    }
    return $changes
}

function Format-JsonValue {
    param([object]$Value)
    return (ConvertTo-Json $Value -Compress -Depth 20)
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($cfg in $configFiles) {
    Write-Host ""
    Write-Host "=== $($cfg.Name) ===" -ForegroundColor Cyan

    $cfgStem = [System.IO.Path]::GetFileNameWithoutExtension($cfg.Name)
    $entry   = @($AutomaticTests + $ManualTests) | Where-Object { $_.Name -eq $cfgStem } | Select-Object -First 1
    if ($entry -and $entry.Setup) {
        try { & $entry.Setup } catch {
            Write-Host "  Setup failed: $_" -ForegroundColor Red
            continue
        }
    }

    $preDirs = Get-PlmLogDirs

    # Audit runs are permissive — workload failures still produce useful
    # trace output, so don't bail on non-zero exit. Suppress the per-run
    # banner so the script's own output stays scannable.
    #
    # Use Start-Process + manual WaitForExit + `taskkill /T /F /PID` so
    # a timeout kills the entire descendant tree (wxc-exec → plm.exe →
    # workload). The previous Start-Job approach only signalled the
    # job's PowerShell host; spawned native descendants survived and
    # raced the next test iteration.
    $stdoutFile = [IO.Path]::GetTempFileName()
    $stderrFile = [IO.Path]::GetTempFileName()
    try {
        $auditProc = Start-Process -FilePath $WxcExec `
            -ArgumentList @('--audit', $cfg.FullName) `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError  $stderrFile `
            -NoNewWindow -PassThru

        $timeoutMs = [int]($AuditTimeoutSec * 1000)
        if ($auditProc.WaitForExit($timeoutMs)) {
            $auditExit = $auditProc.ExitCode
        } else {
            # Hard kill the wxc-exec process *tree*. /T = tree, /F = force.
            & taskkill /T /F /PID $auditProc.Id 2>$null | Out-Null
            $auditProc.WaitForExit()
            $auditExit = -1
            # Best-effort: PLM's WPR session may have outlived the tree
            # kill if it was started before the descendants were nested
            # under the wxc-exec job object. cancel_active_audit_trace
            # in wxc-exec normally handles this on Ctrl-C; cover the
            # taskkill path explicitly here.
            #
            # Invoke wpr.exe via its absolute System32 path. The
            # unqualified `wpr.exe` form would resolve via $env:PATH
            # (which on Windows starts with the current directory for
            # child-process search), reintroducing the exact CWD-plant
            # elevation vulnerability that
            # `src/core/plm/src/wpr_path.rs` was built to prevent.
            # This script enforces Administrator above; a planted
            # `wpr.exe` next to a launcher cwd would run as admin.
            $wprExe = Join-Path ([Environment]::GetFolderPath('System')) 'wpr.exe'
            & $wprExe -cancel 2>$null | Out-Null
        }

        $stdoutText = if (Test-Path $stdoutFile) { Get-Content $stdoutFile -Raw } else { '' }
        $stderrText = if (Test-Path $stderrFile) { Get-Content $stderrFile -Raw } else { '' }
        if ($auditExit -eq -1) {
            $stdout = "ERROR: --audit timed out after ${AuditTimeoutSec}s; killed wxc-exec tree.`n$stdoutText`n$stderrText"
        } else {
            $stdout = "$stdoutText$stderrText"
        }
    } finally {
        Remove-Item $stdoutFile -ErrorAction SilentlyContinue
        Remove-Item $stderrFile -ErrorAction SilentlyContinue
    }

    # Find the new log dir created by this run.
    Start-Sleep -Milliseconds 100
    $postDirs = Get-PlmLogDirs
    $newDirs = @($postDirs | Where-Object { $_ -notin $preDirs })
    $logDir  = $newDirs | Sort-Object -Descending | Select-Object -First 1

    $adjustedPath = $null
    if ($logDir) {
        $adjustedPath = Get-ChildItem $logDir -Filter "Adjusted_*.json" -ErrorAction SilentlyContinue |
                        Select-Object -First 1 -ExpandProperty FullName
    }

    $status = 'unknown'
    $changes = @()
    $missingExpect = @()
    $expectEntry = $entry

    if (-not $logDir) {
        $status = 'no-trace'
        Write-Host "  (no plm log dir produced)" -ForegroundColor Yellow
    } elseif (-not $adjustedPath) {
        Write-Host "  log dir: $logDir" -ForegroundColor DarkGray
        Write-Host "  (no Adjusted_*.json — trace had no mergeable findings)" -ForegroundColor Yellow
        # A "no-adjusted" outcome IS a pass for entries that declare
        # no positive expectations (Expect=@()) — e.g. deny-list
        # fixtures asserting nothing got promoted. We only flag it as
        # a failure when the entry expected at least one observable
        # change.
        if ($expectEntry -and (-not $expectEntry.Expect -or $expectEntry.Expect.Count -eq 0)) {
            $status = 'pass'
            Write-Host "  (Expect=@(); no-adjusted satisfies the negative expectation)" -ForegroundColor Green
        } else {
            $status = 'no-adjusted'
        }
    } else {
        $before = Get-Content $cfg.FullName       -Raw | ConvertFrom-Json
        $after  = Get-Content $adjustedPath       -Raw | ConvertFrom-Json
        $changes = Compare-JsonObjects -Before $before -After $after

        Write-Host "  audit exit: $auditExit" -ForegroundColor DarkGray
        Write-Host "  adjusted:   $adjustedPath" -ForegroundColor DarkGray
        if ($changes.Count -eq 0) {
            Write-Host "  (no differences vs. input)" -ForegroundColor Yellow
        } else {
            Write-Host "  changes:" -ForegroundColor Green
            $changes | ForEach-Object { Write-Host $_ -ForegroundColor Green }
        }

        if ($expectEntry) {
            $joined = ($changes -join "`n")
            foreach ($needle in $expectEntry.Expect) {
                if ($joined -notmatch [regex]::Escape($needle)) {
                    $missingExpect += $needle
                }
            }
            # Negative expectations — assertions that particular
            # substrings MUST NOT appear in the diff (e.g., confirming
            # a deniedPaths entry is not promoted to readwritePaths).
            # $entry.Forbid is an optional string list.
            $forbiddenSeen = @()
            if ($expectEntry.PSObject.Properties.Name -contains 'Forbid' -and $expectEntry.Forbid) {
                foreach ($forbidden in $expectEntry.Forbid) {
                    if ($joined -match [regex]::Escape($forbidden)) {
                        $forbiddenSeen += $forbidden
                    }
                }
            }
            if ($missingExpect.Count -gt 0 -or $forbiddenSeen.Count -gt 0) {
                $status = 'missing-expected'
                if ($missingExpect.Count -gt 0) {
                    Write-Host "  EXPECTED but not observed:" -ForegroundColor Red
                    $missingExpect | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
                }
                if ($forbiddenSeen.Count -gt 0) {
                    Write-Host "  FORBIDDEN but observed:" -ForegroundColor Red
                    $forbiddenSeen | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
                }
            } else {
                $status = 'pass'
            }
        } else {
            $status = if ($changes.Count -gt 0) { 'changed' } else { 'no-changes' }
        }
    }

    $results.Add([pscustomobject]@{
        Config        = $cfg.Name
        Status        = $status
        AuditExit     = $auditExit
        LogDir        = $logDir
        AdjustedPath  = $adjustedPath
        ChangeCount   = $changes.Count
        Missing       = ($missingExpect -join '; ')
    }) | Out-Null

    if (-not $KeepLogs -and $logDir) {
        Remove-Item -Recurse -Force $logDir -ErrorAction SilentlyContinue
    }

    if ($entry -and $entry.Cleanup) {
        try { & $entry.Cleanup } catch {
            Write-Host "  Cleanup warning: $_" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize Config, Status, ChangeCount, AuditExit | Out-Host

# AuditExit reflects the workload's own exit code as returned by
# GetExitCodeProcess inside wxc-exec — it's NOT a harness pass/fail
# signal. Fixtures that intentionally hit denied paths (e.g.,
# fs_denied_not_promoted) commonly surface AuditExit=-1 because
# AppContainer terminates the redirected `type` command with
# 0xFFFFFFFF after the deny ACE fires. The test status is driven
# solely by the Expect/Forbid assertions above, so a non-zero (or
# -1) AuditExit on a `pass` row is expected and harmless.
Write-Host "(AuditExit is informational; non-zero values, including -1 from deny-path fixtures, are expected when the workload itself fails or is sandbox-terminated.)" -ForegroundColor DarkGray

$failed = $results | Where-Object { $_.Status -in @('no-trace', 'no-adjusted', 'missing-expected') }
if ($failed) {
    Write-Host "$($failed.Count) config(s) failed expectations — see above." -ForegroundColor Yellow
    exit 2
}
exit 0
