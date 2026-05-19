#requires -Version 5.1
<#
.SYNOPSIS
    Runs the MXC isolation-session integration test suites from a package
    produced by Build-MxcIsolationSessionPackage.ps1. Emits per-test results
    to the console plus standard JUnit XML, JSON, and TAP files for CI
    consumption.

.DESCRIPTION
    Designed to run "out of the box" on a clean Windows 11 install with a
    workable OS build (one that supports the in-proc
    Windows.AI.IsolationSession IsoSessionOps APIs). The only prerequisite
    this script will install is Node.js 22 LTS (needed for the Node-based
    E2E suite); MSVC, Rust, and Git are not needed on the target.

    The two scripts are decoupled: this script's only contract with the
    producer is the zip shape, described in manifest.json at the zip root.
    The script validates manifest.json's format_version before touching any
    other content.

    Test suites run serially (one-shot, state-aware, Node E2E) and skip with
    clear messages if the host lacks the OS prerequisites
    (IsoSessionApp.dll, the WinRT IsoSessionOps registration, or a build
    with the isolation_session feature). The script does NOT attempt to
    enable velocity keys or feature flags.

.PARAMETER PackagePath
    Path to the .zip produced by Build-MxcIsolationSessionPackage.ps1.
    If omitted, the script searches the directory containing this .ps1 for
    a file matching "mxc-iso-test-package*.zip" and uses the newest match.
    Pass an explicit path to override the auto-discovery.

.PARAMETER ExtractPath
    Directory to extract the package into. The directory is created (and
    overwritten if it already exists). Default:
    "<SystemDrive>\mxc-iso-tests-<timestamp>" where SystemDrive resolves to
    the OS install drive (usually C: but not always). Pass an explicit value
    to extract onto a different drive or under a fixed name.

.PARAMETER ResultsPath
    Directory to write results.junit.xml, results.json, and results.tap.
    Default: the extraction directory.

.PARAMETER Unattended
    Auto-approve prerequisite install prompts.

.EXAMPLE
    .\Invoke-MxcIsolationSessionTests.ps1 -PackagePath .\mxc-iso-test-package-260518-131454.zip

.EXAMPLE
    .\Invoke-MxcIsolationSessionTests.ps1 -PackagePath C:\artifacts\mxc.zip -ExtractPath D:\test-staging -ResultsPath D:\test-results -Unattended
#>

[CmdletBinding()]
param(
    [string]$PackagePath,
    [string]$ExtractPath,
    [string]$ResultsPath,
    [switch]$Unattended
)

$ErrorActionPreference = 'Stop'

# Make PowerShell's view of stdout/stderr UTF-8 so any text we pipe from
# children (node, the PS1 runners) is read with the right encoding. The
# cmd-host codepage that determines on-screen rendering of child output
# is owned by the Run-Tests.cmd wrapper (which sets chcp 65001 before
# invoking PowerShell). Setting it here too is belt-and-suspenders for
# users who invoke the .ps1 directly.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# ============================================================================
# Constants
# ============================================================================

$Script:FormatVersion = 1
$Script:RequiredNodeMajor = 22

# Phase tracking. Same pattern as the producer: each main-flow stage updates
# $Script:CurrentPhase, and on any thrown exception the failure summary
# uses it for a phase-specific hint and a stable per-phase exit code.
$Script:CurrentPhase = 'init'

$Script:PhaseExitCodes = @{
    'init'             = 1
    'validate-package' = 30
    'prereq-probe'     = 10
    'prereq-install'   = 20
    'extract'          = 40
    'run'              = 50
    'emit'             = 60
}

$Script:PhaseHints = @{
    'init'             = ''
    'validate-package' = 'No package was supplied or located, or the package is missing a valid manifest.json. Pass -PackagePath explicitly, or place a "mxc-iso-test-package*.zip" next to this script for auto-discover. The package must be produced by Build-MxcIsolationSessionPackage.ps1 (format_version=1).'
    'prereq-probe'     = 'Prereq probes are not expected to throw. This is likely a script bug; please report it.'
    'prereq-install'   = 'Check internet connectivity, run "winget source update", or install Node.js 22 LTS manually and re-run this script.'
    'extract'          = 'Likely cause: disk full, destination path locked, or insufficient permissions. Try a writable location via -ExtractPath (default: <SystemDrive>\mxc-iso-tests-<timestamp>).'
    'run'              = 'A test suite invocation threw before it produced any result. Inspect the per-suite log files under the extraction directory.'
    'emit'             = 'Could not write results.junit.xml / results.json / results.tap. Check that -ResultsPath is writable.'
}

# ============================================================================
# Output helpers
# ============================================================================

function Write-Stage {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Message)
    Write-Host "  -> $Message" -ForegroundColor Gray
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  OK $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  ! $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "  X $Message" -ForegroundColor Red
}

# Emit the ANSI reset sequence (ESC [ 0 m) to clear any color state left
# in the host console by a child process or by Write-Host -ForegroundColor.
# Without this, an unsuccessful runner can leave the user's prompt stuck
# on a non-default color after the script exits.
function Reset-ConsoleColor {
    try { [Console]::Write([char]27 + '[0m') } catch { }
}

# Resolve the package path: explicit -PackagePath wins; otherwise look for
# mxc-iso-test-package*.zip next to this script and use the newest match.
function Resolve-PackagePath {
    param([string]$Provided)
    if ($Provided) {
        if (-not (Test-Path $Provided)) {
            throw "Package not found at -PackagePath: $Provided"
        }
        return (Resolve-Path $Provided).Path
    }
    $searchDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $candidates = @(Get-ChildItem -Path $searchDir -Filter 'mxc-iso-test-package*.zip' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    if ($candidates.Count -eq 0) {
        throw "No -PackagePath supplied and no mxc-iso-test-package*.zip found in $searchDir. Place the package zip next to this script or pass -PackagePath explicitly."
    }
    if ($candidates.Count -gt 1) {
        Write-Warn "Multiple package zips found in $searchDir; using newest: $($candidates[0].Name)"
    }
    Write-Step "Auto-discovered package: $($candidates[0].FullName)"
    return $candidates[0].FullName
}

function Confirm-Action {
    param([string]$Prompt)
    if ($Unattended) {
        Write-Host "$Prompt [Y/n] Y (unattended)" -ForegroundColor DarkGray
        return $true
    }
    Write-Host "$Prompt [Y/n] " -NoNewline
    $resp = Read-Host
    return ([string]::IsNullOrWhiteSpace($resp) -or $resp -match '^[Yy]')
}

function Write-FailureSummary {
    param([string]$Reason, [TimeSpan]$Elapsed, [string]$Stack)
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "Test run FAILED" -ForegroundColor Red
    Write-Host "  Phase:    $Script:CurrentPhase"
    Write-Host "  Reason:   $Reason"
    $hint = $Script:PhaseHints[$Script:CurrentPhase]
    if ($hint) { Write-Host "  Hint:     $hint" }
    Write-Host "  Elapsed:  $($Elapsed.ToString('hh\:mm\:ss'))"
    if ($Stack) {
        Write-Host "  Stack:" -ForegroundColor DarkGray
        foreach ($line in ($Stack -split "`r?`n")) {
            if ($line) { Write-Host "    $line" -ForegroundColor DarkGray }
        }
    }
    Write-Host "============================================" -ForegroundColor Red
    Write-Host ""
}

function Get-PhaseExitCode {
    $code = $Script:PhaseExitCodes[$Script:CurrentPhase]
    if (-not $code) { return 1 }
    return $code
}

# ============================================================================
# Environment helpers
# ============================================================================

function Test-Command {
    param([string]$Name)
    return ($null -ne (Get-Command $Name -ErrorAction SilentlyContinue))
}

function Update-PathFromRegistry {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $combined = @()
    if ($machine) { $combined += $machine }
    if ($user) { $combined += $user }
    $env:Path = ($combined -join ';')
}

function Test-WingetAvailable {
    return (Test-Command 'winget')
}

# ============================================================================
# Phase: validate package (read manifest WITHOUT full extraction)
# ============================================================================

function Read-PackageManifest {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Package not found: $Path"
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $Path).Path)
    try {
        $entry = $zip.Entries | Where-Object { $_.FullName -eq 'manifest.json' } | Select-Object -First 1
        if (-not $entry) {
            throw "Package is missing manifest.json at the zip root (not a valid MXC isolation-session test package)."
        }
        $stream = $entry.Open()
        try {
            $reader = New-Object System.IO.StreamReader($stream)
            try { return ($reader.ReadToEnd() | ConvertFrom-Json) } finally { $reader.Close() }
        } finally { $stream.Close() }
    } finally { $zip.Dispose() }
}

function Test-ManifestCompatible {
    param($Manifest)
    if (-not $Manifest.format_version) {
        throw 'manifest.json has no format_version field; package is malformed.'
    }
    if ($Manifest.format_version -ne $Script:FormatVersion) {
        throw "Package format_version is $($Manifest.format_version); this consumer supports format_version $($Script:FormatVersion). Rebuild the package or use a matching consumer."
    }
}

# ============================================================================
# Phase: prereq probe / install (Node 22+ only)
# ============================================================================

function Test-NodeInstalled {
    if (-not (Test-Command 'node')) { return $false }
    try {
        $output = & node --version 2>$null
        if ($output -match '^v(\d+)\.') {
            return ([int]$Matches[1] -ge $Script:RequiredNodeMajor)
        }
    } catch { }
    return $false
}

function Install-Node {
    if (-not (Confirm-Action "About to install Node.js $($Script:RequiredNodeMajor) LTS via winget. Proceed?")) {
        throw 'Node install declined. Cannot run the Node-based E2E suite without Node.'
    }
    Write-Step "Installing Node.js $($Script:RequiredNodeMajor) LTS via winget..."
    & winget install --id OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { throw "winget install OpenJS.NodeJS.LTS failed with exit $LASTEXITCODE" }
    Update-PathFromRegistry
}

function Invoke-PrereqProbe {
    Write-Stage 'Probing prerequisites'
    $nodeOk = Test-NodeInstalled
    if ($nodeOk) { Write-Ok "Node $($Script:RequiredNodeMajor)+: present" } else { Write-Warn "Node $($Script:RequiredNodeMajor)+: missing" }
    return @{ Node = $nodeOk }
}

function Invoke-PrereqInstall {
    param([hashtable]$State)
    if ($State.Node) {
        Write-Step 'All prerequisites are present; install phase skipped.'
        return
    }
    Write-Stage 'Installing missing prerequisites: Node'
    if (-not (Test-WingetAvailable)) {
        throw 'winget is not available on this machine. Install App Installer from the Microsoft Store (or install Node.js 22 LTS manually), then re-run this script.'
    }
    Install-Node
    if (-not (Test-NodeInstalled)) {
        throw 'Node is still missing after install. The current console may need to be reopened for PATH updates to take effect; try re-running this script in a new shell.'
    }
    Write-Ok 'Node installed and detected.'
}

# ============================================================================
# Phase: extract
# ============================================================================

function Invoke-Extract {
    param([string]$Path, [string]$Destination)
    Write-Stage 'Extracting package'
    # $env:SystemDrive is "C:" on most installs but follows the OS install
    # drive, so it works on machines where the user has staged Windows on
    # D:\ / E:\ / etc. The caller can override entirely via -ExtractPath.
    if (-not $Destination) {
        $stamp = (Get-Date).ToString('yyMMdd-HHmmss')
        $Destination = Join-Path "$env:SystemDrive\" "mxc-iso-tests-$stamp"
    }
    Write-Step "Destination: $Destination"
    Expand-Archive -Path $Path -DestinationPath $Destination -Force
    if (-not (Test-Path (Join-Path $Destination 'manifest.json'))) {
        throw "Extraction did not produce manifest.json at $Destination (zip may be corrupted)."
    }
    Write-Ok "Extracted to $Destination"
    return $Destination
}

# ============================================================================
# Architecture detection
# ============================================================================

function Get-HostArch {
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { return 'arm64' }
    return 'x64'
}

# ============================================================================
# Phase: run suites (live tee + capture)
# ============================================================================

# Invoke a child process, stream its stdout/stderr to our console as each
# line arrives, AND capture every line to a string array for downstream
# parsing. Returns @{ ExitCode = N; Lines = @(...) }.
#
# Using ForEach-Object over an `&` pipeline gives us live-tee behavior:
# each line is written via Write-Host (so the user sees test progress in
# real time) AND added to a collector for post-hoc parsing. Without the
# ForEach-Object, captured output is buffered until the child exits.
function Invoke-WithLiveTee {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$LogPath
    )
    $collector = New-Object System.Collections.ArrayList
    & $FilePath @ArgumentList 2>&1 | ForEach-Object {
        $line = [string]$_
        Write-Host $line
        [void]$collector.Add($line)
    }
    $exitCode = $LASTEXITCODE
    if ($LogPath) {
        Set-Content -Path $LogPath -Value $collector -Encoding UTF8
    }
    return @{ ExitCode = $exitCode; Lines = $collector }
}

# Invokes a PowerShell script in a child process, capturing/streaming output.
function Invoke-PsRunner {
    param(
        [string]$RunnerPath,
        [string[]]$Arguments,
        [string]$LogPath
    )
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $RunnerPath) + $Arguments
    return Invoke-WithLiveTee -FilePath 'powershell.exe' -ArgumentList $args -LogPath $LogPath
}

# ============================================================================
# Result model + parsers
# ============================================================================

# A test record. Status is one of 'passed', 'failed', 'skipped'.
function New-TestRecord {
    param(
        [string]$Suite,
        [string]$Name,
        [string]$Status,
        [double]$DurationMs = 0.0,
        [string]$Reason = ''
    )
    return [pscustomobject]@{
        Suite      = $Suite
        Name       = $Name
        Status     = $Status
        DurationMs = $DurationMs
        Reason     = $Reason
    }
}

# Synthesize a single record representing a suite-level skip. Used when the
# runner exited early with a top-level "SKIPPED: ..." (e.g., OS doesn't
# support the APIs) so there is no per-test breakdown to parse.
function New-SuiteSkipRecord {
    param([string]$Suite, [string]$Reason)
    return New-TestRecord -Suite $Suite -Name '__suite__' -Status 'skipped' -Reason $Reason
}

# Parse run_isolation_session_tests.ps1 output. The runner uses:
#   - "  <config>.json ... PASS|FAIL|SKIP[ (<reason>)]"
#   - "      Reason: <text>" (after FAIL)
#   - "  concurrent: <label> ran full sequence ... PASS|FAIL: <reasons>"
#   - Summary: "<N>/<M> passed[, <K> FAILED[ (<S> skipped)]]:"
#       followed by "  FAIL: <name> - <reason>" lines
#   - Top-level "SKIPPED: <reason>" means the entire suite skipped.
function Parse-OneShotOutput {
    param([string[]]$Lines, [string]$SuiteName)
    $records = New-Object System.Collections.ArrayList

    # Top-level SKIPPED (OS-prereq probe failed in the runner).
    foreach ($line in $Lines) {
        if ($line -match '^SKIPPED:\s*(.+)$') {
            [void]$records.Add((New-SuiteSkipRecord -Suite $SuiteName -Reason $Matches[1].Trim()))
            return $records
        }
    }

    # Per-test markers in the body.
    $perTest = @{}  # name -> status
    $lastFailName = $null
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if ($line -match '^\s{2}(\S+\.json)\s+\.\.\.\s+(PASS|FAIL|SKIP)') {
            $name = $Matches[1]
            $status = switch ($Matches[2]) {
                'PASS' { 'passed' }
                'FAIL' { 'failed' }
                'SKIP' { 'skipped' }
            }
            $perTest[$name] = @{ Status = $status; Reason = '' }
            $lastFailName = if ($status -eq 'failed') { $name } else { $null }
        }
        elseif ($line -match '^\s{2}concurrent:\s+(.+?)\s+\.\.\.\s+(PASS|FAIL)') {
            $name = "concurrent: $($Matches[1])"
            $status = if ($Matches[2] -eq 'PASS') { 'passed' } else { 'failed' }
            $reason = ''
            if ($status -eq 'failed' -and $line -match '^\s{2}concurrent:.+\.\.\.\s+FAIL:\s*(.+)$') {
                $reason = $Matches[1].Trim()
            }
            $perTest[$name] = @{ Status = $status; Reason = $reason }
        }
        elseif ($line -match '^\s{4}Reason:\s*(.+)$' -and $lastFailName) {
            $perTest[$lastFailName].Reason = $Matches[1].Trim()
            $lastFailName = $null
        }
    }

    foreach ($name in $perTest.Keys) {
        $entry = $perTest[$name]
        [void]$records.Add((New-TestRecord -Suite $SuiteName -Name $name -Status $entry.Status -Reason $entry.Reason))
    }
    return $records
}

# Parse run_isolation_session_state_aware_tests.ps1 output. The runner uses:
#   - "[<test_name>]" as a section header (one per logical test)
#   - "  PASS: <message>" / "  FAIL: <message>" per-assertion
#   - Summary "<N>/<M> passed[, <K> FAILED:]" followed by
#       "  FAIL: <name> - <reason>" lines
#   - Top-level "SKIPPED: <reason>"
#
# We treat each "[<test_name>]" as one logical test; status is failed if any
# assertion in its scope was FAIL, otherwise passed.
function Parse-StateAwareOutput {
    param([string[]]$Lines, [string]$SuiteName)
    $records = New-Object System.Collections.ArrayList

    foreach ($line in $Lines) {
        if ($line -match '^SKIPPED:\s*(.+)$') {
            [void]$records.Add((New-SuiteSkipRecord -Suite $SuiteName -Reason $Matches[1].Trim()))
            return $records
        }
    }

    # First pass: collect test names + their pass/fail (first FAIL message wins).
    $orderedNames = New-Object System.Collections.ArrayList
    $perTest = @{}
    $current = $null
    foreach ($line in $Lines) {
        if ($line -match '^\[([^\]]+)\]\s*$') {
            $current = $Matches[1].Trim()
            if (-not $perTest.ContainsKey($current)) {
                [void]$orderedNames.Add($current)
                $perTest[$current] = @{ Status = 'passed'; Reason = '' }
            }
        }
        elseif ($current -and $line -match '^\s{2}FAIL:\s*(.+)$') {
            if ($perTest[$current].Status -ne 'failed') {
                $perTest[$current].Status = 'failed'
                $perTest[$current].Reason = $Matches[1].Trim()
            }
        }
    }

    foreach ($name in $orderedNames) {
        $entry = $perTest[$name]
        [void]$records.Add((New-TestRecord -Suite $SuiteName -Name $name -Status $entry.Status -Reason $entry.Reason))
    }
    return $records
}

# Parse a Node JUnit XML file produced by `node --test --test-reporter=junit`.
# The reporter emits a <testsuites> root with one or more <testsuite>, each
# containing <testcase> children. <failure> / <skipped> children mark
# non-passing cases.
function Parse-JunitFile {
    param([string]$XmlPath, [string]$SuiteName)
    $records = New-Object System.Collections.ArrayList
    if (-not (Test-Path $XmlPath)) {
        Write-Warn "Node JUnit output not found at $XmlPath; suite produced no parseable results."
        return $records
    }
    [xml]$doc = Get-Content $XmlPath -Raw
    $cases = $doc.SelectNodes('//testcase')
    foreach ($case in $cases) {
        $name = $case.GetAttribute('name')
        $classname = $case.GetAttribute('classname')
        $time = 0.0
        $timeAttr = $case.GetAttribute('time')
        if ($timeAttr) { [double]::TryParse($timeAttr, [ref]$time) | Out-Null }
        $displayName = if ($classname) { "$classname > $name" } else { $name }
        $status = 'passed'
        $reason = ''
        $failure = $case.SelectSingleNode('failure')
        $skipped = $case.SelectSingleNode('skipped')
        if ($failure) {
            $status = 'failed'
            $reason = if ($failure.GetAttribute('message')) { $failure.GetAttribute('message') } else { $failure.InnerText.Trim() }
        } elseif ($skipped) {
            $status = 'skipped'
            $reason = if ($skipped.GetAttribute('message')) { $skipped.GetAttribute('message') } else { $skipped.InnerText.Trim() }
        }
        [void]$records.Add((New-TestRecord -Suite $SuiteName -Name $displayName -Status $status -DurationMs ($time * 1000) -Reason $reason))
    }
    return $records
}

# ============================================================================
# Suite invocation
# ============================================================================

function Invoke-OneShotSuite {
    param([string]$ExtractDir, [string]$Arch, [string]$LogDir)
    Write-Stage 'Suite 1/3: isolation-session one-shot'
    $wxc = Join-Path $ExtractDir "bin\$Arch\wxc-exec.exe"
    $configs = Join-Path $ExtractDir 'test_configs'
    $runner = Join-Path $ExtractDir 'test_scripts\run_isolation_session_tests.ps1'
    $log = Join-Path $LogDir 'one_shot.log'
    $start = Get-Date
    $result = Invoke-PsRunner -RunnerPath $runner -Arguments @('-WxcExePath', $wxc, '-ConfigDir', $configs) -LogPath $log
    $elapsed = ((Get-Date) - $start).TotalMilliseconds
    $records = Parse-OneShotOutput -Lines $result.Lines -SuiteName 'isolation_session_one_shot'
    return @{ Records = $records; DurationMs = $elapsed; RunnerExit = $result.ExitCode; LogPath = $log }
}

function Invoke-StateAwareSuite {
    param([string]$ExtractDir, [string]$Arch, [string]$LogDir)
    Write-Stage 'Suite 2/3: isolation-session state-aware'
    $wxc = Join-Path $ExtractDir "bin\$Arch\wxc-exec.exe"
    $configs = Join-Path $ExtractDir 'test_configs'
    $runner = Join-Path $ExtractDir 'test_scripts\run_isolation_session_state_aware_tests.ps1'
    $log = Join-Path $LogDir 'state_aware.log'
    $start = Get-Date
    $result = Invoke-PsRunner -RunnerPath $runner -Arguments @('-WxcExePath', $wxc, '-ConfigDir', $configs) -LogPath $log
    $elapsed = ((Get-Date) - $start).TotalMilliseconds
    $records = Parse-StateAwareOutput -Lines $result.Lines -SuiteName 'isolation_session_state_aware'
    return @{ Records = $records; DurationMs = $elapsed; RunnerExit = $result.ExitCode; LogPath = $log }
}

function Invoke-NodeSuite {
    param([string]$ExtractDir, [string]$LogDir)
    Write-Stage 'Suite 3/3: SDK integration (Node E2E)'
    $sdkInteg = Join-Path $ExtractDir 'sdk-integration'
    $log = Join-Path $LogDir 'node.log'
    $junit = Join-Path $LogDir 'node-results.junit.xml'
    $testFile = Join-Path $sdkInteg 'dist\isolation-session-state-aware.test.js'
    if (-not (Test-Path $testFile)) {
        Write-Warn "Test file not present in package: $testFile"
        return @{
            Records    = @((New-SuiteSkipRecord -Suite 'sdk_integration_isolation_session' -Reason 'test file missing from package'))
            DurationMs = 0
            RunnerExit = 0
            LogPath    = $log
        }
    }
    # Multiple --test-reporter pairs give us live spec output AND structured
    # JUnit XML for parsing. --test-force-exit because node-pty (a transitive
    # SDK dep) can keep the event loop alive past test completion.
    $args = @(
        '--test',
        '--test-force-exit',
        '--test-reporter=spec', '--test-reporter-destination=stdout',
        '--test-reporter=junit', "--test-reporter-destination=$junit",
        'dist/isolation-session-state-aware.test.js'
    )
    $start = Get-Date
    Push-Location $sdkInteg
    try {
        $result = Invoke-WithLiveTee -FilePath 'node' -ArgumentList $args -LogPath $log
    } finally { Pop-Location }
    $elapsed = ((Get-Date) - $start).TotalMilliseconds
    $records = Parse-JunitFile -XmlPath $junit -SuiteName 'sdk_integration_isolation_session'
    return @{ Records = $records; DurationMs = $elapsed; RunnerExit = $result.ExitCode; LogPath = $log }
}

# ============================================================================
# Emitters
# ============================================================================

function Write-ConsoleSummary {
    param($Suites)
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "Final summary" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
    $totalP = 0; $totalF = 0; $totalS = 0
    foreach ($suite in $Suites) {
        $p = @($suite.Records | Where-Object { $_.Status -eq 'passed' }).Count
        $f = @($suite.Records | Where-Object { $_.Status -eq 'failed' }).Count
        $s = @($suite.Records | Where-Object { $_.Status -eq 'skipped' }).Count
        $totalP += $p; $totalF += $f; $totalS += $s
        $dur = [TimeSpan]::FromMilliseconds($suite.DurationMs).ToString('hh\:mm\:ss')
        $line = "  $($suite.Name): $p passed, $f failed, $s skipped (runner exit=$($suite.RunnerExit), $dur)"
        $color = if ($f -gt 0) { 'Red' } elseif ($s -gt 0 -and $p -eq 0) { 'Yellow' } else { 'Green' }
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ""
    if ($totalF -gt 0) {
        Write-Host "Failures:" -ForegroundColor Red
        foreach ($suite in $Suites) {
            foreach ($r in ($suite.Records | Where-Object { $_.Status -eq 'failed' })) {
                $msg = if ($r.Reason) { "$($r.Suite) / $($r.Name): $($r.Reason)" } else { "$($r.Suite) / $($r.Name)" }
                Write-Host "  - $msg" -ForegroundColor Red
            }
        }
        Write-Host ""
    }
    $allTotal = $totalP + $totalF + $totalS
    $tally = "TOTAL: $totalP passed, $totalF failed, $totalS skipped (of $allTotal)"
    $color = if ($totalF -gt 0) { 'Red' } else { 'Green' }
    Write-Host $tally -ForegroundColor $color
    Write-Host ""
    return @{ Passed = $totalP; Failed = $totalF; Skipped = $totalS; Total = $allTotal }
}

# Convert a free-text reason into XML-safe attribute text.
function ConvertTo-XmlAttribute {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&','&amp;').Replace('"','&quot;').Replace('<','&lt;').Replace('>','&gt;')
}

function Write-JunitXml {
    param($Suites, [string]$Path, $Tallies, [TimeSpan]$Elapsed)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$sb.AppendLine("<testsuites name=`"mxc-isolation-session`" tests=`"$($Tallies.Total)`" failures=`"$($Tallies.Failed)`" skipped=`"$($Tallies.Skipped)`" time=`"$([math]::Round($Elapsed.TotalSeconds, 3))`">")
    foreach ($suite in $Suites) {
        $p = @($suite.Records | Where-Object { $_.Status -eq 'passed' }).Count
        $f = @($suite.Records | Where-Object { $_.Status -eq 'failed' }).Count
        $s = @($suite.Records | Where-Object { $_.Status -eq 'skipped' }).Count
        $total = $p + $f + $s
        $time = [math]::Round($suite.DurationMs / 1000.0, 3)
        [void]$sb.AppendLine("  <testsuite name=`"$($suite.Name)`" tests=`"$total`" failures=`"$f`" skipped=`"$s`" time=`"$time`">")
        foreach ($r in $suite.Records) {
            $caseTime = [math]::Round($r.DurationMs / 1000.0, 3)
            $name = ConvertTo-XmlAttribute $r.Name
            if ($r.Status -eq 'passed') {
                [void]$sb.AppendLine("    <testcase classname=`"$($r.Suite)`" name=`"$name`" time=`"$caseTime`"/>")
            } elseif ($r.Status -eq 'failed') {
                $reason = ConvertTo-XmlAttribute $r.Reason
                [void]$sb.AppendLine("    <testcase classname=`"$($r.Suite)`" name=`"$name`" time=`"$caseTime`">")
                [void]$sb.AppendLine("      <failure message=`"$reason`"/>")
                [void]$sb.AppendLine("    </testcase>")
            } else {
                $reason = ConvertTo-XmlAttribute $r.Reason
                [void]$sb.AppendLine("    <testcase classname=`"$($r.Suite)`" name=`"$name`" time=`"$caseTime`">")
                [void]$sb.AppendLine("      <skipped message=`"$reason`"/>")
                [void]$sb.AppendLine("    </testcase>")
            }
        }
        [void]$sb.AppendLine('  </testsuite>')
    }
    [void]$sb.AppendLine('</testsuites>')
    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}

function Write-ResultsJson {
    param($Suites, $Manifest, $Tallies, [DateTime]$StartedAt, [DateTime]$EndedAt, [string]$Path)
    $arch = Get-HostArch
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $payload = [ordered]@{
        summary = [ordered]@{
            total       = $Tallies.Total
            passed      = $Tallies.Passed
            failed      = $Tallies.Failed
            skipped     = $Tallies.Skipped
            duration_ms = [int](($EndedAt - $StartedAt).TotalMilliseconds)
            started_at  = $StartedAt.ToUniversalTime().ToString('o')
            ended_at    = $EndedAt.ToUniversalTime().ToString('o')
        }
        host = [ordered]@{
            arch       = $arch
            os_version = $os
        }
        package = [ordered]@{
            commit_sha    = $Manifest.mxc.commit_sha
            cargo_version = $Manifest.mxc.cargo_version
            produced_at   = $Manifest.produced_at
        }
        suites = @()
    }
    foreach ($suite in $Suites) {
        $suiteObj = [ordered]@{
            name        = $suite.Name
            duration_ms = [int]$suite.DurationMs
            runner_exit = $suite.RunnerExit
            log_path    = $suite.LogPath
            tests       = @()
        }
        foreach ($r in $suite.Records) {
            $testObj = [ordered]@{
                name        = $r.Name
                status      = $r.Status
                duration_ms = [int]$r.DurationMs
            }
            if ($r.Reason) { $testObj['reason'] = $r.Reason }
            $suiteObj.tests += $testObj
        }
        $payload.suites += $suiteObj
    }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

function Write-Tap {
    param($Suites, [string]$Path)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('TAP version 13')
    $allTests = New-Object System.Collections.ArrayList
    foreach ($suite in $Suites) {
        foreach ($r in $suite.Records) { [void]$allTests.Add($r) }
    }
    [void]$sb.AppendLine("1..$($allTests.Count)")
    $n = 0
    foreach ($r in $allTests) {
        $n++
        $title = "$($r.Suite) / $($r.Name)"
        if ($r.Status -eq 'passed') {
            [void]$sb.AppendLine("ok $n - $title")
        } elseif ($r.Status -eq 'failed') {
            [void]$sb.AppendLine("not ok $n - $title")
            if ($r.Reason) {
                [void]$sb.AppendLine('  ---')
                [void]$sb.AppendLine("  message: $($r.Reason -replace '[\r\n]+',' ')")
                [void]$sb.AppendLine('  ...')
            }
        } else {
            $reason = if ($r.Reason) { $r.Reason -replace '[\r\n]+',' ' } else { 'skipped' }
            [void]$sb.AppendLine("ok $n - $title # SKIP $reason")
        }
    }
    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}

# ============================================================================
# Main
# ============================================================================

$Script:StartedAt = Get-Date

Write-Host ""
Write-Host "MXC IsolationSession Test Runner - Consumer" -ForegroundColor White
Write-Host "============================================" -ForegroundColor White
if ($ResultsPath) { Write-Host "Results: $ResultsPath" }
if ($Unattended)  { Write-Host "Mode: unattended" }

$extractDir = $null
$suites = @()
$tallies = $null

try {
    $Script:CurrentPhase = 'validate-package'
    $PackagePath = Resolve-PackagePath -Provided $PackagePath
    Write-Host "Package: $PackagePath"
    $manifest = Read-PackageManifest -Path $PackagePath
    Test-ManifestCompatible -Manifest $manifest
    Write-Ok "Package manifest validated (format_version=$($manifest.format_version), commit=$($manifest.mxc.commit_sha))"

    $Script:CurrentPhase = 'prereq-probe'
    $probe = Invoke-PrereqProbe

    $Script:CurrentPhase = 'prereq-install'
    Invoke-PrereqInstall -State $probe

    $Script:CurrentPhase = 'extract'
    $extractDir = Invoke-Extract -Path $PackagePath -Destination $ExtractPath

    if (-not $ResultsPath) { $ResultsPath = $extractDir }
    if (-not (Test-Path $ResultsPath)) { New-Item -ItemType Directory -Path $ResultsPath -Force | Out-Null }

    $logDir = Join-Path $extractDir 'logs'
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null

    $arch = Get-HostArch
    Write-Step "Host architecture: $arch"

    $Script:CurrentPhase = 'run'
    $oneShot = Invoke-OneShotSuite -ExtractDir $extractDir -Arch $arch -LogDir $logDir
    $stateAware = Invoke-StateAwareSuite -ExtractDir $extractDir -Arch $arch -LogDir $logDir
    $node = Invoke-NodeSuite -ExtractDir $extractDir -LogDir $logDir

    $suites = @(
        @{ Name = 'isolation_session_one_shot';        Records = $oneShot.Records;    DurationMs = $oneShot.DurationMs;    RunnerExit = $oneShot.RunnerExit;    LogPath = $oneShot.LogPath },
        @{ Name = 'isolation_session_state_aware';     Records = $stateAware.Records; DurationMs = $stateAware.DurationMs; RunnerExit = $stateAware.RunnerExit; LogPath = $stateAware.LogPath },
        @{ Name = 'sdk_integration_isolation_session'; Records = $node.Records;       DurationMs = $node.DurationMs;       RunnerExit = $node.RunnerExit;       LogPath = $node.LogPath }
    )

    $Script:CurrentPhase = 'emit'
    $tallies = Write-ConsoleSummary -Suites $suites
    $elapsed = (Get-Date) - $Script:StartedAt
    $junitPath = Join-Path $ResultsPath 'results.junit.xml'
    $jsonPath  = Join-Path $ResultsPath 'results.json'
    $tapPath   = Join-Path $ResultsPath 'results.tap'
    Write-JunitXml   -Suites $suites -Path $junitPath -Tallies $tallies -Elapsed $elapsed
    Write-ResultsJson -Suites $suites -Manifest $manifest -Tallies $tallies -StartedAt $Script:StartedAt -EndedAt (Get-Date) -Path $jsonPath
    Write-Tap        -Suites $suites -Path $tapPath
    Write-Host "Results written to:" -ForegroundColor Gray
    Write-Host "  $junitPath" -ForegroundColor Gray
    Write-Host "  $jsonPath"  -ForegroundColor Gray
    Write-Host "  $tapPath"   -ForegroundColor Gray
    Write-Host ""
}
catch {
    $elapsed = (Get-Date) - $Script:StartedAt
    Write-FailureSummary -Reason $_.Exception.Message -Elapsed $elapsed -Stack $_.ScriptStackTrace
    Reset-ConsoleColor
    exit (Get-PhaseExitCode)
}

# Exit 0 when no failed test records; 1 when one or more failed. Skips do not
# count as failures (a host that legitimately does not support isolation
# sessions is a clean outcome).
Reset-ConsoleColor
if ($tallies -and $tallies.Failed -gt 0) { exit 1 }
exit 0
