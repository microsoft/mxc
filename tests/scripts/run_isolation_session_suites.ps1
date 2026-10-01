<#
.SYNOPSIS
Runs the isolation-session suites packaged in an isolation-session test bundle.

.DESCRIPTION
The single definition of what each packaged suite runs and what counts as a
pass. Scheduled validation and the Windows OS lab both call it from the
bundle, so a suite's oracle ships with the source it was built from.

Run from the bundle's test_scripts directory. Every selected suite runs even
after an earlier one fails; the last output line is the overall N/M summary.

.PARAMETER List
Writes the name of every suite whose payload is present, one per line, and
exits without running anything.

.PARAMETER Suite
Suites to run. All present suites run when omitted.

.PARAMETER WxcExePath
The wxc-exec under test. Defaults to the bundle's bin\<arch>\wxc-exec.exe.

.PARAMETER BackendUnavailable
What to do when wxc-exec --probe reports that isolation sessions are
unavailable: Fail (scheduled validation) or Skip (hosts that may lack the
backend). Skip writes a SKIPPED: line and exits 0.

.PARAMETER ResultPath
Writes a JSON object of per-suite results here.
#>
[CmdletBinding()]
param(
    [switch]$List,

    [string[]]$Suite,

    # Defaults to the bundle holding this script.
    [string]$BundleRoot,

    [string]$WxcExePath,

    [ValidateSet('Fail', 'Skip')]
    [string]$BackendUnavailable = 'Fail',

    [string]$ResultPath
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell does not set $PSScriptRoot for parameter defaults.
if (-not $BundleRoot) {
    $BundleRoot = Split-Path -Parent $PSScriptRoot
}
$BundleRoot = (Resolve-Path -LiteralPath $BundleRoot).Path

function Get-BundlePath {
    param([Parameter(Mandatory)][string]$RelativePath)

    Join-Path $BundleRoot $RelativePath
}

$suites = [ordered]@{
    'one-shot' = @{
        Requires = @('test_scripts\run_isolation_session_tests.ps1', 'test_configs')
        Run = { Invoke-ScriptSuite 'run_isolation_session_tests.ps1' }
    }
    'state-aware' = @{
        Requires = @('test_scripts\run_isolation_session_state_aware_tests.ps1', 'test_configs')
        Run = { Invoke-ScriptSuite 'run_isolation_session_state_aware_tests.ps1' }
    }
    'node' = @{
        Requires = @('node\node.exe', 'sdk-integration\dist\isolation-session-state-aware.test.js')
        Run = { Invoke-NodeSuite }
    }
    'rust' = @{
        Requires = @('inproc\mxc-sdk-isolation-session-tests.exe')
        Run = { Invoke-LibtestSuite 'inproc\mxc-sdk-isolation-session-tests.exe' 'isolation-session-rust.log' }
    }
    'rust-sdk-helpers' = @{
        Requires = @('inproc\mxc-sdk-helpers-tests.exe')
        Run = { Invoke-LibtestSuite 'inproc\mxc-sdk-helpers-tests.exe' 'isolation-session-rust-helpers.log' }
    }
    'dotnet' = @{
        Requires = @('dotnet\Microsoft.Mxc.Sdk.Tests.exe')
        Run = { Invoke-DotNetSuite }
    }
    'apartment' = @{
        Requires = @('inproc\sta_probe.exe')
        Run = { Invoke-ApartmentSuite }
    }
}

function Test-SuitePresent {
    param([Parameter(Mandatory)][string]$Name)

    foreach ($relativePath in $suites[$Name].Requires) {
        if (-not (Test-Path -LiteralPath (Get-BundlePath $relativePath))) {
            return $false
        }
    }
    $true
}

if ($List) {
    foreach ($name in $suites.Keys) {
        if (Test-SuitePresent $name) {
            Write-Output $name
        }
    }
    exit 0
}

if (-not $WxcExePath) {
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
    $WxcExePath = Get-BundlePath "bin\$arch\wxc-exec.exe"
}
if (-not (Test-Path -LiteralPath $WxcExePath -PathType Leaf)) {
    Write-Host '0/1 passed'
    throw "wxc-exec not found at $WxcExePath."
}
$WxcExePath = (Resolve-Path -LiteralPath $WxcExePath).Path

if ($Suite) {
    $unknown = @($Suite | Where-Object { -not $suites.Contains($_) })
    if ($unknown) {
        throw "Unknown suite(s): $($unknown -join ', '). Known: $($suites.Keys -join ', ')."
    }
    $selected = @($Suite)
}
else {
    $selected = @($suites.Keys | Where-Object { Test-SuitePresent $_ })
}

# A suite result: Failure is empty when the suite passed.
function New-SuiteResult {
    param(
        [int]$Passed,
        [int]$Total,
        [int]$Skipped = 0,
        [string]$Failure = ''
    )

    if (-not $Failure -and $Total -eq 0) {
        $Failure = 'executed no tests'
    }
    if (-not $Failure -and $Passed -ne $Total) {
        $Failure = "$($Total - $Passed) of $Total failed"
    }
    @{ Passed = $Passed; Total = $Total; Skipped = $Skipped; Failure = $Failure }
}

function Invoke-LoggedNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory)][string]$LogName
    )

    $log = Join-Path $env:TEMP $LogName
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = 0
    & $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log | Out-Host
    @{ ExitCode = $LASTEXITCODE; Log = $log }
}

function Invoke-ScriptSuite {
    param([Parameter(Mandatory)][string]$Name)

    $lines = [System.Collections.Generic.List[string]]::new()
    $global:LASTEXITCODE = 0
    & (Get-BundlePath "test_scripts\$Name") -WxcExePath $WxcExePath -ConfigDir (Get-BundlePath 'test_configs') 6>&1 |
        ForEach-Object {
            if ($_.MessageData -is [System.Management.Automation.HostInformationMessage]) {
                $lines.Add([string]$_.MessageData.Message)
                Write-Host $_.MessageData.Message -NoNewline:$_.MessageData.NoNewLine
            }
            else {
                $lines.Add("$_")
                $_ | Out-Host
            }
        }
    $exitCode = $LASTEXITCODE

    # The backend probe passed, so a suite-level skip means the suite gave up on
    # a backend that is present.
    if (@($lines | Where-Object { $_ -cmatch '^SKIPPED:' }).Count -gt 0) {
        return New-SuiteResult -Skipped 1 -Failure 'the suite reported SKIPPED although the backend is available'
    }
    # The script's exit code is the oracle; its summary line only supplies counts.
    # "P/T passed, S skipped" includes skipped cases in T.
    $summary = @($lines | Where-Object { $_ -match '\d+/\d+ passed' } | Select-Object -Last 1)
    $passed = 0
    $executed = 0
    $skipped = 0
    if ($summary) {
        $null = $summary[0] -match '(\d+)/(\d+) passed(?:, (\d+) skipped)?'
        $passed = [int]$Matches[1]
        $executed = [int]$Matches[2]
        if ($Matches[3]) {
            $skipped = [int]$Matches[3]
            $executed -= $skipped
        }
    }
    if ($exitCode -ne 0) {
        return New-SuiteResult -Passed $passed -Total ([Math]::Max($executed, 1)) -Skipped $skipped -Failure "exited $exitCode"
    }
    New-SuiteResult -Passed $passed -Total $executed -Skipped $skipped
}

function Invoke-LibtestSuite {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$LogName
    )

    $run = Invoke-LoggedNative -FilePath (Get-BundlePath $RelativePath) -ArgumentList '--test-threads=1' -LogName $LogName
    $summary = Select-String -LiteralPath $run.Log -Pattern '^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored' |
        Select-Object -Last 1
    $passed = 0
    $failed = 0
    if ($summary) {
        $passed = [int]$summary.Matches[0].Groups[1].Value
        $failed = [int]$summary.Matches[0].Groups[2].Value
    }
    # Ignored tests are opt-in manual cases, not skips.
    New-SuiteResult -Passed $passed -Total ($passed + $failed) -Failure $(if ($run.ExitCode -ne 0) { "exited $($run.ExitCode)" })
}

function Invoke-NodeSuite {
    $junit = Join-Path $env:TEMP 'isolation-session-node.junit.xml'
    Remove-Item -LiteralPath $junit -Force -ErrorAction SilentlyContinue
    Push-Location (Get-BundlePath 'sdk-integration')
    try {
        $run = Invoke-LoggedNative -FilePath (Get-BundlePath 'node\node.exe') -LogName 'isolation-session-node.log' -ArgumentList @(
            '--test', '--test-force-exit',
            '--test-reporter=spec', '--test-reporter-destination=stdout',
            '--test-reporter=junit', "--test-reporter-destination=$junit",
            'dist/isolation-session-state-aware.test.js')
    }
    finally {
        Pop-Location
    }
    if (-not (Test-Path -LiteralPath $junit -PathType Leaf)) {
        return New-SuiteResult -Failure "exited $($run.ExitCode) without a JUnit report"
    }

    [xml]$report = Get-Content -LiteralPath $junit -Raw
    $cases = @($report.SelectNodes('//testcase'))
    $failed = @($cases | Where-Object { $_.SelectSingleNode('failure|error') }).Count
    $skipped = @($cases | Where-Object { $_.SelectSingleNode('skipped') }).Count
    $executed = $cases.Count - $skipped
    # Node reports a skipped describe block as a top-level skipped testcase, so
    # a block whose every case skipped is a suite that gave up.
    $blocks = @($report.testsuites.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
    $emptyBlocks = foreach ($block in $blocks) {
        if (@($block.SelectNodes('descendant-or-self::testcase[not(skipped)]')).Count -eq 0) {
            "'$($block.name)' executed no tests"
        }
    }
    $failure = if ($run.ExitCode -ne 0) { "exited $($run.ExitCode)" } else { $emptyBlocks -join '; ' }
    New-SuiteResult -Passed ($executed - $failed) -Total $executed -Skipped $skipped -Failure $failure
}

function Invoke-DotNetSuite {
    $resultXml = Join-Path $env:TEMP 'isolation-session-dotnet.xml'
    Remove-Item -LiteralPath $resultXml -Force -ErrorAction SilentlyContinue
    $run = Invoke-LoggedNative -FilePath (Get-BundlePath 'dotnet\Microsoft.Mxc.Sdk.Tests.exe') -LogName 'isolation-session-dotnet.log' -ArgumentList @(
        '-class', 'Microsoft.Mxc.Sdk.Tests.MxcSandboxIsolationSessionE2ETests',
        '-class', 'Microsoft.Mxc.Sdk.Tests.MxcLifecycleE2ETests',
        '-result-xml', $resultXml)
    if (-not (Test-Path -LiteralPath $resultXml -PathType Leaf)) {
        return New-SuiteResult -Failure "exited $($run.ExitCode) without an xUnit report"
    }

    [xml]$report = Get-Content -LiteralPath $resultXml -Raw
    $tests = @($report.SelectNodes('//test'))
    $passed = @($tests | Where-Object { $_.result -eq 'Pass' }).Count
    $skipped = @($tests | Where-Object { $_.result -in 'Skip', 'NotRun' }).Count
    New-SuiteResult -Passed $passed -Total ($tests.Count - $skipped) -Skipped $skipped `
        -Failure $(if ($run.ExitCode -ne 0) { "exited $($run.ExitCode)" })
}

# The probe returns success for some failed verdicts, so the RESULT line is the
# oracle. Every mode must complete now that single-threaded apartments are
# admitted.
function Invoke-ApartmentSuite {
    $modes = [ordered]@{
        'sta' = 'RESULT: COMPLETED'
        'mta' = 'RESULT: COMPLETED'
        'none' = 'RESULT: COMPLETED'
        'handle-outlives-thread' = 'RESULT: HANDLE SURVIVED'
    }
    $failures = @()
    $passed = 0
    $skipped = 0
    foreach ($mode in $modes.Keys) {
        $run = Invoke-LoggedNative -FilePath (Get-BundlePath 'inproc\sta_probe.exe') -ArgumentList $mode -LogName "isolation-session-sta-probe-$mode.log"
        $verdicts = @(Select-String -LiteralPath $run.Log -Pattern '^RESULT: ' | ForEach-Object Line)
        if (@($verdicts | Where-Object { $_.StartsWith('RESULT: SKIPPED') }).Count -gt 0) {
            $skipped++
            $failures += "$mode skipped although the backend is available"
        }
        elseif ($run.ExitCode -eq 0 -and $verdicts.Count -gt 0 -and
            @($verdicts | Where-Object { -not $_.StartsWith($modes[$mode]) }).Count -eq 0) {
            $passed++
        }
        else {
            $failures += "$mode exited $($run.ExitCode): $(if ($verdicts) { $verdicts -join ' | ' } else { 'no RESULT line' })"
        }
    }
    New-SuiteResult -Passed $passed -Total ($modes.Count - $skipped) -Skipped $skipped -Failure ($failures -join '; ')
}

# stderr is read apart from stdout: wxc-exec can report host cleanup there
# before the probe's JSON.
function Get-IsolationSessionProbe {
    $errFile = [System.IO.Path]::GetTempFileName()
    $ErrorActionPreference = 'Continue'
    try {
        $stdout = (& $WxcExePath --probe 2>$errFile) | Out-String
        $exitCode = $LASTEXITCODE
        $stderr = Get-Content -LiteralPath $errFile -Raw
    }
    finally {
        Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
    }
    if ($exitCode -ne 0) {
        return @{ Status = 'error'; Detail = "wxc-exec --probe exited $exitCode. $stdout $stderr" }
    }
    try {
        $value = ($stdout | ConvertFrom-Json).probes.isolationSessionAvailable
    }
    catch {
        return @{ Status = 'error'; Detail = "wxc-exec --probe did not emit valid JSON. $stderr" }
    }
    if ($value -isnot [bool]) {
        return @{ Status = 'error'; Detail = "wxc-exec --probe reported no boolean probes.isolationSessionAvailable. $stderr" }
    }
    @{ Status = $(if ($value) { 'available' } else { 'unavailable' }) }
}

function Write-Results {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Results)

    if ($ResultPath) {
        $Results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ResultPath -Encoding utf8
    }
}

Write-Host "Bundle: $BundleRoot"
Write-Host "wxc-exec: $WxcExePath"
Write-Host "Suites: $($selected -join ', ')"

$results = [ordered]@{}
$probe = Get-IsolationSessionProbe
if ($probe.Status -eq 'unavailable' -and $BackendUnavailable -eq 'Skip') {
    foreach ($name in $selected) {
        $results[$name] = @{ Status = 'Skipped'; Summary = ''; Detail = 'isolation sessions are unavailable' }
    }
    Write-Results $results
    Write-Host 'SKIPPED: wxc-exec --probe reports isolationSessionAvailable=false.'
    exit 0
}
if ($probe.Status -ne 'available') {
    $detail = if ($probe.Status -eq 'unavailable') { 'wxc-exec --probe reports isolationSessionAvailable=false.' } else { $probe.Detail }
    foreach ($name in $selected) {
        $results[$name] = @{ Status = 'Failed'; Summary = ''; Detail = $detail }
    }
    Write-Results $results
    Write-Host $detail
    Write-Host "0/$($selected.Count) passed"
    exit 1
}

$env:MXC_ISO_TESTS_REQUIRED = '1'
Remove-Item Env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS -ErrorAction SilentlyContinue
# Suites and the SDKs they load resolve wxc-exec from PATH.
$env:PATH = "$(Split-Path -Parent $WxcExePath);$env:PATH"

$passed = 0
$total = 0
foreach ($name in $selected) {
    Write-Host "=== isolation-session: $name ==="
    if (-not (Test-SuitePresent $name)) {
        $result = New-SuiteResult -Failure "payload missing: $($suites[$name].Requires -join ', ')"
    }
    else {
        # Some suites resolve their own cwd, so pin it: hosts differ (the OS
        # lab relaunches into %SystemRoot%\system32).
        Push-Location -LiteralPath $BundleRoot
        try {
            $result = & $suites[$name].Run
        }
        catch {
            $result = New-SuiteResult -Failure $_.Exception.Message
        }
        finally {
            Pop-Location
        }
    }

    $summary = "$($result.Passed)/$($result.Total) passed"
    if ($result.Skipped -gt 0) {
        $summary += ", $($result.Skipped) skipped"
    }
    $results[$name] = @{
        Status = $(if ($result.Failure) { 'Failed' } else { 'Passed' })
        Summary = $summary
        Detail = $result.Failure
    }
    $passed += $result.Passed
    $total += $result.Total
}

$failedSuites = @($results.Keys | Where-Object { $results[$_].Status -eq 'Failed' })
foreach ($name in $results.Keys) {
    $r = $results[$name]
    if ($r.Status -eq 'Failed') {
        Write-Host "FAIL  $name`: $($r.Summary). $($r.Detail)" -ForegroundColor Red
    }
    else {
        Write-Host "PASS  $name`: $($r.Summary)" -ForegroundColor Green
    }
}
Write-Results $results

if ($failedSuites) {
    Write-Host "$passed/$total passed, $($failedSuites.Count) suite(s) FAILED: $($failedSuites -join ', ')"
    exit 1
}
Write-Host "$passed/$total passed"
exit 0
