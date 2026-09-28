<#
.SYNOPSIS
Runs a Windows backend test from a downloaded CI artifact.

.DESCRIPTION
Takes the matrix backend id straight from the catalog, so there is no
id-to-command mapping to keep in sync. 
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'process-t1',
        'process-t3',
        'isolation-session',
        'windows-sandbox',
        'wslc',
        'microvm'
    )]
    [string]$Backend,

    [Parameter(Mandatory)]
    [string]$BinaryDirectory,

    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture
)

$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptRoot)
$testScriptRoot = Join-Path $repoRoot 'tests\scripts'
$binaryDirectoryPath = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$wxc = Join-Path $binaryDirectoryPath 'wxc-exec.exe'

function Assert-File {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required CI artifact file is missing: $Path"
    }
}

# The suites, and MXC itself, write logs and scratch trees under $env:TEMP,
# which is not the directory CI uploads from. Rather than enumerate every
# artifact and copy it afterwards, point TEMP at the upload directory for the
# duration of the run: parameter defaults, .NET GetTempPath(), and child
# processes all follow it, so anything temp-rooted lands where CI collects it.
#
# The suites' scratch-root guards compare against $env:TEMP, so they stay
# satisfied — this redirects what TEMP means rather than pointing a path
# outside it.
function Redirect-TempToRunnerTemp {
    if (-not $env:RUNNER_TEMP) {
        return
    }
    if (-not (Test-Path -LiteralPath $env:RUNNER_TEMP)) {
        New-Item -ItemType Directory -Force -Path $env:RUNNER_TEMP | Out-Null
    }
    $env:TEMP = $env:RUNNER_TEMP
    $env:TMP  = $env:RUNNER_TEMP
    Write-Host "Redirected TEMP to $env:RUNNER_TEMP so test logs are collected."
}

function Invoke-TestScript {
    param(
        [Parameter(Mandatory)][string]$Path,
        # Splat a hashtable, not an array. Array splatting binds elements
        # positionally, so '-BinDir' would be passed as the first positional
        # value rather than naming the parameter.
        [hashtable]$Arguments = @{}
    )

    # PowerShell scripts do not always replace a previous native exit code.
    # Reset it so a successful script cannot inherit a stale failure.
    $global:LASTEXITCODE = 0
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Backend test failed with exit code $LASTEXITCODE`: $Path"
    }
}

Assert-File -Path $wxc

function Invoke-ProcessContainerTests {
    # Returns the harness exit code rather than throwing, so a caller running
    # more than one suite can report both results instead of stopping at the
    # first failure. The suite talks to the operator through Write-Host (which
    # Out-Null does not touch), so discarding the success stream keeps the
    # return value a scalar even if a phase leaks a stray object.
    [OutputType([int])]
    param(
        # The tier this matrix entry exists to exercise. Passed through to the
        # harness, which aborts when the host selects a different one. Without
        # it a mis-provisioned process-t1 runner would silently run the T3
        # assertions and report green, proving nothing about BaseContainer.
        [Parameter(Mandatory)]
        [ValidateSet('base-container', 'appcontainer-dacl')]
        [string]$RequireTier
    )

    # The existing harness expects separate debug and release layouts. CI
    # intentionally tests one release artifact, so stage it in both slots.
    $debugDirectory = Join-Path $binaryDirectoryPath 'debug'
    $releaseDirectory = Join-Path $binaryDirectoryPath 'release'
    New-Item -ItemType Directory -Force -Path $debugDirectory, $releaseDirectory | Out-Null
    Copy-Item -LiteralPath $wxc -Destination (Join-Path $debugDirectory 'wxc-exec.exe') -Force
    Copy-Item -LiteralPath $wxc -Destination (Join-Path $releaseDirectory 'wxc-exec.exe') -Force

    $uiProbe = Join-Path $binaryDirectoryPath 'wxc-ui-probe.exe'
    Assert-File -Path $uiProbe
    Copy-Item -LiteralPath $uiProbe -Destination (Join-Path $debugDirectory 'wxc-ui-probe.exe') -Force
    Copy-Item -LiteralPath $uiProbe -Destination (Join-Path $releaseDirectory 'wxc-ui-probe.exe') -Force

    # wxc-exec resolves these next to its own image: plm.exe backs the guarded-WPR
    # captureDenials fallback and winhttp-proxy-shim.exe backs the legacy proxy
    # path. Absent, those areas fail as launch errors instead of policy results.
    foreach ($sidecar in 'plm.exe', 'winhttp-proxy-shim.exe') {
        $source = Join-Path $binaryDirectoryPath $sidecar
        Assert-File -Path $source
        Copy-Item -LiteralPath $source -Destination (Join-Path $debugDirectory $sidecar) -Force
        Copy-Item -LiteralPath $source -Destination (Join-Path $releaseDirectory $sidecar) -Force
    }

    $script = Join-Path $testScriptRoot 'run_processcontainer_all_tests.ps1'
    # -KeepArtifacts stops the suite deleting its scratch tree on a clean run,
    # so a passing job still uploads its per-area logs, configs, and result
    # documents.
    $global:LASTEXITCODE = 0
    & $script `
        -SkipBuild `
        -RequireTier $RequireTier `
        -WxcDebug (Join-Path $debugDirectory 'wxc-exec.exe') `
        -WxcRelease (Join-Path $releaseDirectory 'wxc-exec.exe') `
        -UiProbeDebug (Join-Path $debugDirectory 'wxc-ui-probe.exe') `
        -UiProbeRelease (Join-Path $releaseDirectory 'wxc-ui-probe.exe') `
        -KeepArtifacts | Out-Null
    return $LASTEXITCODE
}

function Invoke-T3WorkloadTests {
    [OutputType([int])]
    param()

    $script = Join-Path $testScriptRoot 'T3-Workloads.ps1'
    # -Wxc is required: the script's default points at a debug build that does
    # not exist in a CI artifact. -KeepArtifacts preserves the per-workload
    # logs and configs on a clean run so a passing job still uploads them.
    # -GrantDriveRoot lets the pwsh/git workloads resolve their working
    # directory's ancestor chain; it rewrites ACLs across the system drive,
    # which is why the script leaves it off by default and only a disposable
    # CI runner opts in. Temporary until pwsh 7.7 leaves preview.
    $global:LASTEXITCODE = 0
    & $script -Wxc $wxc -KeepArtifacts -GrantDriveRoot | Out-Null
    return $LASTEXITCODE
}

# stderr is read apart from stdout: wxc-exec can report host cleanup there
# before the probe's JSON.
function Get-IsolationSessionProbe {
    $errFile = [System.IO.Path]::GetTempFileName()
    $ErrorActionPreference = 'Continue'
    try {
        $stdout = (& $wxc --probe 2>$errFile) | Out-String
        $exitCode = $LASTEXITCODE
        $stderr = Get-Content -LiteralPath $errFile -Raw
    }
    finally {
        Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
    }
    if ($exitCode -ne 0) {
        return @{ Status = 'error'; Detail = "wxc-exec --probe exited $exitCode. $stderr" }
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
    return @{ Status = $(if ($value) { 'available' } else { 'unavailable' }) }
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
    return @{ ExitCode = $LASTEXITCODE; Log = $log }
}

function Invoke-ScriptSuite {
    param([Parameter(Mandatory)][string]$Name)

    $skipped = $null
    $global:LASTEXITCODE = 0
    & (Join-Path $testScriptRoot $Name) -WxcExePath $wxc 6>&1 | ForEach-Object {
        if ($_.MessageData -is [System.Management.Automation.HostInformationMessage]) {
            if ($_.MessageData.Message -match '^SKIPPED:') { $skipped = $_.MessageData.Message }
            Write-Host $_.MessageData.Message -NoNewline:$_.MessageData.NoNewLine
        }
        else {
            $_
        }
    } | Out-Host
    if ($LASTEXITCODE -ne 0) { return "exited $LASTEXITCODE" }
    $skipped
}

function Get-LibtestFailure {
    param([Parameter(Mandatory)][hashtable]$Run)

    if ($Run.ExitCode -ne 0) {
        return "exited $($Run.ExitCode)"
    }
    $summary = Select-String -LiteralPath $Run.Log -Pattern '^test result: \w+\. (\d+) passed; (\d+) failed;' |
        Select-Object -Last 1
    if (-not $summary -or ([int]$summary.Matches[0].Groups[1].Value + [int]$summary.Matches[0].Groups[2].Value) -eq 0) {
        return 'executed no tests'
    }
}

# Node reports a skipped describe block as a top-level skipped testcase.
function Get-NodeSuiteFailure {
    param([Parameter(Mandatory)][string]$JunitPath)

    [xml]$report = Get-Content -LiteralPath $JunitPath -Raw
    $blocks = @($report.testsuites.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
    if ($blocks.Count -eq 0) {
        return 'executed no tests'
    }
    $failures = foreach ($block in $blocks) {
        if (@($block.SelectNodes('descendant-or-self::testcase[not(skipped)]')).Count -eq 0) {
            "'$($block.name)' executed no tests"
        }
    }
    $failures -join '; '
}

function Invoke-IsolationSessionSuites {
    $bundle = Join-Path $binaryDirectoryPath 'isolation-session-bundle'
    $inProcTests = Join-Path $bundle 'inproc\mxc-sdk-isolation-session-tests.exe'
    $helperTests = Join-Path $bundle 'inproc\mxc-sdk-helpers-tests.exe'
    $staProbe = Join-Path $bundle 'inproc\sta_probe.exe'
    $dotnetTests = Join-Path $bundle 'dotnet\Microsoft.Mxc.Sdk.Tests.exe'
    $node = Join-Path $bundle 'node\node.exe'
    $nodeSuiteRoot = Join-Path $bundle 'sdk-integration'
    foreach ($file in $inProcTests, $helperTests, $staProbe, $dotnetTests, $node, (Join-Path $nodeSuiteRoot 'dist\isolation-session-state-aware.test.js')) {
        Assert-File -Path $file
    }

    $probe = Get-IsolationSessionProbe
    if ($probe.Status -eq 'unavailable') {
        throw 'wxc-exec --probe reports isolationSessionAvailable=false.'
    }
    if ($probe.Status -ne 'available') {
        throw "Could not determine whether isolation sessions are available: $($probe.Detail)"
    }

    $env:MXC_ISO_TESTS_REQUIRED = '1'
    Remove-Item Env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS -ErrorAction SilentlyContinue

    $suites = [ordered]@{
        'one-shot' = { Invoke-ScriptSuite 'run_isolation_session_tests.ps1' }
        'state-aware' = { Invoke-ScriptSuite 'run_isolation_session_state_aware_tests.ps1' }
        'Node' = {
            $junit = Join-Path $env:TEMP 'isolation-session-node.junit.xml'
            Push-Location $nodeSuiteRoot
            try {
                $run = Invoke-LoggedNative -FilePath $node -LogName 'isolation-session-node.log' -ArgumentList @(
                    '--test', '--test-force-exit',
                    '--test-reporter=spec', '--test-reporter-destination=stdout',
                    '--test-reporter=junit', "--test-reporter-destination=$junit",
                    'dist/isolation-session-state-aware.test.js')
            }
            finally {
                Pop-Location
            }
            if ($run.ExitCode -ne 0) { "exited $($run.ExitCode)" } else { Get-NodeSuiteFailure -JunitPath $junit }
        }
        'Rust' = {
            Get-LibtestFailure (Invoke-LoggedNative -FilePath $inProcTests -ArgumentList '--test-threads=1' -LogName 'isolation-session-rust.log')
        }
        'Rust SDK helpers' = {
            Get-LibtestFailure (Invoke-LoggedNative -FilePath $helperTests -ArgumentList '--test-threads=1' -LogName 'isolation-session-rust-helpers.log')
        }
        'C#' = {
            $resultXml = Join-Path $env:TEMP 'isolation-session-dotnet.xml'
            $run = Invoke-LoggedNative -FilePath $dotnetTests -LogName 'isolation-session-dotnet.log' -ArgumentList @(
                '-class', 'Microsoft.Mxc.Sdk.Tests.MxcSandboxIsolationSessionE2ETests',
                '-class', 'Microsoft.Mxc.Sdk.Tests.MxcLifecycleE2ETests',
                '-result-xml', $resultXml)
            if ($run.ExitCode -ne 0) {
                "exited $($run.ExitCode)"
            }
            elseif (@(([xml](Get-Content -LiteralPath $resultXml -Raw)).SelectNodes("//test[@result='Pass' or @result='Fail']")).Count -eq 0) {
                'executed no tests'
            }
        }
        'apartment probe' = {
            $modes = [ordered]@{
                'sta' = 'RESULT: COMPLETED'
                'mta' = 'RESULT: COMPLETED'
                'none' = 'RESULT: COMPLETED'
                'handle-outlives-thread' = 'RESULT: HANDLE SURVIVED'
            }
            $failures = foreach ($mode in $modes.Keys) {
                $run = Invoke-LoggedNative -FilePath $staProbe -ArgumentList $mode -LogName "isolation-session-sta-probe-$mode.log"
                $verdicts = @(Select-String -LiteralPath $run.Log -Pattern '^RESULT: ' | ForEach-Object Line)
                if ($run.ExitCode -ne 0 -or $verdicts.Count -eq 0 -or
                    @($verdicts | Where-Object { -not $_.StartsWith($modes[$mode]) }).Count -gt 0) {
                    "$mode exited $($run.ExitCode): $(if ($verdicts) { $verdicts -join ' | ' } else { 'no RESULT line' })"
                }
            }
            $failures -join '; '
        }
    }

    # Account names stay in memory; they must not reach the log.
    $accountsBefore = @((Get-LocalUser).Name)
    $results = [ordered]@{}
    try {
        foreach ($name in $suites.Keys) {
            Write-Host "=== isolation-session: $name ==="
            try {
                $results[$name] = "$(& $suites[$name])"
            }
            catch {
                $results[$name] = $_.Exception.Message
            }
        }
    }
    finally {
        $accountsAfter = @((Get-LocalUser).Name)
        $added = @($accountsAfter | Where-Object { $accountsBefore -notcontains $_ }).Count
        $removed = @($accountsBefore | Where-Object { $accountsAfter -notcontains $_ }).Count
        $results['local accounts'] = "before $($accountsBefore.Count), after $($accountsAfter.Count) (+$added, -$removed)"
        if ($added -eq 0 -and $removed -eq 0) {
            Write-Host "Local accounts: $($results['local accounts'])"
            $results['local accounts'] = ''
        }
    }

    foreach ($name in $results.Keys) {
        if ($results[$name]) {
            Write-Host "FAIL  $name`: $($results[$name])" -ForegroundColor Red
        }
        else {
            Write-Host "PASS  $name" -ForegroundColor Green
        }
    }
    if (@($results.Values | Where-Object { $_ }).Count -gt 0) {
        throw 'isolation-session validation failed; see the results above.'
    }
}

Redirect-TempToRunnerTemp

# The matrix entry names the tier the job exists to exercise, but the host picks
# the tier at run time. -RequireTier makes the suite abort instead of testing
# whichever tier it landed on and reporting green for the wrong entry.
switch ($Backend) {
    'process-t1' {
        $primitives = Invoke-ProcessContainerTests -RequireTier 'base-container'
        if ($primitives -ne 0) {
            throw "Process Container tests failed with exit code $primitives."
        }
    }
    'process-t3' {
        # Run both suites before reporting. Stopping at the first failure would
        # hide the other suite's result, costing an extra nightly run to triage.
        $primitives = Invoke-ProcessContainerTests -RequireTier 'appcontainer-dacl'
        $workloads = Invoke-T3WorkloadTests
        if ($primitives -ne 0 -or $workloads -ne 0) {
            throw "process-t3 tests failed (primitives exit=$primitives, workloads exit=$workloads)."
        }
    }
    'isolation-session' {
        Invoke-IsolationSessionSuites
    }
    'windows-sandbox' {
        Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_windows_sandbox_one_shot_tests.ps1') -Arguments @{
            BinDir = $binaryDirectoryPath
        }
    }
    'wslc' {
        Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_wslc_all_tests.ps1') -Arguments @{
            WxcExecPath = $wxc
        }
    }
    'microvm' {
        Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_microvm_tests.ps1') -Arguments @{
            BinDir = $binaryDirectoryPath
        }
    }
}
