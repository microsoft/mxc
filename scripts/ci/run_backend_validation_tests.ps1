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
        'process',
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
    [string]$Architecture,

    [string]$TempDirectory
)

$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptRoot 'lib\TestSuiteResults.ps1')
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
# CI passes the upload directory as -TempDirectory.
function Redirect-Temp {
    if (-not $TempDirectory) {
        return
    }
    $directory = (New-Item -ItemType Directory -Force -Path $TempDirectory).FullName
    $env:TEMP = $directory
    $env:TMP  = $directory
    Write-Host "Redirected TEMP to $directory so test logs are collected."
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
    $probe = & $wxc --probe | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "ProcessContainer probe failed with exit code $LASTEXITCODE."
    }
    if (-not $probe.probes.baseContainerApiPresent -or $probe.tier -ne 'base-container') {
        throw 'ProcessContainer CI requires an enabled native PSEC contract.'
    }

    $scratch = Join-Path $env:TEMP ("mxc-native-process-container-ci-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null
    $configPath = Join-Path $scratch 'config.json'
    @{
        version = '1.0.0'
        containment = 'processcontainer'
        process = @{
            commandLine = 'cmd.exe /d /s /c "echo native-process-container-ok>native-smoke.txt && type native-smoke.txt"'
            cwd = $scratch
        }
        filesystem = @{
            readwritePaths = @($scratch)
        }
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath

    $output = (& $wxc $configPath | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $output -cne 'native-process-container-ok' -or
        (Get-Content -LiteralPath (Join-Path $scratch 'native-smoke.txt') -Raw).Trim() -cne $output) {
        throw "Native ProcessContainer read/write smoke failed: exit=$LASTEXITCODE; output=$output"
    }
    Write-Host $output
    Invoke-ProcessContainerStreamingTests
    Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_base_container_network_tests.ps1') `
        -Arguments @{ BinDir = $binaryDirectoryPath }
    $finalPathProbe = Join-Path $binaryDirectoryPath 'windows-sdk-bundle\inproc\mxc-final-path-probe.exe'
    Assert-File -Path $finalPathProbe
    Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_processcontainer_policy_tests.ps1') `
        -Arguments @{ BinDir = $binaryDirectoryPath; FinalPathProbe = $finalPathProbe }
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

function Invoke-ProcessContainerStreamingTests {
    $bundle = Join-Path $binaryDirectoryPath 'windows-sdk-bundle'
    $rustTests = Join-Path $bundle 'inproc\mxc-sdk-process-container-streaming-tests.exe'
    $dotnetTests = Join-Path $bundle 'dotnet\Microsoft.Mxc.Sdk.Tests.exe'
    $node = Join-Path $bundle 'node\node.exe'
    $nodeSuiteRoot = Join-Path $bundle 'sdk-integration'
    foreach ($file in $rustTests, $dotnetTests, $node, (Join-Path $nodeSuiteRoot 'dist\windows-process-container.test.js')) {
        Assert-File -Path $file
    }

    $rustCase = 'streaming_processcontainer_bidirectional_stdio'
    $run = Invoke-LoggedNative -FilePath $rustTests -LogName 'process-container-rust-streaming.log' `
        -ArgumentList @('--ignored', '--exact', $rustCase, '--test-threads=1')
    $failure = Get-LibtestFailure -Run $run -RequiredTests $rustCase
    if ($failure) { throw "Rust ProcessContainer streaming: $failure" }

    $previousPsec = $env:MXC_E2E_PSEC_CAPABLE_HOST
    $previousSkip = $env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS
    try {
        $env:MXC_E2E_PSEC_CAPABLE_HOST = '1'
        $env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS = '0'
        $resultXml = Join-Path $env:TEMP 'process-container-dotnet-streaming.xml'
        if (Test-Path -LiteralPath $resultXml) { Remove-Item -LiteralPath $resultXml }
        $run = Invoke-LoggedNative -FilePath $dotnetTests -LogName 'process-container-dotnet-streaming.log' `
            -ArgumentList @('-class', '*.MxcProcessTests', '-result-xml', $resultXml)
        if ($run.ExitCode -ne 0) { throw ".NET ProcessContainer streaming exited $($run.ExitCode)." }
        $failure = Get-XunitSuiteFailure -ResultXml $resultXml -Classes 'MxcProcessTests' -RejectSkipped `
            -RequiredMethods @('Streaming_WritesStdin_AndReadsEchoedStdout', 'OutputHeavyChild_DoesNotDeadlock',
                'Kill_DuringWaitAsync_Unblocks', 'Wait_EnforcesPolicyTimeout',
                'WaitForExitWithOutputAsync_Cancellation_DoesNotDeadlock')
        if ($failure) { throw ".NET ProcessContainer streaming: $failure" }

        $junit = Join-Path $env:TEMP 'process-container-node-streaming.junit.xml'
        if (Test-Path -LiteralPath $junit) { Remove-Item -LiteralPath $junit }
        $requiredNodeTests = @(
            'public run captures output and the workload exit code',
            'public spawn returns an SDK process with live standard streams'
        )
        Push-Location $nodeSuiteRoot
        try {
            $run = Invoke-LoggedNative -FilePath $node -LogName 'process-container-node-streaming.log' `
                -ArgumentList @('--test', '--test-force-exit',
                    '--test-name-pattern', ($requiredNodeTests -join '|'),
                    '--test-reporter=spec', '--test-reporter-destination=stdout',
                    '--test-reporter=junit', "--test-reporter-destination=$junit",
                    'dist/windows-process-container.test.js')
        } finally {
            Pop-Location
        }
        if ($run.ExitCode -ne 0) { throw "Node ProcessContainer streaming exited $($run.ExitCode)." }
        $failure = Get-NodeSuiteFailure -JunitPath $junit -RequiredTests $requiredNodeTests
        if ($failure) { throw "Node ProcessContainer streaming: $failure" }
    } finally {
        [Environment]::SetEnvironmentVariable('MXC_E2E_PSEC_CAPABLE_HOST', $previousPsec)
        [Environment]::SetEnvironmentVariable('MXC_SKIP_OS_BUILD_DEPENDENT_TESTS', $previousSkip)
    }
}

function Invoke-NodeIntegrationSuite {
    param(
        [Parameter(Mandatory)][string]$Bundle,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$TestFile
    )

    $junit = Join-Path $env:TEMP "$Name-node.junit.xml"
    Push-Location (Join-Path $Bundle 'sdk-integration')
    try {
        $run = Invoke-LoggedNative -FilePath (Join-Path $Bundle 'node\node.exe') -LogName "$Name-node.log" -ArgumentList @(
            '--test', '--test-force-exit',
            '--test-reporter=spec', '--test-reporter-destination=stdout',
            '--test-reporter=junit', "--test-reporter-destination=$junit",
            "dist/$TestFile")
    }
    finally {
        Pop-Location
    }
    if ($run.ExitCode -ne 0) { "exited $($run.ExitCode)" } else { Get-NodeSuiteFailure -JunitPath $junit }
}

function Invoke-XunitClasses {
    param(
        [Parameter(Mandatory)][string]$Bundle,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Classes
    )

    $resultXml = Join-Path $env:TEMP "$Name-dotnet.xml"
    $run = Invoke-LoggedNative -FilePath (Join-Path $Bundle 'dotnet\Microsoft.Mxc.Sdk.Tests.exe') -LogName "$Name-dotnet.log" -ArgumentList @(
        $Classes | ForEach-Object { '-class', "*.$_" }
        '-result-xml', $resultXml)
    if ($run.ExitCode -ne 0) { "exited $($run.ExitCode)" } else { Get-XunitSuiteFailure -ResultXml $resultXml -Classes $Classes }
}

# Run each named suite, report every result, then fail if any suite did.
function Invoke-NamedSuites {
    param(
        [Parameter(Mandatory)][string]$Backend,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Suites,
        [System.Collections.IDictionary]$Results = [ordered]@{},
        [scriptblock]$Finally = {}
    )

    try {
        foreach ($name in $Suites.Keys) {
            Write-Host "=== ${Backend}: $name ==="
            try {
                $Results[$name] = "$(& $Suites[$name])"
            }
            catch {
                $Results[$name] = $_.Exception.Message
            }
        }
    }
    finally {
        & $Finally $Results
    }

    foreach ($name in $Results.Keys) {
        if ($Results[$name]) {
            Write-Host "FAIL  $name`: $($Results[$name])" -ForegroundColor Red
        }
        else {
            Write-Host "PASS  $name" -ForegroundColor Green
        }
    }
    if (@($Results.Values | Where-Object { $_ }).Count -gt 0) {
        throw "$Backend validation failed; see the results above."
    }
}

function Invoke-WslcSuites {
    $bundle = Join-Path $binaryDirectoryPath 'windows-sdk-bundle'
    foreach ($file in 'dotnet\Microsoft.Mxc.Sdk.Tests.exe', 'node\node.exe', 'sdk-integration\dist\wslc-state-aware.test.js', 'sdk-integration\dist\wslc-e2e.test.js') {
        Assert-File -Path (Join-Path $bundle $file)
    }

    # The SDK suites skip unless asked to run, and a skip is reported as a
    # failure below.
    $env:MXC_ENABLE_WSLC_TESTS = '1'

    Invoke-NamedSuites -Backend 'wslc' -Suites ([ordered]@{
        'command line' = {
            $global:LASTEXITCODE = 0
            & (Join-Path $testScriptRoot 'run_wslc_all_tests.ps1') -WxcExecPath $wxc | Out-Host
            if ($LASTEXITCODE -ne 0) { "exited $LASTEXITCODE" }
        }
        'Node' = { Invoke-NodeIntegrationSuite -Bundle $bundle -Name 'wslc' -TestFile 'wslc-state-aware.test.js' }
        'Node create-and-run' = { Invoke-NodeIntegrationSuite -Bundle $bundle -Name 'wslc-create-and-run' -TestFile 'wslc-e2e.test.js' }
        'C#' = { Invoke-XunitClasses -Bundle $bundle -Name 'wslc' -Classes 'MxcLifecycleWslcE2ETests', 'MxcContainerWslcE2ETests' }
    })
}

function Invoke-IsolationSessionSuites {
    $bundle = Join-Path $binaryDirectoryPath 'windows-sdk-bundle'
    $inProcTests = Join-Path $bundle 'inproc\mxc-sdk-isolation-session-tests.exe'
    $helperTests = Join-Path $bundle 'inproc\mxc-sdk-helpers-tests.exe'
    $staProbe = Join-Path $bundle 'inproc\sta_probe.exe'
    foreach ($file in $inProcTests, $helperTests, $staProbe, (Join-Path $bundle 'dotnet\Microsoft.Mxc.Sdk.Tests.exe'), (Join-Path $bundle 'node\node.exe'), (Join-Path $bundle 'sdk-integration\dist\isolation-session-state-aware.test.js')) {
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
        'Node' = { Invoke-NodeIntegrationSuite -Bundle $bundle -Name 'isolation-session' -TestFile 'isolation-session-state-aware.test.js' }
        'Rust' = {
            Get-LibtestFailure (Invoke-LoggedNative -FilePath $inProcTests -ArgumentList '--test-threads=1' -LogName 'isolation-session-rust.log')
        }
        'Rust SDK helpers' = {
            Get-LibtestFailure (Invoke-LoggedNative -FilePath $helperTests -ArgumentList '--test-threads=1' -LogName 'isolation-session-rust-helpers.log')
        }
        'C#' = { Invoke-XunitClasses -Bundle $bundle -Name 'isolation-session' -Classes 'MxcContainerIsolationSessionE2ETests', 'MxcLifecycleE2ETests' }
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
    Invoke-NamedSuites -Backend 'isolation-session' -Suites $suites -Finally {
        param($results)
        $accountsAfter = @((Get-LocalUser).Name)
        $added = @($accountsAfter | Where-Object { $accountsBefore -notcontains $_ }).Count
        $removed = @($accountsBefore | Where-Object { $accountsAfter -notcontains $_ }).Count
        $results['local accounts'] = "before $($accountsBefore.Count), after $($accountsAfter.Count) (+$added, -$removed)"
        if ($added -eq 0 -and $removed -eq 0) {
            Write-Host "Local accounts: $($results['local accounts'])"
            $results['local accounts'] = ''
        }
    }
}

function Invoke-MicroVmTests {
    if ($Architecture -ne 'x64') {
        throw 'MicroVM validation requires x64.'
    }
    $tests = Join-Path $binaryDirectoryPath 'nvx-e2e-tests.exe'
    Assert-File -Path $tests
    $env:ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR = Join-Path $binaryDirectoryPath 'aci-edge-sandboxes'
    $run = Invoke-LoggedNative -FilePath $tests -LogName 'microvm-nvx.log' -ArgumentList @(
        '--include-ignored', '--nocapture', '--test-threads=1'
    )
    $failure = Get-LibtestFailure -Run $run
    if ($failure) {
        throw "MicroVM SDK tests $failure."
    }
    $output = Get-Content -LiteralPath $run.Log -Raw
    if ($output -match '\bSKIP(?:PED)?:' -or
        $output -notmatch '(?m)^test result: ok\. \d+ passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;') {
        throw 'MicroVM SDK validation skipped or filtered tests.'
    }
    $scenarios = [ordered]@{
        'facade' = 'VM_EXECUTED facade sequential '
        'executor' = 'VM_EXECUTED executor sequential '
        'executor configs' = 'VM_EXECUTED executor configs '
        'executor interruption' = 'VM_EXECUTED executor console interruption '
    }
    foreach ($scenario in $scenarios.Keys) {
        if (-not $output.Contains($scenarios[$scenario])) {
            throw "MicroVM SDK validation did not execute the $scenario VM scenario."
        }
    }
}

Redirect-Temp

switch ($Backend) {
    'process' { Invoke-ProcessContainerTests }
    'isolation-session' {
        Invoke-IsolationSessionSuites
    }
    'windows-sandbox' {
        Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_windows_sandbox_one_shot_tests.ps1') -Arguments @{
            BinDir = $binaryDirectoryPath
        }
    }
    'wslc' {
        Invoke-WslcSuites
    }
    'microvm' {
        Invoke-MicroVmTests
    }
}
