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
        'microvm',
        'hyperlight'
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
    param()

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

    $script = Join-Path $testScriptRoot 'WinProcessContainer-Tests.ps1'
    # -KeepArtifacts stops the harness deleting its scratch tree on a clean
    # run, so a passing job still uploads its per-test logs and configs.
    # Skip build and Cargo phases because this job consumes a previously
    # built artifact; retain the host and containment behavior phases.
    $phases = @(
        'Probes',
        'T3Forced',
        'T1DenyForced',
        'UiMitigationMatrix',
        'GlobalAtomIsolation',
        'DaclDisabled',
        'CrashRecovery'
    )
    $global:LASTEXITCODE = 0
    & $script `
        -SkipBuild `
        -SkipReleaseLane `
        -WxcDebug (Join-Path $debugDirectory 'wxc-exec.exe') `
        -WxcRelease (Join-Path $releaseDirectory 'wxc-exec.exe') `
        -UiProbeDebug (Join-Path $debugDirectory 'wxc-ui-probe.exe') `
        -UiProbeRelease (Join-Path $releaseDirectory 'wxc-ui-probe.exe') `
        -KeepArtifacts `
        -Phases $phases | Out-Null
    return $LASTEXITCODE
}

function Invoke-T3WorkloadTests {
    [OutputType([int])]
    param()

    $script = Join-Path $testScriptRoot 'T3-Workloads.ps1'
    # -Wxc is required: the script's default points at a debug build that does
    # not exist in a CI artifact. -KeepArtifacts preserves the per-workload
    # logs and configs on a clean run so a passing job still uploads them.
    $global:LASTEXITCODE = 0
    & $script -Wxc $wxc -KeepArtifacts | Out-Null
    return $LASTEXITCODE
}

Redirect-TempToRunnerTemp

switch ($Backend) {
    'process-t1' {
        $primitives = Invoke-ProcessContainerTests
        if ($primitives -ne 0) {
            throw "Process Container tests failed with exit code $primitives."
        }
    }
    'process-t3' {
        # Run both suites before reporting. Stopping at the first failure would
        # hide the other suite's result, costing an extra nightly run to triage.
        $primitives = Invoke-ProcessContainerTests
        $workloads = Invoke-T3WorkloadTests
        if ($primitives -ne 0 -or $workloads -ne 0) {
            throw "process-t3 tests failed (primitives exit=$primitives, workloads exit=$workloads)."
        }
    }
    'isolation-session' {
        Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_isolation_session_tests.ps1') -Arguments @{
            WxcExePath = $wxc
        }
    }
    'windows-sandbox' {
        Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_windows_sandbox_one_shot_tests.ps1') -Arguments @{
            BinDir = $binaryDirectoryPath
        }
    }
    'wslc' {
        # The current WSLC helper hardcodes the x64 target when locating assets.
        if ($Architecture -ne 'x64') {
            throw 'The existing WSLC test harness is not architecture-portable yet.'
        }
        Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_wslc_all_tests.ps1') -Arguments @{
            WxcExecPath = $wxc
        }
    }
    'microvm' {
        Invoke-TestScript -Path (Join-Path $testScriptRoot 'run_microvm_tests.ps1') -Arguments @{
            BinDir = $binaryDirectoryPath
        }
    }
    'hyperlight' {
        # Keep unwired backends explicit so accidental activation fails loudly.
        throw 'The Hyperlight CI backend is not wired to an existing test entry point yet.'
    }
}
