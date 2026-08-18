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
$binaryDirectoryPath = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$wxc = Join-Path $binaryDirectoryPath 'wxc-exec.exe'

function Assert-File {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required CI artifact file is missing: $Path"
    }
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

    $script = Join-Path $scriptRoot 'WinProcessContainer-Tests.ps1'
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
        -Phases $phases
    if ($LASTEXITCODE -ne 0) {
        throw "Process Container tests failed with exit code $LASTEXITCODE."
    }
}

switch ($Backend) {
    'process-t1' {
        Invoke-ProcessContainerTests
    }
    'process-t3' {
        Invoke-ProcessContainerTests
    }
    'isolation-session' {
        Invoke-TestScript -Path (Join-Path $scriptRoot 'run_isolation_session_tests.ps1') -Arguments @{
            WxcExePath = $wxc
        }
    }
    'windows-sandbox' {
        Invoke-TestScript -Path (Join-Path $scriptRoot 'run_windows_sandbox_one_shot_tests.ps1') -Arguments @{
            BinDir = $binaryDirectoryPath
        }
    }
    'wslc' {
        # The current WSLC helper hardcodes the x64 target when locating assets.
        if ($Architecture -ne 'x64') {
            throw 'The existing WSLC test harness is not architecture-portable yet.'
        }
        Invoke-TestScript -Path (Join-Path $scriptRoot 'run_wslc_all_tests.ps1') -Arguments @{
            WxcExecPath = $wxc
        }
    }
    'microvm' {
        Invoke-TestScript -Path (Join-Path $scriptRoot 'run_microvm_tests.ps1') -Arguments @{
            BinDir = $binaryDirectoryPath
        }
    }
    'hyperlight' {
        # Keep unwired backends explicit so accidental activation fails loudly.
        throw 'The Hyperlight CI backend is not wired to an existing test entry point yet.'
    }
}
