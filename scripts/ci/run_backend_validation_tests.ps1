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
    $probe = & $wxc --probe | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "ProcessContainer probe failed with exit code $LASTEXITCODE."
    }
    if (-not $probe.probes.baseContainerUsable -or $probe.tier -ne 'base-container') {
        throw 'ProcessContainer CI requires an enabled native PSEC or SBOX contract.'
    }

    $scratch = Join-Path $env:TEMP 'mxc-native-process-container-ci'
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null
    $configPath = Join-Path $scratch 'config.json'
    @{
        version = '0.8.0-alpha'
        containment = 'processcontainer'
        process = @{
            commandLine = 'cmd.exe /d /s /c "echo native-process-container-ok"'
            cwd = $scratch
        }
        filesystem = @{
            readwritePaths = @($scratch)
        }
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath

    & $wxc $configPath
    if ($LASTEXITCODE -ne 0) {
        throw "Native ProcessContainer smoke test failed with exit code $LASTEXITCODE."
    }
}

Redirect-TempToRunnerTemp

switch ($Backend) {
    'process' { Invoke-ProcessContainerTests }
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
