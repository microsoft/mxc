<#
.SYNOPSIS
Builds the Windows SDK test bundle for one Windows architecture.

.DESCRIPTION
Builds the IsolationSession and ProcessContainer streaming test payloads for
Rust, .NET, and Node, and the WSLC create-and-run and lifecycle payloads for
.NET and Node, stages the native dependencies and PowerShell suites, and checks
that every payload discovers its tests.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture,

    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [Parameter(Mandatory)]
    [string]$Pipeline,

    [Parameter(Mandatory)]
    [string]$BranchName,

    [Parameter(Mandatory)]
    [string]$SourceRef,

    [Parameter(Mandatory)]
    [string]$BuildId,

    [string]$Package,

    # Built with the isolation_session feature when not supplied.
    [string]$WxcExecPath,

    [string]$NuGetSource
)

$ErrorActionPreference = 'Stop'

$triple = @{ x64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }[$Architecture]
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$srcRoot = Join-Path $repoRoot 'src'
$nodeSdkRoot = Join-Path $repoRoot 'sdk\node'
$integrationRoot = Join-Path $nodeSdkRoot 'tests\integration'

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Command
    )

    $global:LASTEXITCODE = 0
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

# Paths come from cargo's report, so any target directory works.
function Invoke-CargoBuild {
    param([Parameter(Mandatory)][string[]]$Arguments)

    Push-Location $srcRoot
    try {
        $messages = Invoke-Checked "cargo $($Arguments -join ' ')" {
            cargo @Arguments --locked --release --target $triple --message-format=json
        }
    }
    finally {
        Pop-Location
    }
    $messages | ForEach-Object {
        try { $_ | ConvertFrom-Json -ErrorAction Stop } catch { }
    } | Where-Object { $_.reason -eq 'compiler-artifact' }
}

function Get-CargoExecutable {
    param([object[]]$Artifacts, [string]$TargetName)

    $path = $Artifacts |
        Where-Object { $_.target.name -eq $TargetName -and $_.executable } |
        Select-Object -Last 1 -ExpandProperty executable
    if (-not $path) {
        throw "cargo reported no executable for $TargetName."
    }
    $path
}

function New-Directory {
    param([Parameter(Mandatory)][string]$Path)

    (New-Item -ItemType Directory -Force -Path $Path).FullName
}

if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
$OutputDirectory = New-Directory $OutputDirectory

$sdkPackage = @('-p', 'mxc-sdk', '--features', 'isolation_session')
if (-not $WxcExecPath) {
    $WxcExecPath = Get-CargoExecutable (Invoke-CargoBuild @('build', '-p', 'wxc', '--features', 'isolation_session')) 'wxc-exec'
}
$testArtifacts = Invoke-CargoBuild (@('test') + $sdkPackage + @(
    '--test', 'isolation_session', '--test', 'sdk_helpers',
    '--test', 'streaming_processcontainer', '--no-run'))
$probeArtifacts = Invoke-CargoBuild (@('build') + $sdkPackage + @('--example', 'sta_probe'))
$nativeLibrary = Invoke-CargoBuild @('build', '-p', 'mxc_ffi', '--features', 'isolation_session,wslc') |
    Where-Object { $_.target.name -eq 'mxc_ffi' } |
    ForEach-Object { $_.filenames } |
    Where-Object { [IO.Path]::GetExtension($_) -eq '.dll' } |
    Select-Object -Last 1
if (-not $nativeLibrary) {
    throw 'cargo reported no mxc_ffi.dll.'
}
$wslcDaemon = Get-CargoExecutable (Invoke-CargoBuild @('build', '-p', 'mxc-sdk', '--features', 'wslc', '--bin', 'wxc-wslc-daemon')) 'wxc-wslc-daemon'

# The wslc build feature stages the WSLC SDK library beside mxc_ffi.
$wslcSdk = Join-Path (Split-Path -Parent $nativeLibrary) 'wslcsdk.dll'

$sdkBin = New-Directory (Join-Path $nodeSdkRoot "bin\$Architecture")
$retiredPlm = Join-Path $sdkBin 'plm.exe'
if (Test-Path -LiteralPath $retiredPlm) { Remove-Item -LiteralPath $retiredPlm }
Copy-Item -LiteralPath $WxcExecPath, $nativeLibrary, $wslcDaemon, $wslcSdk -Destination $sdkBin -Force
foreach ($project in $nodeSdkRoot, $integrationRoot) {
    Push-Location $project
    try {
        Invoke-Checked "npm ci in $project" { npm ci }
        Invoke-Checked "npm run build in $project" { npm run build }
    }
    finally {
        Pop-Location
    }
}

$dotnetOut = Join-Path $OutputDirectory 'dotnet'
$publish = @(
    'publish', (Join-Path $repoRoot 'sdk\dotnet\Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj'),
    '-c', 'Release', '-r', "win-$Architecture", '-p:MxcWithIsolationSession=true', '-p:MxcWithWslc=true',
    '--self-contained', 'true', '-o', $dotnetOut, '--nologo'
)
if ($NuGetSource) {
    $publish += @('--source', $NuGetSource)
}
Invoke-Checked 'dotnet publish' { dotnet @publish }

Copy-Item -LiteralPath $WxcExecPath -Destination (New-Directory (Join-Path $OutputDirectory "bin\$Architecture"))

$inproc = New-Directory (Join-Path $OutputDirectory 'inproc')
$finalPathProbe = Join-Path $inproc 'mxc-final-path-probe.exe'
$finalPathSource = Join-Path $repoRoot 'tests\regression_tests\test_cases\data\Issue694-FinalPathProbe.cs'
$fixtureCompiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $fixtureCompiler -PathType Leaf)) {
    throw "The inbox .NET Framework compiler is required: $fixtureCompiler"
}
Invoke-Checked 'Building the native final-path fixture' {
    & $fixtureCompiler /nologo /target:exe /platform:anycpu "/out:$finalPathProbe" $finalPathSource
}
Copy-Item -LiteralPath (Get-CargoExecutable $testArtifacts 'isolation_session') -Destination (Join-Path $inproc 'mxc-sdk-isolation-session-tests.exe')
Copy-Item -LiteralPath (Get-CargoExecutable $testArtifacts 'sdk_helpers') -Destination (Join-Path $inproc 'mxc-sdk-helpers-tests.exe')
Copy-Item -LiteralPath (Get-CargoExecutable $testArtifacts 'streaming_processcontainer') -Destination (Join-Path $inproc 'mxc-sdk-process-container-streaming-tests.exe')
Copy-Item -LiteralPath (Get-CargoExecutable $probeArtifacts 'sta_probe') -Destination (Join-Path $inproc 'sta_probe.exe')

$nodeExe = (Get-Command node -CommandType Application | Select-Object -First 1).Source
Copy-Item -LiteralPath $nodeExe, (Join-Path (Split-Path -Parent $nodeExe) 'LICENSE') -Destination (New-Directory (Join-Path $OutputDirectory 'node'))

Copy-Item -Path (Join-Path $repoRoot 'tests\configs\isolation_session_*.json') -Destination (New-Directory (Join-Path $OutputDirectory 'test_configs'))
$scriptsOut = New-Directory (Join-Path $OutputDirectory 'test_scripts')
foreach ($name in 'run_isolation_session_tests.ps1', 'run_isolation_session_state_aware_tests.ps1', 'run_isolation_session_resize_smoke.ps1') {
    Copy-Item -LiteralPath (Join-Path $repoRoot "tests\scripts\$name") -Destination $scriptsOut
}
$helperPaths = @(& (Join-Path $PSScriptRoot 'stage-isolation-session-test-helpers.ps1') `
    -SourceDirectory (Join-Path $repoRoot 'tests\scripts') -ScriptsDirectory $scriptsOut)

$integrationOut = New-Directory (Join-Path $OutputDirectory 'sdk-integration')
Copy-Item -Path (Join-Path $integrationRoot 'dist\isolation-session-*.test.js'), (Join-Path $integrationRoot 'dist\windows-process-container.test.js'), (Join-Path $integrationRoot 'dist\wslc-state-aware.test.js'), (Join-Path $integrationRoot 'dist\wslc-e2e.test.js'), (Join-Path $integrationRoot 'dist\test-helpers.js') -Destination (New-Directory (Join-Path $integrationOut 'dist'))
Copy-Item -LiteralPath (Join-Path $integrationRoot 'package.json'), (Join-Path $integrationRoot 'run-tests.js') -Destination $integrationOut
# Stages the SDK built above in place of the installed copy.
$modulesOut = New-Directory (Join-Path $integrationOut 'node_modules')
Get-ChildItem -LiteralPath (Join-Path $integrationRoot 'node_modules') -Force |
    Where-Object Name -ne '@microsoft' |
    Copy-Item -Destination $modulesOut -Recurse -Force
$sdkOut = New-Directory (Join-Path $modulesOut '@microsoft\mxc-sdk')
foreach ($name in 'bin', 'dist', 'node_modules', 'package.json', 'LICENSE.md') {
    $source = Join-Path $nodeSdkRoot $name
    if (Test-Path -LiteralPath $source) {
        Copy-Item -LiteralPath $source -Destination $sdkOut -Recurse -Force
    }
}

$manifest = [ordered]@{
    format_version = 1
    produced_at    = [DateTime]::UtcNow.ToString('o')
    branch_name    = $BranchName
    source_ref     = $SourceRef
    commit_sha     = (git -C $repoRoot rev-parse HEAD).Trim()
    build_id       = $BuildId
    pipeline       = $Pipeline
    triplet        = $triple
    features       = @('isolation_session', 'wslc', 'dotnetsdk', 'node-sdk-integration')
}
if ($Package) {
    $manifest['package'] = $Package
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8

$required = @(
    'manifest.json',
    "bin\$Architecture\wxc-exec.exe",
    'inproc\mxc-sdk-isolation-session-tests.exe',
    'inproc\mxc-sdk-helpers-tests.exe',
    'inproc\mxc-sdk-process-container-streaming-tests.exe',
    'inproc\mxc-final-path-probe.exe',
    'inproc\sta_probe.exe',
    'dotnet\Microsoft.Mxc.Sdk.Tests.exe',
    'dotnet\mxc_ffi.dll',
    'dotnet\wxc-wslc-daemon.exe',
    'dotnet\wslcsdk.dll',
    'node\node.exe',
    'node\LICENSE',
    'sdk-integration\package.json',
    'sdk-integration\run-tests.js',
    'sdk-integration\dist\isolation-session-state-aware.test.js',
    'sdk-integration\dist\windows-process-container.test.js',
    'sdk-integration\dist\wslc-state-aware.test.js',
    'sdk-integration\dist\wslc-e2e.test.js',
    "sdk-integration\node_modules\@microsoft\mxc-sdk\bin\$Architecture\wxc-wslc-daemon.exe",
    "sdk-integration\node_modules\@microsoft\mxc-sdk\bin\$Architecture\wslcsdk.dll",
    'test_scripts\run_isolation_session_tests.ps1',
    'test_scripts\run_isolation_session_state_aware_tests.ps1',
    'test_scripts\run_isolation_session_resize_smoke.ps1'
)
$required += @($helperPaths | ForEach-Object { Join-Path 'test_scripts' $_ })
foreach ($relativePath in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory $relativePath) -PathType Leaf)) {
        throw "The bundle is missing $relativePath."
    }
}
if (-not (Get-ChildItem -LiteralPath (Join-Path $OutputDirectory 'test_configs') -Filter '*.json')) {
    throw 'The bundle has no isolation-session test configs.'
}

function Assert-Discovery {
    param(
        [Parameter(Mandatory)][string]$Payload,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][scriptblock]$Command
    )

    $output = @(Invoke-Checked "Listing the $Payload" $Command)
    $output | ForEach-Object { Write-Host $_ }
    if (($output -join "`n") -notmatch $Pattern) {
        throw "The $Payload discovered no tests."
    }
}

Assert-Discovery 'in-process tests' '(?m)^[1-9][0-9]* tests, 0 benchmarks\r?$' {
    & (Join-Path $inproc 'mxc-sdk-isolation-session-tests.exe') --list
}
Assert-Discovery 'SDK helper tests' '(?m)^[1-9][0-9]* tests, 0 benchmarks\r?$' {
    & (Join-Path $inproc 'mxc-sdk-helpers-tests.exe') --list
}
Assert-Discovery 'ProcessContainer streaming test' '(?m)^streaming_processcontainer_bidirectional_stdio: test\r?$' {
    & (Join-Path $inproc 'mxc-sdk-process-container-streaming-tests.exe') --list --ignored --exact streaming_processcontainer_bidirectional_stdio
}
Assert-Discovery '.NET tests' 'Microsoft\.Mxc\.Sdk\.Tests' {
    & (Join-Path $dotnetOut 'Microsoft.Mxc.Sdk.Tests.exe') -list full
}
Assert-Discovery '.NET streaming tests' 'MxcProcessTests\.Streaming_WritesStdin_AndReadsEchoedStdout' {
    & (Join-Path $dotnetOut 'Microsoft.Mxc.Sdk.Tests.exe') -list full -class '*.MxcProcessTests'
}
Assert-Discovery '.NET WSLC lifecycle tests' 'MxcLifecycleWslcE2ETests\.' {
    & (Join-Path $dotnetOut 'Microsoft.Mxc.Sdk.Tests.exe') -list full -class '*.MxcLifecycleWslcE2ETests'
}
Assert-Discovery '.NET WSLC create-and-run tests' 'MxcContainerWslcE2ETests\.' {
    & (Join-Path $dotnetOut 'Microsoft.Mxc.Sdk.Tests.exe') -list full -class '*.MxcContainerWslcE2ETests'
}
Push-Location $integrationOut
$env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS = '1'
try {
    Assert-Discovery 'Node SDK integration suite' '(?m)^[^A-Za-z0-9]*tests\s+[1-9][0-9]*\r?$' {
        & (Join-Path $OutputDirectory 'node\node.exe') --test --test-force-exit dist/isolation-session-state-aware.test.js
    }
    Assert-Discovery 'Node ProcessContainer suite' '(?m)^[^A-Za-z0-9]*tests\s+[1-9][0-9]*\r?$' {
        & (Join-Path $OutputDirectory 'node\node.exe') --test --test-force-exit dist/windows-process-container.test.js
    }
    Assert-Discovery 'Node WSLC lifecycle suite' 'WSLC state-aware lifecycle E2E' {
        & (Join-Path $OutputDirectory 'node\node.exe') --test --test-force-exit dist/wslc-state-aware.test.js
    }
    Assert-Discovery 'Node WSLC create-and-run suite' 'WSLC SDK E2E' {
        & (Join-Path $OutputDirectory 'node\node.exe') --test --test-force-exit dist/wslc-e2e.test.js
    }
}
finally {
    Remove-Item Env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS
    Pop-Location
}

$ErrorActionPreference = 'Continue'
$global:LASTEXITCODE = 0
$probeOutput = (& (Join-Path $inproc 'sta_probe.exe') invalid 2>&1 | ForEach-Object { "$_" }) -join "`n"
$probeExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($probeExit -ne 2 -or $probeOutput -notmatch 'unknown mode: invalid') {
    throw "The packaged apartment probe did not start (exit $probeExit): $probeOutput"
}
$global:LASTEXITCODE = 0

Write-Host "Windows SDK test bundle for $Architecture staged at $OutputDirectory"
