<#
.SYNOPSIS
Builds the isolation-session test bundle for one Windows architecture.

.DESCRIPTION
The one recipe for the bundle, used by scheduled validation and by the Azure
Pipelines job that feeds the Windows OS vpack.

Builds the in-process Rust tests, the apartment probe, the self-contained .NET
SDK tests and the Node SDK integration suite from -SourceRoot, stages them
beside wxc-exec, a Node runtime, the PowerShell suites and the suite runner,
and checks that every payload discovers its tests.

-Phase Build stages the bundle and -Phase Validate checks it, so a pipeline
can sign the staged binaries in between. The script runs from any checkout
and only reads -SourceRoot, so one checkout's recipe can build another
branch.
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

    # The checkout to build. Defaults to the checkout holding this script.
    [string]$SourceRoot,

    [ValidateSet('All', 'Build', 'Validate')]
    [string]$Phase = 'All',

    # Built with the isolation_session feature when not supplied.
    [string]$WxcExecPath,

    # The Node runtime to ship. Defaults to node on PATH.
    [string]$NodeRuntimePath,

    [string]$NuGetSource
)

$ErrorActionPreference = 'Stop'

$triple = @{ x64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }[$Architecture]
# Windows PowerShell does not set $PSScriptRoot for parameter defaults.
if (-not $SourceRoot) {
    $SourceRoot = Join-Path $PSScriptRoot '..\..'
}
$repoRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
$srcRoot = Join-Path $repoRoot 'src'
$nodeSdkRoot = Join-Path $repoRoot 'sdk\node'
$integrationRoot = Join-Path $nodeSdkRoot 'tests\integration'
$dotnetTestProject = Join-Path $repoRoot 'sdk\dotnet\Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj'
$runnerName = 'run_isolation_session_suites.ps1'

# Older sources predate these payloads; the bundle carries them when present.
$hasSdkHelperTests = Test-Path -LiteralPath (Join-Path $srcRoot 'core\mxc-sdk\tests\sdk_helpers.rs') -PathType Leaf
$hasSuiteRunner = Test-Path -LiteralPath (Join-Path $repoRoot "tests\scripts\$runnerName") -PathType Leaf

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
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$DebugProfile
    )

    [string[]]$profileArgs = if ($DebugProfile) { @() } else { @('--release') }
    Push-Location $srcRoot
    try {
        $messages = Invoke-Checked "cargo $($Arguments -join ' ')" {
            cargo @Arguments --locked @profileArgs --target $triple --message-format=json
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

function Get-CargoLibrary {
    param([object[]]$Artifacts, [string]$TargetName)

    $path = $Artifacts |
        Where-Object { $_.target.name -eq $TargetName } |
        ForEach-Object { $_.filenames } |
        Where-Object { [IO.Path]::GetExtension($_) -eq '.dll' } |
        Select-Object -Last 1
    if (-not $path) {
        throw "cargo reported no $TargetName.dll."
    }
    $path
}

function New-Directory {
    param([Parameter(Mandatory)][string]$Path)

    (New-Item -ItemType Directory -Force -Path $Path).FullName
}

function Build-Bundle {
    if (Test-Path -LiteralPath $OutputDirectory) {
        Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
    }
    $out = New-Directory $OutputDirectory

    $sdkPackage = @('-p', 'mxc-sdk', '--features', 'isolation_session')
    if (-not $WxcExecPath) {
        $WxcExecPath = Get-CargoExecutable (Invoke-CargoBuild @('build', '-p', 'wxc', '--features', 'isolation_session')) 'wxc-exec'
    }
    $testTargets = @('--test', 'isolation_session')
    if ($hasSdkHelperTests) {
        $testTargets += @('--test', 'sdk_helpers')
    }
    $testArtifacts = Invoke-CargoBuild (@('test') + $sdkPackage + $testTargets + @('--no-run'))
    $probeArtifacts = Invoke-CargoBuild (@('build') + $sdkPackage + @('--example', 'sta_probe'))
    $nodeNative = Get-CargoLibrary (Invoke-CargoBuild @('build', '-p', 'mxc_ffi', '--features', 'isolation_session')) 'mxc_ffi'

    # The .NET tests load a debug build: test isolation overrides compile only
    # with debug assertions. Its own target directory keeps it from replacing
    # the release library the Node SDK ships.
    $targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $srcRoot 'target' }
    $dotnetNative = Get-CargoLibrary (Invoke-CargoBuild -DebugProfile @(
            'build', '-p', 'mxc_ffi', '--features', 'dotnetsdk,test-support,isolation_session',
            '--target-dir', "$targetDir-dotnet-test-support")) 'mxc_ffi'

    $sdkBin = New-Directory (Join-Path $nodeSdkRoot "bin\$Architecture")
    Copy-Item -LiteralPath $WxcExecPath, $nodeNative -Destination $sdkBin -Force
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

    $dotnetOut = Join-Path $out 'dotnet'
    $publish = @(
        'publish', $dotnetTestProject,
        '-c', 'Release', '-r', "win-$Architecture", '-p:MxcWithIsolationSession=true',
        '--self-contained', 'true', '-o', $dotnetOut, '--nologo'
    )
    # Projects that accept a prebuilt library skip building their own.
    $acceptsPrebuilt = Select-String -LiteralPath $dotnetTestProject -Pattern 'MxcTestPrebuiltNativeLibrary' -SimpleMatch -Quiet
    if ($acceptsPrebuilt) {
        $publish += "-p:MxcTestPrebuiltNativeLibrary=$dotnetNative"
    }
    if ($NuGetSource) {
        $publish += @('--source', $NuGetSource)
    }
    Invoke-Checked 'dotnet publish' { dotnet @publish }
    Copy-Item -LiteralPath $dotnetNative -Destination (Join-Path $dotnetOut 'mxc_ffi.dll') -Force

    Copy-Item -LiteralPath $WxcExecPath -Destination (New-Directory (Join-Path $out "bin\$Architecture"))

    $inproc = New-Directory (Join-Path $out 'inproc')
    Copy-Item -LiteralPath (Get-CargoExecutable $testArtifacts 'isolation_session') -Destination (Join-Path $inproc 'mxc-sdk-isolation-session-tests.exe')
    if ($hasSdkHelperTests) {
        Copy-Item -LiteralPath (Get-CargoExecutable $testArtifacts 'sdk_helpers') -Destination (Join-Path $inproc 'mxc-sdk-helpers-tests.exe')
    }
    Copy-Item -LiteralPath (Get-CargoExecutable $probeArtifacts 'sta_probe') -Destination (Join-Path $inproc 'sta_probe.exe')

    $nodeExe = if ($NodeRuntimePath) { $NodeRuntimePath } else { (Get-Command node -CommandType Application | Select-Object -First 1).Source }
    $nodeLicense = Join-Path (Split-Path -Parent $nodeExe) 'LICENSE'
    if (-not (Test-Path -LiteralPath $nodeLicense -PathType Leaf)) {
        throw "Node.js license not found beside $nodeExe."
    }
    Copy-Item -LiteralPath $nodeExe, $nodeLicense -Destination (New-Directory (Join-Path $out 'node'))

    Copy-Item -Path (Join-Path $repoRoot 'tests\configs\isolation_session_*.json') -Destination (New-Directory (Join-Path $out 'test_configs'))
    $scriptsOut = New-Directory (Join-Path $out 'test_scripts')
    $scripts = @('run_isolation_session_tests.ps1', 'run_isolation_session_state_aware_tests.ps1', 'run_isolation_session_resize_smoke.ps1')
    if ($hasSuiteRunner) {
        $scripts += $runnerName
    }
    foreach ($name in $scripts) {
        Copy-Item -LiteralPath (Join-Path $repoRoot "tests\scripts\$name") -Destination $scriptsOut
    }

    $integrationOut = New-Directory (Join-Path $out 'sdk-integration')
    Copy-Item -Path (Join-Path $integrationRoot 'dist\isolation-session-*.test.js'), (Join-Path $integrationRoot 'dist\test-helpers.js') -Destination (New-Directory (Join-Path $integrationOut 'dist'))
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
        features       = @('isolation_session', 'dotnetsdk', 'test-support', 'node-sdk-integration')
    }
    if ($Package) {
        $manifest['package'] = $Package
    }
    if ($hasSuiteRunner) {
        $manifest['suite_runner'] = "test_scripts/$runnerName"
        $manifest['suites'] = @(& (Join-Path $scriptsOut $runnerName) -List -BundleRoot $out)
    }
    $manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $out 'manifest.json') -Encoding utf8
}

function Test-Bundle {
    $out = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $inproc = Join-Path $out 'inproc'

    $required = @(
        'manifest.json',
        "bin\$Architecture\wxc-exec.exe",
        'inproc\mxc-sdk-isolation-session-tests.exe',
        'inproc\sta_probe.exe',
        'dotnet\Microsoft.Mxc.Sdk.Tests.exe',
        'dotnet\mxc_ffi.dll',
        'dotnet\plm.exe',
        'node\node.exe',
        'node\LICENSE',
        'sdk-integration\package.json',
        'sdk-integration\run-tests.js',
        'sdk-integration\dist\isolation-session-state-aware.test.js',
        'test_scripts\run_isolation_session_tests.ps1',
        'test_scripts\run_isolation_session_state_aware_tests.ps1',
        'test_scripts\run_isolation_session_resize_smoke.ps1'
    )
    if ($hasSdkHelperTests) {
        $required += 'inproc\mxc-sdk-helpers-tests.exe'
    }
    if ($hasSuiteRunner) {
        $required += "test_scripts\$runnerName"
    }
    foreach ($relativePath in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $out $relativePath) -PathType Leaf)) {
            throw "The bundle is missing $relativePath."
        }
    }
    if (-not (Get-ChildItem -LiteralPath (Join-Path $out 'test_configs') -Filter '*.json')) {
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
    if ($hasSdkHelperTests) {
        Assert-Discovery 'SDK helper tests' '(?m)^[1-9][0-9]* tests, 0 benchmarks\r?$' {
            & (Join-Path $inproc 'mxc-sdk-helpers-tests.exe') --list
        }
    }
    $dotnetTests = Join-Path $out 'dotnet\Microsoft.Mxc.Sdk.Tests.exe'
    Assert-Discovery '.NET tests' 'Microsoft\.Mxc\.Sdk\.Tests' {
        & $dotnetTests -list full
    }
    # These need no backend, and fail unless the packaged native library was
    # built with test-support.
    Invoke-Checked 'The packaged .NET telemetry tests' {
        & $dotnetTests -class 'Microsoft.Mxc.Sdk.Tests.MxcTelemetryTests' -noLogo
    }
    Push-Location (Join-Path $out 'sdk-integration')
    $env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS = '1'
    try {
        Assert-Discovery 'Node SDK integration suite' '(?m)^[^A-Za-z0-9]*tests\s+[1-9][0-9]*\r?$' {
            & (Join-Path $out 'node\node.exe') --test --test-force-exit dist/isolation-session-state-aware.test.js
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

    if ($hasSuiteRunner) {
        $listed = @(& (Join-Path $out "test_scripts\$runnerName") -List -BundleRoot $out)
        $declared = @((Get-Content -LiteralPath (Join-Path $out 'manifest.json') -Raw | ConvertFrom-Json).suites)
        if (-not $listed -or ($listed -join ',') -ne ($declared -join ',')) {
            throw "The suite runner lists '$($listed -join ', ')' but the manifest declares '$($declared -join ', ')'."
        }
        Write-Host "Suites: $($listed -join ', ')"
    }
    $global:LASTEXITCODE = 0
}

if ($Phase -in 'All', 'Build') {
    Build-Bundle
}
if ($Phase -in 'All', 'Validate') {
    Test-Bundle
}

Write-Host "Isolation-session test bundle for $Architecture ($Phase) at $OutputDirectory"