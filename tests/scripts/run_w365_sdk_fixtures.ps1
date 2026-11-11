# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Offline only: all SDK service calls go to the Rust fixture's loopback TLS server.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$saved = @{}
foreach ($key in 'MXC_FFI_DIR', 'MXC_W365_TEST_SDK_COMMAND', 'MXC_W365_TEST_APP_COMMAND') {
    $saved[$key] = [Environment]::GetEnvironmentVariable($key)
}
Push-Location (Join-Path $root 'src')
try {
    cargo build --locked -p mxc_ffi --features dotnetsdk,test-support --target-dir target\w365-sdk-fixture
    if ($LASTEXITCODE -ne 0) { throw 'W365 fixture FFI build failed.' }
    $native = (Resolve-Path target\w365-sdk-fixture\debug).Path
    $env:MXC_FFI_DIR = $native
    $fixture = 'backend_modules::w365agents::tests::sdk_lifecycle::sdk_fresh_caller_fixture'
    $names = @(cargo test --locked -p mxc-sdk --lib --target-dir target\w365-sdk-fixture -- --list)
    if ($LASTEXITCODE -ne 0 -or $names -notcontains "${fixture}: test") {
        throw 'Missing required public SDK fixture orchestrator.'
    }
    if ($names -notcontains 'backend_modules::w365agents::tests::execution::execution_sdk_fresh_caller_fixture: test') {
        throw 'Missing required public SDK execution fixture.'
    }
    if ($names -notcontains 'backend_modules::w365agents::tests::execution::test_app_fresh_caller_fixture: test') {
        throw 'Missing required C# application fixture.'
    }
    $project = Join-Path $root 'sdk\dotnet\Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj'
    dotnet build $project -f net10.0 "-p:MxcPrebuiltNativeDir=$native" `
        "-p:MxcTestPrebuiltNativeLibrary=$native\mxc_ffi.dll" --nologo
    if ($LASTEXITCODE -ne 0) { throw 'W365 managed SDK test build failed.' }
    $caller = Join-Path $root 'sdk\dotnet\Microsoft.Mxc.Sdk.Tests\bin\Debug\net10.0\Microsoft.Mxc.Sdk.Tests.dll'
    $env:MXC_W365_TEST_SDK_COMMAND = ConvertTo-Json -Compress -InputObject @(
        'dotnet', $caller, '-class', '*.W365DevSdkFixtureTests'
    )
    cargo test --locked -p mxc-sdk --lib --target-dir target\w365-sdk-fixture sdk_fresh_caller_fixture -- --ignored --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'W365 public .NET SDK fixture failed.' }

    Push-Location (Join-Path $root 'sdk\node')
    try {
        if (-not (Test-Path node_modules)) {
            npm ci --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) { throw 'Node SDK dependency restore failed.' }
        }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Node SDK build failed.' }
    }
    finally { Pop-Location }
    $env:MXC_W365_TEST_SDK_COMMAND = ConvertTo-Json -Compress -InputObject @(
        'node', (Join-Path $root 'sdk\node\tests\w365-dev-sdk-fixture.mjs')
    )
    cargo test --locked -p mxc-sdk --lib --target-dir target\w365-sdk-fixture sdk_fresh_caller_fixture -- --ignored --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'W365 public Node SDK fixture failed.' }

    $appProject = Join-Path $root 'tests\tools\w365\W365SdkTestApp.Tests\W365SdkTestApp.Tests.csproj'
    dotnet build $appProject "-p:MxcPrebuiltNativeDir=$native" `
        "-p:MxcTestPrebuiltNativeLibrary=$native\mxc_ffi.dll" --nologo
    if ($LASTEXITCODE -ne 0) { throw 'W365 C# test-app fixture build failed.' }
    $appCaller = Join-Path $root 'tests\tools\w365\W365SdkTestApp.Tests\bin\Debug\net10.0\W365SdkTestApp.Tests.dll'
    dotnet $appCaller -method- '*PublicSdkAppAgainstTrustedTlsFixture*'
    if ($LASTEXITCODE -ne 0) { throw 'W365 test-app offline regressions failed.' }
    $env:MXC_W365_TEST_APP_COMMAND = ConvertTo-Json -Compress -InputObject @(
        'dotnet', $appCaller, '-method', '*PublicSdkAppAgainstTrustedTlsFixture'
    )
    cargo test --locked -p mxc-sdk --lib --target-dir target\w365-sdk-fixture test_app_fresh_caller_fixture -- --ignored --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'W365 C# test-app public SDK fixture failed.' }
}
finally {
    Pop-Location
    foreach ($key in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($key, $saved[$key])
    }
}
