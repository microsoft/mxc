#Requires -Version 7.0

<#
.SYNOPSIS
    Contract tests for CopilotCliMxcBuild module. Validates dependency
    rewriting, ambiguous-input rejection, and manifest sanitization without
    private CLI source access.

.DESCRIPTION
    Creates synthetic CLI and MXC Cargo manifests under a unique temp directory,
    imports the module, and asserts:
    - One dependency is rewritten correctly
    - A missing dependency fails
    - Duplicate dependencies fail
    - The manifest contains no temp path or canary secret
    - runtimeHashesMatch is true only for equal hashes
    - Invalid roots fail before unrelated paths are changed
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "copilot-cli-mxc-test-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$passed = 0
$failed = 0
$errors = [System.Collections.Generic.List[string]]::new()
$originalCanary = [System.Environment]::GetEnvironmentVariable('GHCP_CLI_SOURCE_READ', 'Process')

function New-TestDirectory {
    param([string]$Name)
    $dir = Join-Path $testRoot $Name
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
    return $dir
}

function Assert-Throws {
    param(
        [string]$TestName,
        [scriptblock]$ScriptBlock,
        [string]$ExpectedPattern = ''
    )
    try {
        & $ScriptBlock
        $script:failed++
        $script:errors.Add("$TestName : Expected exception but none was thrown")
        Write-Host "  FAIL: $TestName (no exception)"
    }
    catch {
        if ($ExpectedPattern -and $_.Exception.Message -notmatch $ExpectedPattern) {
            $script:failed++
            $script:errors.Add("$TestName : Exception did not match '$ExpectedPattern': $($_.Exception.Message)")
            Write-Host "  FAIL: $TestName (wrong message: $($_.Exception.Message))"
        }
        else {
            $script:passed++
            Write-Host "  PASS: $TestName"
        }
    }
}

function Assert-DoesNotThrow {
    param(
        [string]$TestName,
        [scriptblock]$ScriptBlock
    )
    try {
        & $ScriptBlock
        $script:passed++
        Write-Host "  PASS: $TestName"
    }
    catch {
        $script:failed++
        $script:errors.Add("$TestName : Unexpected exception: $($_.Exception.Message)")
        Write-Host "  FAIL: $TestName ($($_.Exception.Message))"
    }
}

try {
    Write-Host '=== Copilot CLI + MXC build helper contract tests ==='
    Write-Host "Test root: $testRoot"
    New-Item -Path $testRoot -ItemType Directory -Force | Out-Null

    # Import the module from the same directory as this script
    $modulePath = Join-Path $PSScriptRoot 'CopilotCliMxcBuild.psm1'
    Import-Module $modulePath -Force

    # ---------------------------------------------------------------
    # Set-CopilotCliMxcDependency tests
    # ---------------------------------------------------------------
    Write-Host "`n--- Set-CopilotCliMxcDependency ---"

    # Test 1: Single dependency is rewritten correctly
    $cli1 = New-TestDirectory 'rewrite-ok/cli'
    $mxc1 = New-TestDirectory 'rewrite-ok/mxc'
    $cargoDir1 = Join-Path $cli1 'src/runtime/src/sandbox_engine'
    New-Item -Path $cargoDir1 -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $cargoDir1 'src') -ItemType Directory -Force | Out-Null
    Set-Content -Path (Join-Path $cargoDir1 'src/lib.rs') -Value ''
    $mxcSdkDir1 = Join-Path $mxc1 'src/core/mxc-sdk'
    New-Item -Path $mxcSdkDir1 -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $mxcSdkDir1 'src') -ItemType Directory -Force | Out-Null
    Set-Content -Path (Join-Path $mxcSdkDir1 'src/lib.rs') -Value ''
    Set-Content (Join-Path $cargoDir1 'Cargo.toml') -Value @"
[package]
name = "sandbox_engine"
version = "0.1.0"

[dependencies]
mxc-sdk = { version = "0.1", registry = "mxc-deps" }
"@
    Set-Content (Join-Path $mxcSdkDir1 'Cargo.toml') -Value @"
[package]
name = "mxc-sdk"
version = "0.1.0"
"@

    Assert-DoesNotThrow 'Single dependency rewrite succeeds' {
        Set-CopilotCliMxcDependency -CliRoot $cli1 -MxcRoot $mxc1
    }

    $rewritten = Get-Content (Join-Path $cargoDir1 'Cargo.toml') -Raw
    $expectedPath = ($mxcSdkDir1 -replace '\\', '/').Replace('//', '/')
    if ($rewritten -match [regex]::Escape("mxc-sdk = { path = `"$expectedPath`" }")) {
        $passed++
        Write-Host '  PASS: Rewritten content matches expected path'
    }
    else {
        $failed++
        $errors.Add("Rewritten content does not contain expected path: $expectedPath")
        Write-Host "  FAIL: Rewritten content does not contain expected path"
        Write-Host "  Content: $rewritten"
    }

    Assert-DoesNotThrow 'Cargo provenance accepts exactly the selected MXC SDK' {
        Assert-CopilotCliMxcProvenance -CliRoot $cli1 -MxcRoot $mxc1
    }

    # Test 2: Missing dependency fails
    $cli2 = New-TestDirectory 'rewrite-missing/cli'
    $mxc2 = New-TestDirectory 'rewrite-missing/mxc'
    $cargoDir2 = Join-Path $cli2 'src/runtime/src/sandbox_engine'
    New-Item -Path $cargoDir2 -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $mxc2 'src/core/mxc-sdk') -ItemType Directory -Force | Out-Null
    Set-Content (Join-Path $cargoDir2 'Cargo.toml') -Value @"
[package]
name = "sandbox_engine"

[dependencies]
serde = "1"
"@
    Set-Content (Join-Path $mxc2 'src/core/mxc-sdk/Cargo.toml') -Value @"
[package]
name = "mxc-sdk"
"@

    Assert-Throws 'Missing dependency fails' {
        Set-CopilotCliMxcDependency -CliRoot $cli2 -MxcRoot $mxc2
    } -ExpectedPattern 'No.*mxc-sdk'

    # Test 3: Duplicate dependencies fail
    $cli3 = New-TestDirectory 'rewrite-dup/cli'
    $mxc3 = New-TestDirectory 'rewrite-dup/mxc'
    $cargoDir3 = Join-Path $cli3 'src/runtime/src/sandbox_engine'
    New-Item -Path $cargoDir3 -ItemType Directory -Force | Out-Null
    New-Item -Path (Join-Path $mxc3 'src/core/mxc-sdk') -ItemType Directory -Force | Out-Null
    Set-Content (Join-Path $cargoDir3 'Cargo.toml') -Value @"
[package]
name = "sandbox_engine"

[dependencies]
mxc-sdk = { version = "0.1" }

[dev-dependencies]
mxc-sdk = { version = "0.1", features = ["test"] }
"@
    Set-Content (Join-Path $mxc3 'src/core/mxc-sdk/Cargo.toml') -Value @"
[package]
name = "mxc-sdk"
"@

    Assert-Throws 'Duplicate dependencies fail' {
        Set-CopilotCliMxcDependency -CliRoot $cli3 -MxcRoot $mxc3
    } -ExpectedPattern 'Multiple'

    Assert-Throws 'Cargo provenance rejects a different MXC checkout' {
        Assert-CopilotCliMxcProvenance -CliRoot $cli1 -MxcRoot $mxc2
    } -ExpectedPattern 'manifest_path mismatch'

    $otherMxcSdk = New-TestDirectory 'rewrite-ok/other-mxc-sdk'
    New-Item -Path (Join-Path $otherMxcSdk 'src') -ItemType Directory -Force | Out-Null
    Set-Content -Path (Join-Path $otherMxcSdk 'src/lib.rs') -Value ''
    Set-Content (Join-Path $otherMxcSdk 'Cargo.toml') -Value @"
[package]
name = "mxc-sdk"
version = "0.2.0"
"@
    $otherMxcSdkPath = $otherMxcSdk -replace '\\', '/'
    Add-Content (Join-Path $cargoDir1 'Cargo.toml') -Value @"
other-mxc-sdk = { package = "mxc-sdk", path = "$otherMxcSdkPath" }
"@
    Assert-Throws 'Cargo provenance rejects an additional mxc-sdk package' {
        Assert-CopilotCliMxcProvenance -CliRoot $cli1 -MxcRoot $mxc1
    } -ExpectedPattern 'exactly 1 mxc-sdk'

    # ---------------------------------------------------------------
    # New-CopilotCliMxcManifest tests
    # ---------------------------------------------------------------
    Write-Host "`n--- New-CopilotCliMxcManifest ---"

    # Test 4: Manifest contains no temp path or canary secret
    $manifestDir = New-TestDirectory 'manifest'
    $manifestPath = Join-Path $manifestDir 'provenance.json'
    $testHash = 'a' * 64
    $testSha = 'b' * 40

    # Plant a canary env var to verify it is NOT leaked
    $env:GHCP_CLI_SOURCE_READ = 'ghp_CANARY_SECRET_VALUE_12345678'

    Assert-DoesNotThrow 'Manifest creation succeeds' {
        New-CopilotCliMxcManifest `
            -ManifestPath $manifestPath `
            -MxcSha $testSha `
            -CliSha $testSha `
            -MxcSdkManifest 'src/core/mxc-sdk/Cargo.toml' `
            -RuntimeSourceSha256 $testHash `
            -RuntimeBundleSha256 $testHash `
            -CliVersion 'GitHub Copilot CLI 1.0.0-test' `
            -CargoBuildJobs 2
    }

    $manifestContent = Get-Content $manifestPath -Raw
    $canaryLeak = $false
    foreach ($prohibited in @($testRoot, 'ghp_CANARY', 'GHCP_CLI_SOURCE_READ', $env:GHCP_CLI_SOURCE_READ)) {
        if ($manifestContent -match [regex]::Escape($prohibited)) {
            $canaryLeak = $true
            $failed++
            $errors.Add("Manifest contains prohibited content: $prohibited")
            Write-Host "  FAIL: Manifest leaks: $prohibited"
        }
    }
    if (-not $canaryLeak) {
        $passed++
        Write-Host '  PASS: Manifest contains no temp path or canary secret'
    }

    $rejectedManifestPath = Join-Path $manifestDir 'provenance-canary.json'
    Assert-Throws 'Manifest rejects canary secret content' {
        New-CopilotCliMxcManifest `
            -ManifestPath $rejectedManifestPath `
            -MxcSha $testSha `
            -CliSha $testSha `
            -MxcSdkManifest 'src/core/mxc-sdk/Cargo.toml' `
            -RuntimeSourceSha256 $testHash `
            -RuntimeBundleSha256 $testHash `
            -CliVersion "GitHub Copilot CLI $env:GHCP_CLI_SOURCE_READ" `
            -CargoBuildJobs 2
    } -ExpectedPattern 'suspicious content'
    if (Test-Path $rejectedManifestPath) {
        $failed++
        $errors.Add('Rejected canary manifest was not deleted')
        Write-Host '  FAIL: Rejected canary manifest was not deleted'
    }

    # Clear canary
    Remove-Item Env:\GHCP_CLI_SOURCE_READ -ErrorAction SilentlyContinue

    # Test 5: runtimeHashesMatch is true only for equal hashes
    $hashA = 'a' * 64
    $hashB = 'b' * 64

    $manifestPathMatch = Join-Path $manifestDir 'provenance-match.json'
    $resultMatch = New-CopilotCliMxcManifest `
        -ManifestPath $manifestPathMatch `
        -MxcSha $testSha -CliSha $testSha `
        -MxcSdkManifest 'src/core/mxc-sdk/Cargo.toml' `
        -RuntimeSourceSha256 $hashA `
        -RuntimeBundleSha256 $hashA `
        -CliVersion 'GitHub Copilot CLI test' -CargoBuildJobs 2

    if ($resultMatch.runtimeHashesMatch -eq $true) {
        $passed++
        Write-Host '  PASS: runtimeHashesMatch is true for equal hashes'
    }
    else {
        $failed++
        $errors.Add('runtimeHashesMatch should be true for equal hashes')
        Write-Host '  FAIL: runtimeHashesMatch should be true for equal hashes'
    }

    $manifestPathMismatch = Join-Path $manifestDir 'provenance-mismatch.json'
    $resultMismatch = New-CopilotCliMxcManifest `
        -ManifestPath $manifestPathMismatch `
        -MxcSha $testSha -CliSha $testSha `
        -MxcSdkManifest 'src/core/mxc-sdk/Cargo.toml' `
        -RuntimeSourceSha256 $hashA `
        -RuntimeBundleSha256 $hashB `
        -CliVersion 'GitHub Copilot CLI test' -CargoBuildJobs 2

    if ($resultMismatch.runtimeHashesMatch -eq $false) {
        $passed++
        Write-Host '  PASS: runtimeHashesMatch is false for different hashes'
    }
    else {
        $failed++
        $errors.Add('runtimeHashesMatch should be false for different hashes')
        Write-Host '  FAIL: runtimeHashesMatch should be false for different hashes'
    }

    # ---------------------------------------------------------------
    # Invalid roots fail before unrelated paths are changed (Task 2 §14)
    # ---------------------------------------------------------------
    Write-Host "`n--- Invalid root rejection ---"

    $protectedStage = New-TestDirectory 'invalid-root/protected-stage'
    $sentinelPath = Join-Path $protectedStage 'do-not-delete.txt'
    Set-Content -Path $sentinelPath -Value 'sentinel'
    $buildScript = Join-Path $PSScriptRoot 'build-copilot-cli-with-mxc.ps1'

    Assert-Throws 'Build script rejects an invalid source root' {
        & $buildScript `
            -MxcRoot (Join-Path $testRoot 'does-not-exist') `
            -CliRoot $cli1 `
            -StageRoot $protectedStage `
            -ManifestPath (Join-Path $testRoot 'must-not-exist.json')
    } -ExpectedPattern 'MXC root does not exist'

    if ((Test-Path $sentinelPath) -and
        -not (Test-Path (Join-Path $testRoot 'must-not-exist.json'))) {
        $passed++
        Write-Host '  PASS: Invalid roots do not change or delete unrelated paths'
    }
    else {
        $failed++
        $errors.Add('Invalid-root build invocation changed or deleted an unrelated path')
        Write-Host '  FAIL: Invalid roots changed or deleted an unrelated path'
    }

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    Write-Host "`n=== Results ==="
    Write-Host "Passed: $passed"
    Write-Host "Failed: $failed"

    if ($failed -gt 0) {
        Write-Host "`nFailures:"
        foreach ($err in $errors) {
            Write-Host "  - $err"
        }
        throw "FAIL: $failed contract test(s) failed."
    }

    Write-Host "`nPASS: Copilot CLI + MXC build helper contract"
}
finally {
    [System.Environment]::SetEnvironmentVariable(
        'GHCP_CLI_SOURCE_READ',
        $originalCanary,
        'Process'
    )

    # Clean up test directory
    if (Test-Path $testRoot) {
        Remove-Item $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
