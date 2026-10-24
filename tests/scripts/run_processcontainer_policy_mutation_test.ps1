# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$ContextJson,
    [string]$ResultsJson,
    [string]$RequireTier,
    [switch]$SkipNetwork,
    [switch]$KeepArtifacts,
    [string]$FixtureManifest = $env:MXC_POLICY_MUTATION_FIXTURE,
    [string]$TestExecutable = $env:MXC_POLICY_MUTATION_TEST_EXE
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lib\WinProcessContainer.Common.ps1')
$context = @{}
foreach ($name in @('ContextJson','ResultsJson','RequireTier','SkipNetwork','KeepArtifacts')) {
    if ($PSBoundParameters.ContainsKey($name)) { $context[$name] = $PSBoundParameters[$name] }
}
Initialize-WpcContext @context

function Phase-PolicyMutation {
    if (-not $FixtureManifest) {
        Record-Result -Phase 'PolicyMutation' -Name 'Governed policy fixture is not configured' `
            -Status skip -Detail 'No governed correction/reuse coverage is claimed on this host.'
        return
    }
    if ($Script:ExpectedTier -ne 'base-container') {
        throw 'The governed mutation scenario requires native BaseContainer, not fallback.'
    }
    foreach ($path in @($FixtureManifest, $TestExecutable)) {
        if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'A configured governed lane requires its manifest and built SDK test executable.'
        }
    }
    $fixture = Get-Content -LiteralPath $FixtureManifest -Raw | ConvertFrom-Json
    if (-not $fixture.root -or
        -not (Test-Path -LiteralPath $fixture.root -PathType Container)) {
        throw 'The governed fixture does not identify an existing data directory.'
    }
    $resultPath = Join-Path $fixture.root 'result.json'
    $ownerPath = Join-Path $fixture.root 'sdk-owner.json'
    if ((Test-Path -LiteralPath $resultPath) -or (Test-Path -LiteralPath $ownerPath)) {
        throw 'Use a fresh governed fixture; stale result/owner receipts are not evidence.'
    }
    $priorManifest = $env:MXC_POLICY_MUTATION_FIXTURE
    $process = $null
    try {
        $env:MXC_POLICY_MUTATION_FIXTURE = (Resolve-Path -LiteralPath $FixtureManifest).Path
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = (Resolve-Path -LiteralPath $TestExecutable).Path
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        foreach ($argument in @('--ignored','--exact',
            'governed_creation_policy_reuses_restrictions','--nocapture')) {
            $start.ArgumentList.Add($argument)
        }
        $process = [Diagnostics.Process]::Start($start)
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(180000)) {
            Stop-Process -Id $process.Id -Force
            throw 'The governed SDK scenario exceeded 180 seconds.'
        }
        $out = $stdout.GetAwaiter().GetResult()
        $err = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $fixture.root 'test-stdout.txt'), $out)
        [IO.File]::WriteAllText((Join-Path $fixture.root 'test-stderr.txt'), $err)
        if ($process.ExitCode -ne 0 -or
            $out -notmatch 'test result: ok\. 1 passed; 0 failed;' -or
            -not (Test-Path -LiteralPath $resultPath)) {
            throw "Governed SDK assertions failed: exit=$($process.ExitCode); $out $err"
        }
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        $workloads = @($result.workloadProcessIds)
        if ($result.sdkProcessId -ne $process.Id -or $workloads.Count -ne 4 -or
            @($workloads | Select-Object -Unique).Count -ne 4 -or
            $result.strictControls -ne 2 -or $result.successfulCreations -ne 4) {
            throw 'The SDK result does not establish the complete governed scenario.'
        }
        Record-Result -Phase 'PolicyMutation' -Name 'Governed strict/cold/warm/further-restriction SDK behavior' `
            -Pass $true -Detail 'Public run/spawn, enforced access, fresh CA/proxy values, quiet reuse and strict controls passed.'
        Record-Result -Phase 'PolicyMutation' -Name 'Workload ledger detects refused or replayed execution' `
            -Pass $true -Detail "Four distinct workload entries: $($workloads -join ', ')"
    } finally {
        if (Test-Path -LiteralPath $ownerPath) {
            $owner = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json
            $remaining = Get-Process -Id $owner.pid -ErrorAction SilentlyContinue
            if ($remaining -and
                $remaining.StartTime.ToUniversalTime().ToFileTimeUtc() -eq $owner.creationFileTime -and
                [string]::Equals($remaining.Path, $owner.executable,
                    [StringComparison]::OrdinalIgnoreCase)) {
                Stop-Process -Id $remaining.Id -Force
            }
        }
        $env:MXC_POLICY_MUTATION_FIXTURE = $priorManifest
        if ($process) { $process.Dispose() }
    }
}

Invoke-WpcPhase -Key 'PolicyMutation' -Body { Phase-PolicyMutation }
Complete-WpcChild
