# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\scripts\ci\lib\TestSuiteResults.ps1')

function Assert-SuiteResult {
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyString()][string]$Failure,
        [bool]$ExpectFailure
    )
    if ([bool]$Failure -ne $ExpectFailure) {
        throw "$Name returned an unexpected suite result: '$Failure'."
    }
    Write-Host "PASS: $Name"
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ("mxc-suite-results-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$scratch = (Resolve-Path -LiteralPath $scratch).Path
try {
    $rustLog = Join-Path $scratch 'rust.log'
    $run = @{ ExitCode = 0; Log = $rustLog }
    foreach ($case in @(
        @{ Name = 'Rust passing required test'; Text = "test streaming ... ok`ntest result: ok. 1 passed; 0 failed; 0 ignored;"; Fails = $false },
        @{ Name = 'Rust ignored required test'; Text = "test streaming ... ignored`ntest result: ok. 0 passed; 0 failed; 1 ignored;"; Fails = $true },
        @{ Name = 'Rust empty selection'; Text = 'test result: ok. 0 passed; 0 failed; 0 ignored;'; Fails = $true },
        @{ Name = 'Rust unrelated test passed'; Text = "test unrelated ... ok`ntest result: ok. 1 passed; 0 failed; 0 ignored;"; Fails = $true }
    )) {
        Set-Content -LiteralPath $rustLog -Value $case.Text
        Assert-SuiteResult -Name $case.Name -ExpectFailure $case.Fails `
            -Failure (Get-LibtestFailure -Run $run -RequiredTests 'streaming')
    }
    $run.ExitCode = 1
    Assert-SuiteResult -Name 'Rust native failure' -ExpectFailure $true -Failure (Get-LibtestFailure -Run $run)

    $dotnetXml = Join-Path $scratch 'dotnet.xml'
    foreach ($case in @(
        @{ Name = '.NET passing streaming test'; Tests = '<test type="Sdk.MxcProcessTests" method="Streaming" result="Pass"/>'; Fails = $false },
        @{ Name = '.NET skipped streaming with a passing unit test'; Tests = '<test type="Sdk.MxcProcessTests" method="Normalize" result="Pass"/><test type="Sdk.MxcProcessTests" method="Streaming" result="Skip"/>'; Fails = $true },
        @{ Name = '.NET missing required method'; Tests = '<test type="Sdk.MxcProcessTests" method="Normalize" result="Pass"/>'; Fails = $true },
        @{ Name = '.NET empty selection'; Tests = ''; Fails = $true }
    )) {
        Set-Content -LiteralPath $dotnetXml -Value "<assemblies><assembly><collection>$($case.Tests)</collection></assembly></assemblies>"
        Assert-SuiteResult -Name $case.Name -ExpectFailure $case.Fails `
            -Failure (Get-XunitSuiteFailure -ResultXml $dotnetXml -Classes 'MxcProcessTests' `
                -RequiredMethods 'Streaming' -RejectSkipped)
    }

    $nodeXml = Join-Path $scratch 'node.xml'
    foreach ($case in @(
        @{ Name = 'Node passing streaming test'; Tests = '<testcase name="public spawn"/>'; Fails = $false },
        @{ Name = 'Node skipped streaming with an unrelated pass'; Tests = '<testcase name="public spawn"><skipped/></testcase><testcase name="unrelated"/>'; Fails = $true },
        @{ Name = 'Node missing required test'; Tests = '<testcase name="unrelated"/>'; Fails = $true },
        @{ Name = 'Node all-skipped suite'; Tests = '<testcase name="public spawn"><skipped/></testcase>'; Fails = $true }
    )) {
        Set-Content -LiteralPath $nodeXml -Value "<testsuites><testsuite name='Windows'>$($case.Tests)</testsuite></testsuites>"
        Assert-SuiteResult -Name $case.Name -ExpectFailure $case.Fails `
            -Failure (Get-NodeSuiteFailure -JunitPath $nodeXml -RequiredTests 'public spawn')
    }
    Set-Content -LiteralPath $nodeXml -Value '<testsuites/>'
    Assert-SuiteResult -Name 'Node empty selection' -ExpectFailure $true `
        -Failure (Get-NodeSuiteFailure -JunitPath $nodeXml -RequiredTests 'public spawn')
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
