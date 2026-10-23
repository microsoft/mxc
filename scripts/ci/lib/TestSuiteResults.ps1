# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-LibtestFailure {
    param(
        [Parameter(Mandatory)][hashtable]$Run,
        [string[]]$RequiredTests = @()
    )

    if ($Run.ExitCode -ne 0) { return "exited $($Run.ExitCode)" }
    $summary = Select-String -LiteralPath $Run.Log -Pattern '^test result: \w+\. (\d+) passed; (\d+) failed;' |
        Select-Object -Last 1
    if (-not $summary -or ([int]$summary.Matches[0].Groups[1].Value + [int]$summary.Matches[0].Groups[2].Value) -eq 0) {
        return 'executed no tests'
    }
    if ([int]$summary.Matches[0].Groups[2].Value -ne 0) { return 'reported failed tests' }
    foreach ($name in $RequiredTests) {
        $pattern = '^test ' + [regex]::Escape($name) + ' \.\.\. ok\r?$'
        if (-not (Select-String -LiteralPath $Run.Log -Pattern $pattern)) {
            return "'$name' did not pass"
        }
    }
}

# Node reports a skipped describe block as a top-level skipped testcase.
function Get-NodeSuiteFailure {
    param(
        [Parameter(Mandatory)][string]$JunitPath,
        [string[]]$RequiredTests = @()
    )

    [xml]$report = Get-Content -LiteralPath $JunitPath -Raw
    $blocks = @($report.testsuites.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })
    if ($blocks.Count -eq 0) { return 'executed no tests' }
    $failures = @(foreach ($block in $blocks) {
        if (@($block.SelectNodes('descendant-or-self::testcase[not(skipped)]')).Count -eq 0) {
            "'$($block.name)' executed no tests"
        }
    })
    foreach ($name in $RequiredTests) {
        $cases = @($report.SelectNodes('//testcase') | Where-Object { $_.name.Contains($name) })
        if ($cases.Count -eq 0 -or @($cases | Where-Object { $_.SelectSingleNode('skipped') -or $_.SelectSingleNode('failure') }).Count) {
            $failures += "'$name' did not pass"
        }
    }
    $failures -join '; '
}

function Get-XunitSuiteFailure {
    param(
        [Parameter(Mandatory)][string]$ResultXml,
        [Parameter(Mandatory)][string[]]$Classes,
        [string[]]$RequiredMethods = @(),
        [switch]$RejectSkipped
    )

    $allTests = @(([xml](Get-Content -LiteralPath $ResultXml -Raw)).SelectNodes('//test'))
    $selected = @(foreach ($class in $Classes) {
        $allTests | Where-Object { $_.type -like "*.$class" }
    })
    $failures = @(foreach ($class in $Classes) {
        if (@($selected | Where-Object { $_.type -like "*.$class" -and $_.result -in 'Pass', 'Fail' }).Count -eq 0) {
            "'$class' executed no tests"
        }
    })
    if ($RejectSkipped -and @($selected | Where-Object { $_.result -eq 'Skip' }).Count) {
        $failures += 'selected tests were skipped'
    }
    foreach ($method in $RequiredMethods) {
        if (@($selected | Where-Object { $_.method -eq $method -and $_.result -eq 'Pass' }).Count -eq 0) {
            $failures += "'$method' did not pass"
        }
    }
    $failures -join '; '
}
