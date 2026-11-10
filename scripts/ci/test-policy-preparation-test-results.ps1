# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\TestSuiteResults.ps1')
$directory = Join-Path (Get-Location) ('.mxc-preparation-results-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $directory
try {
    $name = 'dev_json_processcontainer_policy_feedback_restricts_current_request'
    $markers = @('0.9.0-alpha', '1.0.0', '1.1.0-alpha') |
        ForEach-Object { "MXC_POLICY_PREPARATION_STRICT_CREATE_OK:$_" }
    $log = Join-Path $directory 'libtest.log'
    $passed = @("test $name ... ok", 'test result: ok. 1 passed; 0 failed; 0 ignored;')
    foreach ($case in 'complete', 'missing', 'partial', 'unmatched', 'zero', 'ignored') {
        $lines = switch ($case) {
            'complete' { $passed + $markers }
            'missing' { $passed }
            'partial' { $passed + $markers[0] }
            'unmatched' { $passed + @($markers | ForEach-Object { "noise $_" }) }
            'zero' { @('test result: ok. 0 passed; 0 failed; 0 ignored;') + $markers }
            'ignored' { @("test $name ... ignored", 'test result: ok. 0 passed; 0 failed; 1 ignored;') + $markers }
        }
        Set-Content -LiteralPath $log -Value $lines
        $failure = Get-LibtestFailure -Run @{ ExitCode = 0; Log = $log } `
            -RequiredTests $name -RequiredOutputLines $markers
        if (($case -eq 'complete') -ne [string]::IsNullOrEmpty($failure)) {
            throw "Unexpected preparation result gate for ${case}: $failure"
        }
    }
    Set-Content -LiteralPath $log -Value $passed
    if (Get-LibtestFailure -Run @{ ExitCode = 0; Log = $log } -RequiredTests $name) {
        throw 'Unchanged callers must not require new output markers.'
    }
    $outputText = @('MXC_PREPARED_FILESYSTEM_BASELINE_RW_OK', 'MXC_PREPARED_FILESYSTEM_ACCEPTED:',
        'MXC_PREPARED_FILESYSTEM_STRICT_RUN_SPAWN_OK:1.1.0-alpha:seed=unchanged:permitted=written')
    $xunit = Join-Path $directory 'xunit.xml'
    foreach ($case in 'complete', 'missing', 'skipped') {
        $result = if ($case -eq 'skipped') { 'Skip' } else { 'Pass' }
        $output = if ($case -eq 'missing') { 'noise' } else { $outputText -join "`n" }
        Set-Content -LiteralPath $xunit -Value ('<assemblies><assembly><collection>' +
            "<test type='Ns.MxcProcessTests' method='DevJson_CapturesOutputAndStreamsInput' result='$result'>" +
            "<output><![CDATA[$output]]></output></test></collection></assembly></assemblies>")
        $failure = Get-XunitSuiteFailure -ResultXml $xunit -Classes 'MxcProcessTests' -RejectSkipped `
            -RequiredMethods 'DevJson_CapturesOutputAndStreamsInput' -RequiredOutputText $outputText
        if (($case -eq 'complete') -ne [string]::IsNullOrEmpty($failure)) {
            throw "Unexpected .NET prepared-scenario gate for ${case}: $failure"
        }
    }
    $methods = @('PolicyPreparationReturnsOwnedNativeRequestsWithoutLaunching',
        'PolicyPreparationStoragePreservesLargeTextWithoutHtmlExpansion',
        'PolicyPreparationStoragePreservesDuplicateCommentMembers')
    foreach ($case in 'complete', 'missing-class', 'missing-method', 'skipped-native') {
        $rows = @("<test type='Ns.MxcProcessTests' method='DevJson_CapturesOutputAndStreamsInput' result='Pass'/>")
        if ($case -ne 'missing-class') {
            if ($case -ne 'missing-method') {
                $rows += "<test type='Ns.DevEntryPointTests' method='$($methods[0])' result='Pass'/>"
            }
            foreach ($method in $methods[1..2]) {
                $result = if ($case -eq 'skipped-native') { 'Skip' } else { 'Pass' }
                $rows += "<test type='Ns.DevEntryPointTests' method='$method' name='nativePreparation: True' result='$result'/>"
                $rows += "<test type='Ns.DevEntryPointTests' method='$method' name='nativePreparation: False' result='Pass'/>"
            }
        }
        Set-Content -LiteralPath $xunit -Value (
            '<assemblies><assembly><collection>' + ($rows -join '') + '</collection></assembly></assemblies>')
        $failure = Get-XunitSuiteFailure -ResultXml $xunit -Classes 'MxcProcessTests', 'DevEntryPointTests' `
            -RejectSkipped -RequiredMethods (@('DevJson_CapturesOutputAndStreamsInput') + $methods)
        if (($case -eq 'complete') -ne [string]::IsNullOrEmpty($failure)) {
            throw "Unexpected .NET native preparation gate for ${case}: $failure"
        }
    }
    Write-Host 'Policy preparation result gates passed (14 cases).'
}
finally {
    Remove-Item -LiteralPath $directory -Recurse -Force
}
