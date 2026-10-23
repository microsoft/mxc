# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')
function Import-TestFunctions {
    param([string]$Path, [string[]]$Names)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Could not parse test helpers in $Path" }
    foreach ($name in $Names) {
        $node = $ast.Find({ param($item)
            $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $name
        }, $true)
        if (-not $node) { throw "Missing test helper: $name" }
        Set-Item -Path "Function:script:$name" -Value ([scriptblock]::Create($node.Body.Extent.Text.Substring(1, $node.Body.Extent.Text.Length - 2)))
    }
}
Import-TestFunctions (Join-Path $PSScriptRoot 'run_processcontainer_policy_tests.ps1') @(
    'New-PolicyRequest', 'New-UiPolicyRequest', 'Invoke-PolicyCase', 'Invoke-UiPolicyMatrixCase'
)
Import-TestFunctions (Join-Path $PSScriptRoot 'run_processcontainer_contract_tests.ps1') @(
    'New-ContractRequest', 'Invoke-ContractCase'
)
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    try { & $Action }
    catch {
        if ($_.Exception.Message -notmatch $Message) { throw }
        return
    }
    throw "Expected a failure matching: $Message"
}
function Invoke-NativeProcessContainer {
    param($WxcExec, $ScratchRoot, $Name, $Arguments, $Observe, $Environment, $WorkingDirectory)
    [pscustomobject]$script:MockRun
}
$ScratchRoot = Join-Path $env:TEMP ("mxc-native-oracles-" + [guid]::NewGuid().ToString('N'))
$scratch = $ScratchRoot
New-Item -ItemType Directory -Path $scratch | Out-Null
$FixtureDirectories = @('')
$WxcExec = 'controlled-fixture'
$wxc = $WxcExec
$WindowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$powershell = $WindowsPowerShell
$ProbeScript = Join-Path $PSScriptRoot 'lib\processcontainer_policy_probe.ps1'
$UiProbe = 'controlled-ui-fixture'
$Passed = 0
$script:UiGrantable = @{}
$script:MockRun = @{ ExitCode = 0; Stdout = 'NATIVE_POLICY_OK'; Stderr = ''; Log = '{"tier":"base-container"}' }
try {
    Invoke-PolicyCase -Name 'ordinary-policy-case' -Request (New-PolicyRequest -Mode 'allowed')
    if ($Passed -ne 1) { throw 'A policy case without a custom result validator did not count as a pass.' }
    $Passed = 0
    Write-Host 'PASS: existing policy cases retain their normal success handling'

    $script:MockRun.Stdout = 'INJECTION=INCONCLUSIVE'
    Invoke-UiPolicyMatrixCase -Name 'inconclusive-control' -Tag 'INJECTION' -Baseline
    if ($Passed -ne 0 -or $script:UiGrantable.INJECTION) { throw 'An inconclusive control counted as a pass.' }
    Write-Host 'PASS: inconclusive native UI operations remain skips'

    $script:UiGrantable.INJECTION = $true
    $script:MockRun.Stdout = 'INJECTION=FAIL'
    Assert-Throws { Invoke-UiPolicyMatrixCase -Name 'unenforced-limit' -Tag 'INJECTION' } 'expected INJECTION=PASS'
    $script:UiGrantable.READCLIPBOARD = $true
    $script:MockRun.Stdout = 'READCLIPBOARD=PASS'
    Assert-Throws {
        Invoke-UiPolicyMatrixCase -Name 'over-restricted-allow' -Tag 'READCLIPBOARD' -Allowed $true
    } 'expected READCLIPBOARD=FAIL'
    Write-Host 'PASS: both missing restrictions and broken permissive policies fail'

    $script:MockRun.Stdout = 'READCLIPBOARD=FAIL'
    Assert-Throws {
        Invoke-UiPolicyMatrixCase -Name 'missing-round-trip' -Tag 'READCLIPBOARD' -Allowed $true -RequireClipboardRoundTrip
    } 'did not read back'
    $script:MockRun.Stdout = "READCLIPBOARD=DIAG GetClipboardData returned the seeded text`nREADCLIPBOARD=FAIL"
    Invoke-UiPolicyMatrixCase -Name 'readable-round-trip' -Tag 'READCLIPBOARD' -Allowed $true -RequireClipboardRoundTrip
    if ($Passed -ne 1) { throw 'The successful round trip was not the only passing UI case.' }
    Write-Host 'PASS: allowed clipboard reads require the real seeded round trip'

    $script:MockRun = @{ ExitCode = 1; Stdout = ''; Stderr = 'unrelated backend failure'; Log = '' }
    $request = New-ContractRequest -Name 'wrong-error' -Version '1.0.0'
    Assert-Throws {
        Invoke-ContractCase -Name 'wrong-error' -Request $request -Rejection 'must be an absolute path'
    } 'not rejected before execution'
    $script:MockRun.Stderr = 'must be an absolute path'
    Set-Content -LiteralPath (Join-Path $scratch 'wrong-error.executed') -Value 'ran'
    Assert-Throws {
        Invoke-ContractCase -Name 'wrong-error' -Request $request -Rejection 'must be an absolute path'
    } 'not rejected before execution'
    Write-Host 'PASS: CLI rejections require the right error and an unexecuted workload'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
$global:LASTEXITCODE = 0
