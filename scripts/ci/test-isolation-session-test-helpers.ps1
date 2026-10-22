$ErrorActionPreference = 'Stop'
$stager = Join-Path $PSScriptRoot 'stage-isolation-session-test-helpers.ps1'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scratch = (New-Item -ItemType Directory -Path (
    Join-Path ([IO.Path]::GetTempPath()) "mxc-bundle-helpers-$([guid]::NewGuid())")).FullName
$passed = 0

function Assert-True {
    param([string]$Name, [bool]$Condition)
    if (-not $Condition) { throw $Name }
    $script:passed++
    Write-Host "[PASS] $Name"
}

function Assert-Failure {
    param([string]$Name, [scriptblock]$Action, [string]$Message)
    $failure = $null
    try { & $Action | Out-Null } catch { $failure = $_ }
    Assert-True $Name ($null -ne $failure -and $failure.ToString() -like $Message)
}

try {
    $source = (New-Item -ItemType Directory -Path (Join-Path $scratch 'source')).FullName
    $sourceLib = (New-Item -ItemType Directory -Path (Join-Path $source 'lib')).FullName
    $main = (New-Item -ItemType Directory -Path (Join-Path $scratch 'main')).FullName
    foreach ($name in @(
        'run_isolation_session_tests.ps1',
        'run_isolation_session_state_aware_tests.ps1',
        'run_isolation_session_resize_smoke.ps1'
    )) {
        Copy-Item -LiteralPath (Join-Path $repoRoot "tests\scripts\$name") -Destination $main
    }
    $helper = Join-Path $sourceLib 'LoopbackAnchor.ps1'
    Copy-Item -LiteralPath (Join-Path $repoRoot 'tests\scripts\lib\LoopbackAnchor.ps1') `
        -Destination $helper
    $paths = @(& $stager -SourceDirectory $source -ScriptsDirectory $main)
    Assert-True 'Main suites stage exactly one required helper' (
        $paths.Count -eq 1 -and $paths[0] -eq (Join-Path 'lib' 'LoopbackAnchor.ps1'))
    Assert-True 'Staged helper bytes match the source' (
        (Get-FileHash -LiteralPath $helper).Hash -eq
        (Get-FileHash -LiteralPath (Join-Path $main $paths[0])).Hash)

    Remove-Item -LiteralPath $helper
    Assert-Failure 'Missing required source fails even if a stale staged helper exists' {
        & $stager -SourceDirectory $source -ScriptsDirectory $main
    } '*Required test script helper not found:*LoopbackAnchor.ps1'

    $legacy = (New-Item -ItemType Directory -Path (Join-Path $scratch 'legacy')).FullName
    $suite = Join-Path $legacy 'suite.ps1'
    @'
# LoopbackAnchor.ps1 is not used by this suite.
Write-Output 'LoopbackAnchor.ps1'
'@ | Set-Content -LiteralPath $suite
    $paths = @(& $stager -SourceDirectory $source -ScriptsDirectory $legacy)
    Assert-True 'Legacy suites need no helper; comments and log text are not dependencies' (
        $paths.Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $legacy 'lib')))

    Set-Content -LiteralPath $helper -Value '# unused helper'
    $paths = @(& $stager -SourceDirectory $source -ScriptsDirectory $legacy)
    Assert-True 'An unreferenced helper is not added to the bundle' (
        $paths.Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $legacy 'lib')))

    $secondSuite = Join-Path $legacy 'second-suite.ps1'
    Set-Content -LiteralPath $secondSuite -Value '. "$PSScriptRoot/lib/LoopbackAnchor.ps1"'
    $paths = @(& $stager -SourceDirectory $source -ScriptsDirectory $legacy)
    Assert-True 'A dependency in any staged suite is included, including slash paths' (
        $paths.Count -eq 1 -and
        (Test-Path -LiteralPath (Join-Path $legacy $paths[0]) -PathType Leaf))

    Remove-Item -LiteralPath $helper
    Assert-Failure 'A referencing legacy checkout cannot silently omit the helper' {
        & $stager -SourceDirectory $source -ScriptsDirectory $legacy
    } '*Required test script helper not found:*LoopbackAnchor.ps1'

    Set-Content -LiteralPath $secondSuite -Value 'function Broken {'
    Assert-Failure 'Malformed staged scripts fail inspection explicitly' {
        & $stager -SourceDirectory $source -ScriptsDirectory $legacy
    } '*Cannot inspect*second-suite.ps1*'

    $empty = (New-Item -ItemType Directory -Path (Join-Path $scratch 'empty')).FullName
    Assert-Failure 'An empty staging directory is not a successful bundle' {
        & $stager -SourceDirectory $source -ScriptsDirectory $empty
    } '*No staged test scripts found*'

    $tokens = $null
    $errors = $null
    $builder = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'build-windows-sdk-test-bundle.ps1'),
        [ref]$tokens, [ref]$errors)
    $updates = @($builder.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$required' -and $node.Operator -eq 'PlusEquals'
    }, $true))
    if ($errors.Count -or $updates.Count -ne 1) {
        throw 'Cannot locate the standalone builder helper layout check.'
    }
    $required = @('manifest.json')
    $helperPaths = @()
    . ([scriptblock]::Create($updates[0].Extent.Text))
    Assert-True 'No helpers adds no null entry to the standalone layout check' (
        $required.Count -eq 1 -and $required[0] -eq 'manifest.json')
    $helperPaths = @(Join-Path 'lib' 'LoopbackAnchor.ps1')
    . ([scriptblock]::Create($updates[0].Extent.Text))
    Assert-True 'Required helpers participate in the standalone layout check' (
        $required.Count -eq 2 -and
        $required[1] -eq (Join-Path 'test_scripts' $helperPaths[0]))

    Write-Host "Passed $passed bundle helper assertions."
}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
