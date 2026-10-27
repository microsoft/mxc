# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#Requires -Version 7.0

# Manual host-only regression; this does not run workloads or join the CI suite.
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$source = Join-Path $PSScriptRoot 'run_processcontainer_workload_tests.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "Could not parse $source" }
foreach ($name in @('New-WorkloadGitEnvironment', 'Invoke-WorkloadGit')) {
    $node = $ast.Find({ param($item)
        $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $name
    }, $true)
    if (-not $node) { throw "Missing Git fixture helper: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$setup = $ast.Find({ param($item)
    $item -is [Management.Automation.Language.IfStatementAst] -and
        $item.Extent.Text.StartsWith('if ($tools.pwsh -and $tools.git)')
}, $true)
if (-not $setup) { throw 'Missing host Git fixture setup.' }
$setup = [scriptblock]::Create($setup.Extent.Text)
$tools = @{
    git = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    pwsh = (Get-Command pwsh.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
}
$keys = @('GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'XDG_CONFIG_HOME')
function Get-CallerGitEnvironment {
    $state = @{}
    foreach ($key in $keys) {
        $item = Get-Item -LiteralPath "Env:$key" -ErrorAction SilentlyContinue
        $state[$key] = @{
            Exists = $null -ne $item
            Value = if ($null -ne $item) { $item.Value } else { $null }
        }
    }
    $state
}
function Assert-CallerGitEnvironment {
    param([hashtable]$Expected)
    $actual = Get-CallerGitEnvironment
    foreach ($key in $keys) {
        if ($actual[$key].Exists -ne $Expected[$key].Exists -or
            $actual[$key].Value -cne $Expected[$key].Value) {
            throw "Git fixture preparation changed caller environment variable $key."
        }
    }
}
$original = Get-CallerGitEnvironment
$scratch = Join-Path $env:TEMP ("mxc-git-environment-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    foreach ($state in @('absent', 'empty', 'nonempty', 'failure')) {
        foreach ($key in $keys) {
            if (Test-Path -LiteralPath "Env:$key") { Remove-Item -LiteralPath "Env:$key" }
            if ($state -eq 'empty') {
                [Environment]::SetEnvironmentVariable($key, '', 'Process')
            } elseif ($state -eq 'nonempty' -or ($state -eq 'failure' -and $key -eq 'XDG_CONFIG_HOME')) {
                [Environment]::SetEnvironmentVariable($key, (Join-Path $scratch "caller-$key"), 'Process')
            }
        }
        $before = Get-CallerGitEnvironment
        if ($state -eq 'empty' -and -not $before.GIT_CONFIG_GLOBAL.Exists) {
            Write-Host 'SKIPPED: this runtime cannot represent an existing empty environment variable.'
            continue
        }
        $gitEnvironment = New-WorkloadGitEnvironment -Directory (Join-Path $scratch "$state\configuration")
        $repo = Join-Path $scratch "$state\repo"
        if ($state -eq 'failure') {
            [IO.File]::WriteAllText($gitEnvironment.GIT_CONFIG_GLOBAL, '[broken configuration')
            $failed = $false
            try { . $setup }
            catch {
                if ($_.Exception.Message -notmatch 'Git fixture preparation exited') { throw }
                $failed = $true
            }
            if (-not $failed) { throw 'The injected Git preparation failure did not fail.' }
        } else {
            . $setup
            if (-not (Test-Path -LiteralPath (Join-Path $repo '.git\HEAD'))) {
                throw 'Git fixture preparation did not create its repository.'
            }
        }
        Assert-CallerGitEnvironment -Expected $before
        Write-Host "PASS: caller Git environment preserved ($state)"
    }
} finally {
    foreach ($key in $keys) {
        if ($original[$key].Exists) {
            [Environment]::SetEnvironmentVariable($key, $original[$key].Value, 'Process')
        } elseif (Test-Path -LiteralPath "Env:$key") {
            Remove-Item -LiteralPath "Env:$key"
        }
    }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
$global:LASTEXITCODE = 0
