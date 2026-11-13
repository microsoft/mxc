<#
.SYNOPSIS
Stages the known helpers dot-sourced by the selected checkout's bundled suites.
.OUTPUTS
Relative paths of the staged helpers, for the bundle layout check.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourceDirectory,

    [Parameter(Mandatory)]
    [string]$ScriptsDirectory
)

$ErrorActionPreference = 'Stop'
$scripts = @(Get-ChildItem -LiteralPath $ScriptsDirectory -Filter '*.ps1' -File)
if ($scripts.Count -eq 0) {
    throw "No staged test scripts found in $ScriptsDirectory."
}

$dotSources = @(
    foreach ($script in $scripts) {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script.FullName, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) {
            throw "Cannot inspect $($script.FullName): $($parseErrors.Message -join '; ')"
        }
        $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot
        }, $true)
    }
)

foreach ($helper in @('LoopbackAnchor.ps1')) {
    $pattern = '\b' + [regex]::Escape($helper) + '\b'
    if (-not ($dotSources | Where-Object { $_.Extent.Text -match $pattern })) {
        continue
    }
    $relativePath = Join-Path 'lib' $helper
    $source = Join-Path $SourceDirectory $relativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Required test script helper not found: $source"
    }
    $destination = Join-Path $ScriptsDirectory 'lib'
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -Force
    $relativePath
}
