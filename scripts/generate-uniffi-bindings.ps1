# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [switch]$SkipToolInstall
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'src'
$profile = $Configuration.ToLowerInvariant()
$extension = if ($IsWindows) { '.exe' } else { '' }
$libraryName = if ($IsWindows) {
    'mxc_uniffi.dll'
} elseif ($IsMacOS) {
    'libmxc_uniffi.dylib'
} else {
    'libmxc_uniffi.so'
}
$library = Join-Path $src "target\$profile\$libraryName"
$nodeToolRoot = Join-Path $src 'target\uniffi-tools\node'
$csharpToolRoot = Join-Path $src 'target\uniffi-tools\csharp'
$nodeTool = Join-Path $nodeToolRoot "bin\uniffi-bindgen-react-native$extension"
$csharpTool = Join-Path $csharpToolRoot "bin\uniffi-bindgen-cs$extension"
$config = Join-Path $src 'ffi\mxc_uniffi\uniffi.toml'
$nodeOut = Join-Path $root 'sdk\node\prototype\generated'
$csharpOut = Join-Path $root 'sdk\dotnet\Microsoft.Mxc.Uniffi.Generated\Generated'

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$Command,

        [Parameter(ValueFromRemainingArguments)]
        [string[]]$Arguments
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$Command' failed with exit code $LASTEXITCODE."
    }
}

function Normalize-GeneratedFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $content = [System.IO.File]::ReadAllText($Path)
    $newline = if ($content.Contains("`r`n")) { "`r`n" } else { "`n" }
    $content = [regex]::Replace(
        $content,
        '[ \t]+(?=\r?$)',
        '',
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
    $content = $content.TrimEnd("`r", "`n") + $newline
    [System.IO.File]::WriteAllText($Path, $content, [System.Text.UTF8Encoding]::new($false))
}

if (-not $SkipToolInstall) {
    if (-not (Test-Path $nodeTool)) {
        Invoke-Checked cargo install uniffi-bindgen-react-native `
            --git https://github.com/jhugman/uniffi-bindgen-react-native.git `
            --tag 0.31.0-5 --locked --no-default-features --root $nodeToolRoot
    }
    if (-not (Test-Path $csharpTool)) {
        Invoke-Checked cargo install uniffi-bindgen-cs `
            --git https://github.com/NordSecurity/uniffi-bindgen-cs.git `
            --tag v0.11.0+v0.31.0 --locked --root $csharpToolRoot
    }
}

if (-not (Test-Path $nodeTool) -or -not (Test-Path $csharpTool)) {
    throw 'Pinned UniFFI generators are missing. Run without -SkipToolInstall first.'
}

Push-Location $src
try {
    $buildArguments = @('build', '-p', 'mxc_uniffi')
    if ($Configuration -eq 'Release') {
        $buildArguments += '--release'
    }
    Invoke-Checked cargo @buildArguments

    New-Item -ItemType Directory -Force $nodeOut, $csharpOut | Out-Null
    Invoke-Checked $nodeTool generate napi bindings $library `
        --library --crate mxc_uniffi --ts-dir $nodeOut --lib-colocated --no-format
    Invoke-Checked $csharpTool $library `
        --library --crate mxc_uniffi --config $config --out-dir $csharpOut --no-format
    Get-ChildItem $nodeOut -Filter '*.ts' | ForEach-Object {
        Normalize-GeneratedFile $_.FullName
    }
    Normalize-GeneratedFile (Join-Path $csharpOut 'mxc_uniffi.cs')
} finally {
    Pop-Location
}

Write-Host "Generated Node bindings in $nodeOut"
Write-Host "Generated C# bindings in $csharpOut"
