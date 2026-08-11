#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-stage-test-{0}' -f ([guid]::NewGuid()))
$dropRoot = Join-Path $testRoot 'drop'
$outDir = Join-Path $testRoot 'out'
$script = Join-Path (Split-Path $PSScriptRoot -Parent) 'Stage-IsoSessionOsBinaries.ps1'

try {
    New-Item -ItemType Directory -Path $dropRoot | Out-Null
    $required = @(
        'IsoSessionServer.dll',
        'IsoSessionClient.dll',
        'IsoSessionApp.dll',
        'IsoSessionProxyStub.dll',
        'IsolationProxy.exe',
        'IsoSessionCli.exe',
        'windows.ai.isolationsession.winmd',
        'windows.ai.isolationsession.preview.winmd'
    )
    foreach ($name in $required) {
        [System.IO.File]::WriteAllText((Join-Path $dropRoot $name), "test-$name")
    }

    & $script `
        -DropRoot $dropRoot `
        -OutDir $outDir `
        -ArchTag arm64 `
        -BuildGuid '72de6fa1-35ec-8b71-6bd4-6e74b1af57db' `
        -DropName 'wdg/test/arm64fre/BIN/test' `
        -Flavor arm64fre

    foreach ($name in $required) {
        $staged = Join-Path $outDir "bin\arm64\$name"
        if (-not (Test-Path -LiteralPath $staged -PathType Leaf)) {
            throw "Expected staged file missing: $staged"
        }
    }

    $manifest = Get-Content (Join-Path $outDir 'source-manifest.json') -Raw |
        ConvertFrom-Json
    if ($manifest.arch -ne 'arm64' -or $manifest.files.Count -ne $required.Count) {
        throw 'Source manifest did not contain the expected architecture and files.'
    }
    $winmdEntry = $manifest.files | Where-Object { $_.name -eq 'windows.ai.isolationsession.preview.winmd' }
    if (-not $winmdEntry -or $winmdEntry.kind -ne 'winmd' -or
        $winmdEntry.relativeSourcePath -ne 'windows.ai.isolationsession.preview.winmd') {
        throw 'WinMD provenance was not recorded in the expected relative-path form.'
    }

    Remove-Item -LiteralPath (Join-Path $dropRoot 'IsoSessionCli.exe') -Force
    $failed = $false
    try {
        & $script `
            -DropRoot $dropRoot `
            -OutDir (Join-Path $testRoot 'missing') `
            -ArchTag x64 `
            -BuildGuid '72de6fa1-35ec-8b71-6bd4-6e74b1af57db' `
            -DropName 'wdg/test/amd64fre/BIN/test' `
            -Flavor amd64fre
    }
    catch {
        $failed = $true
    }
    if (-not $failed) {
        throw 'Staging unexpectedly succeeded with a required binary missing.'
    }

    Write-Host 'IsoSession OS binary staging tests passed.'
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
