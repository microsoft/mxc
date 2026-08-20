#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-download-test-{0}' -f ([guid]::NewGuid()))
$fakeDrop = Join-Path $testRoot 'fake-drop.ps1'
$outDir = Join-Path $testRoot 'out'
$script = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-IsoSessionOsBinaries.ps1'

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    @'
$verb = $args[0]
if ($verb -eq 'list') {
    $jsonIndex = [array]::IndexOf($args, '--toJsonFile')
    $jsonFile = $args[$jsonIndex + 1]
    @(
        @{
            Name = 'wdg/test/arm64fre/BIN/older'
            UploadComplete = $true
            DeletePending = $false
            CreatedDateUtc = '2026-08-01T00:00:00Z'
        },
        @{
            Name = 'wdg/test/arm64fre/BIN/newest'
            UploadComplete = $true
            DeletePending = $false
            CreatedDateUtc = '2026-08-02T00:00:00Z'
        }
    ) | ConvertTo-Json | Set-Content -LiteralPath $jsonFile -Encoding UTF8
    exit 0
}
if ($verb -eq 'get') {
    $destinationIndex = [array]::IndexOf($args, '-d')
    $destination = $args[$destinationIndex + 1]
    $filterIndex = [array]::IndexOf($args, '-r')
    $filters = if ($filterIndex -ge 0) { $args[$filterIndex + 1] } else { '' }
    if ($filters -notmatch '/windows\.ai\.isolationsession\.winmd' -or
        $filters -notmatch '/windows\.ai\.isolationsession\.preview\.winmd') {
        Write-Output 'WinMD filters were not requested.'
        exit 3
    }
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    foreach ($name in @(
        'IsoSessionServer.dll',
        'IsoSessionCore.dll',
        'IsoSessionClient.dll',
        'IsoSessionApp.dll',
        'IsoSessionProxyStub.dll',
        'IsolationProxy.exe',
        'IsoSessionCli.exe',
        'windows.ai.isolationsession.winmd',
        'windows.ai.isolationsession.preview.winmd'
    )) {
        $content = if ($name -eq 'IsoSessionClient.dll') {
            "SOFTWARE\Microsoft\IsoSession ClientClsid IsolationSession_"
        } else {
            $name
        }
        [System.IO.File]::WriteAllText(
            (Join-Path $destination $name),
            $content,
            [System.Text.Encoding]::Unicode)
    }
    exit 0
}
exit 9
'@ | Set-Content -LiteralPath $fakeDrop -Encoding UTF8

    & $script `
        -DropExe $fakeDrop `
        -BuildGuid '72de6fa1-35ec-8b71-6bd4-6e74b1af57db' `
        -ArchTag arm64 `
        -OutDir $outDir `
        -UseAadAuth

    $manifest = Get-Content (Join-Path $outDir 'source-manifest.json') -Raw |
        ConvertFrom-Json
    if ($manifest.dropName -ne 'wdg/test/arm64fre/BIN/newest') {
        throw "Resolver did not select the newest finalized drop: $($manifest.dropName)"
    }
    if ($manifest.flavor -ne 'arm64fre' -or $manifest.files.Count -ne 9) {
        throw 'Download manifest did not contain the expected ARM64 payload.'
    }
    if (@($manifest.files | Where-Object { $_.kind -eq 'winmd' }).Count -ne 2) {
        throw 'Download manifest did not contain both WinMD payloads.'
    }

    Write-Host 'IsoSession filtered download tests passed.'
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
