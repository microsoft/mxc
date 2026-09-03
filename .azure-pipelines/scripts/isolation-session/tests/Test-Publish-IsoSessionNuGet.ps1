#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'mxc-isosession-publish-test-{0}' -f ([guid]::NewGuid()))
$script = Join-Path (Split-Path $PSScriptRoot -Parent) 'Publish-IsoSessionNuGet.ps1'

try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    $packagePath = Join-Path $testRoot 'Microsoft.Windows.AI.IsolationSession.SDK.0.202608.1.nupkg'
    Set-Content -LiteralPath $packagePath -Value 'package-bytes' -Encoding UTF8

    $fakeNuGet = Join-Path $testRoot 'fake-nuget.ps1'
    @'
$verb = $args[0]
$packagePath = $args[1]
$sourceIndex = [array]::IndexOf($args, '-Source')
$feedUrl = if ($sourceIndex -ge 0) { $args[$sourceIndex + 1] } else { '' }

if ($env:FAKE_NUGET_MODE -eq 'duplicate') {
    Write-Output '409 Conflict - package already exists.'
    exit 1
}

if ($verb -ne 'push' -or $sourceIndex -lt 0 -or -not $feedUrl) {
    Write-Output 'unexpected invocation'
    exit 2
}

Write-Output "pushed $packagePath to $feedUrl"
exit 0
'@ | Set-Content -LiteralPath $fakeNuGet -Encoding UTF8

    & $script `
        -NuGetExe $fakeNuGet `
        -PackagePath $packagePath `
        -FeedUrl 'https://example.test/feed/index.json'

    $duplicateFailed = $false
    try {
        $env:FAKE_NUGET_MODE = 'duplicate'
        & $script `
            -NuGetExe $fakeNuGet `
            -PackagePath $packagePath `
            -FeedUrl 'https://example.test/feed/index.json'
    }
    catch {
        $duplicateFailed = $true
    }
    finally {
        Remove-Item Env:FAKE_NUGET_MODE -ErrorAction SilentlyContinue
    }

    if (-not $duplicateFailed) {
        throw 'Publish-IsoSessionNuGet.ps1 unexpectedly allowed a duplicate package publication.'
    }

    Write-Host 'IsoSession NuGet publish tests passed.'
    exit 0
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
