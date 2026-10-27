# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [string]$WxcExec,
    [string]$WorkDirectory = (Join-Path $env:TEMP 'mxc-issue-694'),
    [string]$ProbeExe
)

$ErrorActionPreference = 'Stop'
$regressionRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $regressionRoot 'inc\Resolve-RegressionExecutable.ps1')
$WxcExec = Resolve-RegressionExecutable $WxcExec 'wxc-exec.exe'
$scratch = Join-Path $WorkDirectory ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$scratch = (Resolve-Path -LiteralPath $scratch).Path
Write-Host "Issue #694 artifacts: $scratch"

$source = Join-Path $PSScriptRoot 'data\Issue694-FinalPathProbe.cs'
$probe = if ($ProbeExe) { (Resolve-Path -LiteralPath $ProbeExe -ErrorAction Stop).Path } else {
    Join-Path $scratch 'final-path-probe.exe'
}
if (-not $ProbeExe) {
    $compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
        throw "The inbox .NET Framework compiler is required: $compiler"
    }
    & $compiler /nologo /target:exe /platform:anycpu "/out:$probe" $source
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $probe -PathType Leaf)) {
        throw 'Could not compile the final-path probe with the inbox .NET Framework compiler.'
    }
}
$inputFile = Join-Path $scratch 'input.json'
Set-Content -LiteralPath $inputFile -Value '{}' -NoNewline
$hostOutput = @(& $probe $inputFile 2>&1)
if ($LASTEXITCODE -ne 0) { throw "Final-path host control failed: $($hostOutput -join "`n")" }
$expected = @{}
foreach ($line in $hostOutput) {
    if ($line -match '^(VOLUME_NAME_DOS|VOLUME_NAME_NT): (.+)$') { $expected[$matches[1]] = $matches[2] }
}
if ($expected.Count -ne 2 -or -not $expected.VOLUME_NAME_DOS.StartsWith('\\?\') -or
    -not $expected.VOLUME_NAME_NT.StartsWith('\Device\')) {
    throw 'The host control did not return both normalized DOS and NT paths.'
}

$readonly = @($env:SystemRoot)
if ((Split-Path -Parent $probe) -ine $scratch) { $readonly += Split-Path -Parent $probe }
$request = @{
    version = '1.0.0'
    containment = 'processcontainer'
    process = @{ commandLine = "`"$probe`" `"$inputFile`""; cwd = $scratch; timeout = 30000 }
    filesystem = @{ readwritePaths = @($scratch); readonlyPaths = $readonly }
    ui = @{ disable = $false }
}
$path = Join-Path $scratch 'request.json'
$request | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path
$security = Get-Acl -LiteralPath $scratch
try {
    $logPath = Join-Path $scratch 'native-final-path.log'
    $errorPath = Join-Path $scratch 'native-final-path.stderr.txt'
    $stdout = (& $WxcExec --log-file $logPath $path 2> $errorPath | Out-String)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or (Get-Content -LiteralPath $logPath -Raw) -notmatch '"tier":"base-container"') {
        throw "Native final-path probe failed: exit=$exitCode; stderr=$(Get-Content -LiteralPath $errorPath -Raw)"
    }
    $actual = @{}
    foreach ($line in ($stdout -split "`r?`n")) {
        if ($line -match '^(VOLUME_NAME_DOS|VOLUME_NAME_NT): (.+)$') { $actual[$matches[1]] = $matches[2] }
    }
    foreach ($name in 'VOLUME_NAME_DOS', 'VOLUME_NAME_NT') {
        $prefix = if ($name -eq 'VOLUME_NAME_DOS') { '\\?\' } else { '\Device\' }
        if (-not $actual.ContainsKey($name) -or -not $actual[$name].StartsWith($prefix) -or
            -not $actual[$name].EndsWith('\input.json', [StringComparison]::OrdinalIgnoreCase)) {
            throw "$name did not return a valid final path for the fixture file: $stdout"
        }
    }
    Write-Host 'PASSED: native GetFinalPathNameByHandle returns DOS and NT paths'
} finally {
    if ((Get-Acl -LiteralPath $scratch).Sddl -cne $security.Sddl) {
        Set-Acl -LiteralPath $scratch -AclObject $security
        throw 'Native final-path execution changed the owned fixture security descriptor.'
    }
}
