# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#Requires -Version 7.0

[CmdletBinding()]
param([Parameter(Mandatory)][string]$BinDir)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\NativeProcessContainer.ps1')
$wxc = Join-Path (Resolve-Path -LiteralPath $BinDir).Path 'wxc-exec.exe'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$registry = Get-Content -LiteralPath (Join-Path $repo 'schemas\schema-version.json') -Raw | ConvertFrom-Json
$versions = @($registry.min, $registry.stableLatest, $registry.maxSupported) | Select-Object -Unique
$scratch = Join-Path $env:TEMP ("mxc-native-contracts-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
Write-Host "Native CLI contract artifacts: $scratch"
$hostProbe = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
    -Name 'host-probe' -Arguments @('--probe')
if ($hostProbe.ExitCode -ne 0) { throw "Native contract host probe failed: $($hostProbe.Stderr)" }
$facts = ($hostProbe.Stdout | ConvertFrom-Json).probes
if (-not $facts.baseContainerApiPresent) { throw 'CLI contract validation requires native PSEC.' }
$passed = 0

function New-ContractRequest {
    param([string]$Name, [string]$Version)
    $sentinel = Join-Path $scratch "$Name.executed"
    $code = "[IO.File]::WriteAllText('$($sentinel.Replace("'", "''"))','ran');[Console]::WriteLine('CLI_BOUNDARY_OK')"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    @{
        version = $Version
        containment = 'processcontainer'
        process = @{ commandLine = "`"$powershell`" -NoProfile -NonInteractive -EncodedCommand $encoded"; cwd = $scratch; timeout = 30000 }
        filesystem = @{ readwritePaths = @($scratch); readonlyPaths = @($env:SystemRoot) }
        ui = @{ disable = $false }
        telemetry = @{ enabled = $false }
        processContainer = @{}
    }
}

function Invoke-ContractCase {
    param(
        [string]$Name,
        [hashtable]$Request,
        [string]$Rejection,
        [string]$ExpectedOutput = 'CLI_BOUNDARY_OK'
    )
    $path = Join-Path $scratch "$Name.json"
    $Request | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path
    $security = Get-NativeFixtureSecuritySnapshot -Paths @($scratch)
    try {
        $result = Invoke-NativeProcessContainer -WxcExec $wxc -ScratchRoot $scratch `
            -Name $Name -Arguments @($path)
        if ($Rejection) {
            if ($result.ExitCode -ne 1 -or $result.Stderr -notmatch $Rejection -or
                $result.Log -match '"event":"mxc.ProcessExited"' -or
                (Test-Path -LiteralPath (Join-Path $scratch "$Name.executed"))) {
                throw "$Name was not rejected before execution: exit=$($result.ExitCode); stderr=$($result.Stderr)"
            }
        } elseif ($result.ExitCode -ne 0 -or $result.Stdout.Trim() -cne $ExpectedOutput -or
            $result.Log -notmatch '"tier":"base-container"') {
            throw "$Name did not execute successfully in native PSEC: exit=$($result.ExitCode); stdout=$($result.Stdout); stderr=$($result.Stderr)"
        }
    } finally {
        Assert-NativeFixtureSecurity -Name $Name -Snapshot $security
    }
    $script:passed++
    Write-Host "PASSED: $Name"
}

foreach ($version in $versions) {
    foreach ($case in @(
        @{ Name = 'omitted' },
        @{ Name = 'empty'; Capabilities = @() },
        @{ Name = 'unknown'; Capabilities = @('notARealCapability') },
        @{ Name = 'misspelled'; Capabilities = @('internetCleint') },
        @{ Name = 'multiple'; Capabilities = @('internetClient', 'registryRead') }
    )) {
        $name = "capabilities-$($case.Name)-$version"
        $request = New-ContractRequest -Name $name -Version $version
        if ($case.ContainsKey('Capabilities')) { $request.processContainer.capabilities = $case.Capabilities }
        Invoke-ContractCase -Name $name -Request $request
    }
    foreach ($lifecycle in @(
        @{ destroyOnExit = $true }, @{ destroyOnExit = $false },
        @{ preservePolicy = $true }, @{ preservePolicy = $false },
        @{ destroyOnExit = $true; preservePolicy = $false }
    )) {
        $name = "lifecycle-$version-$passed"
        $request = New-ContractRequest -Name $name -Version $version
        $request.lifecycle = $lifecycle
        Invoke-ContractCase -Name $name -Request $request
    }
    foreach ($enabled in @($false, $true)) {
        $name = "telemetry-$enabled-$version"
        $request = New-ContractRequest -Name $name -Version $version
        $request.telemetry.enabled = $enabled
        Invoke-ContractCase -Name $name -Request $request
    }
}

$networkCases = @(
    @{
        Name = 'empty-destinations'
        Network = @{ egress = @{ default = 'deny'; allow = @(@{ to = @() }) } }
        Rejection = 'network\.egress\.allow\[0\]\.to.*array must not be empty'
    },
    @{
        Name = 'empty-ports'
        Network = @{ egress = @{ default = 'deny'; allow = @(@{ ports = @() }) } }
        Rejection = 'network\.egress\.allow\[0\]\.ports.*array must not be empty'
    },
    @{
        Name = 'hostname-cidr'
        Network = @{ egress = @{ default = 'deny'; allow = @(@{ to = @(@{ cidr = 'example.com' }) }) } }
        Rejection = 'network\.egress\.allow\[0\]\.to\[0\]\.cidr.*valid network CIDR'
    },
    @{
        Name = 'missing-range-start'
        Network = @{ egress = @{ default = 'deny'; allow = @(@{ ports = @(@{ protocol = 'tcp'; endPort = 500 }) }) } }
        Rejection = 'network\.egress\.allow\[0\]\.ports\[0\]\.endPort.*requires port'
    },
    @{
        Name = 'remote-proxy'
        Network = @{
            egress = @{ default = 'deny' }
            ingress = @{ default = 'allow'; hostLoopback = 'allow' }
        }
        RuntimeConfig = @{ networkProxy = 'http://proxy.example.com:8080' }
        Rejection = 'runtimeConfig\.networkProxy.*must use localhost'
    },
    @{
        Name = 'legacy-default-policy'
        Network = @{ defaultPolicy = 'block'; egress = @{ default = 'allow' } }
        Rejection = 'unknown field `defaultPolicy`'
    }
)
foreach ($version in $versions) {
    foreach ($case in $networkCases) {
        $name = "network-reject-$($case.Name)-$version"
        $request = New-ContractRequest -Name $name -Version $version
        $request.network = $case.Network
        if ($case.ContainsKey('RuntimeConfig')) { $request.runtimeConfig = $case.RuntimeConfig }
        Invoke-ContractCase -Name $name -Request $request -Rejection $case.Rejection
    }
    $name = "network-valid-control-$version"
    $request = New-ContractRequest -Name $name -Version $version
    $request.network = @{
        egress = @{ default = 'allow' }
        ingress = @{ default = 'deny'; hostLoopback = 'deny' }
    }
    Invoke-ContractCase -Name $name -Request $request
}

$product = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName
if ([string]::IsNullOrWhiteSpace($product)) { throw 'The host registry-read control returned no ProductName.' }
$registryRequest = New-ContractRequest -Name 'registry-read' -Version $registry.stableLatest
$registryCode = "[Console]::WriteLine((Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName))"
$registryRequest.process.commandLine = "`"$powershell`" -NoProfile -NonInteractive -EncodedCommand " +
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($registryCode))
$registryRequest.processContainer.capabilities = @('registryRead')
Invoke-ContractCase -Name 'registry-read' -Request $registryRequest -ExpectedOutput $product

foreach ($case in @(
    @{ Name = 'relative'; Path = 'capture.json'; Error = 'must be an absolute path' },
    @{ Name = 'root'; Path = [IO.Path]::GetPathRoot($scratch); Error = 'directory root' },
    @{ Name = 'missing-parent'; Path = (Join-Path $scratch 'missing\capture.json'); Error = 'parent directory does not exist' },
    @{ Name = 'directory'; Path = $scratch; Error = 'existing directory' }
)) {
    $name = "capture-path-$($case.Name)"
    $request = New-ContractRequest -Name $name -Version $registry.stableLatest
    $request.processContainer.captureDenials = @{ outputPath = $case.Path }
    Invoke-ContractCase -Name $name -Request $request -Rejection ([regex]::Escape($case.Error))
}
$validCapture = New-ContractRequest -Name 'capture-path-valid-control' -Version $registry.stableLatest
$validCapture.processContainer.captureDenials = @{ outputPath = (Join-Path $scratch 'capture.json') }
if ($facts.nativeCaptureAvailable) {
    Invoke-ContractCase -Name 'capture-path-valid-control' -Request $validCapture
} else {
    Invoke-ContractCase -Name 'capture-path-valid-control' -Request $validCapture `
        -Rejection 'requires native Learning Mode capture support'
}

foreach ($version in @('0.8.0-alpha', '9999.0.0', 'not-a-version')) {
    $name = "rejected-version-$version"
    Invoke-ContractCase -Name $name -Request (New-ContractRequest -Name $name -Version $version) `
        -Rejection '(?i)version'
}
if ($passed -eq 0) { throw 'The native CLI contract suite executed no cases.' }
Write-Host "PASSED: all $passed native CLI contract cases"
$global:LASTEXITCODE = 0
