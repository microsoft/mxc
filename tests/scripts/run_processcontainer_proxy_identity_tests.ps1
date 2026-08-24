# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Exercises the four proxy identity shapes accepted by the schema 0.8
# ProcessContainer network model: packaged/unpackaged AppContainer peers,
# a packaged full-trust peer, and host loopback for unpackaged full trust.

[CmdletBinding()]
param(
    [string]$BinDir = (Join-Path $PSScriptRoot '..\..\src\target\debug'),
    [string]$PackageOutput = (Join-Path $env:TEMP 'mxc-proxy-test-packages'),
    [switch]$PackagedOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$proxyPort = 8080
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$wxc = Join-Path $BinDir 'wxc-exec.exe'
$proxy = Join-Path $BinDir 'wxc-test-proxy.exe'
$packageBuilder = Join-Path $repoRoot 'tests\assets\processcontainer-proxy-packages\build-proxy-test-packages.ps1'
$testRoot = Join-Path $env:TEMP "mxc-proxy-identity-$PID"
$firewallRules = @()
$processes = @()
$packages = $null
$appContainerProfile = "MXC-Unpackaged-AppContainer-Proxy-$PID"

if (-not (Test-Path $wxc) -or -not (Test-Path $proxy)) {
    throw "Expected wxc-exec.exe and wxc-test-proxy.exe in $BinDir"
}

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$runUnpackaged = -not $PackagedOnly -and $isElevated
if (-not $PackagedOnly -and -not $isElevated) {
    Write-Host 'SKIPPED: unpackaged proxy cases require administrator firewall rules.' `
        -ForegroundColor Yellow
}

function Invoke-ProxyLauncher {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $proxy @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne 0) {
        $details = ($output | ForEach-Object { "$_" }) -join '; '
        throw "wxc-test-proxy $($Arguments[0]) failed with exit code $exitCode`: $details"
    }
    if ($output.Count -ne 1) {
        throw "wxc-test-proxy $($Arguments[0]) returned $($output.Count) output lines; expected one"
    }
    return "$($output[0])".Trim()
}

function Invoke-ProxyLauncherPid {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = Invoke-ProxyLauncher $Arguments
    if ($output -notmatch '^[1-9][0-9]*$') {
        throw "wxc-test-proxy $($Arguments[0]) returned invalid PID '$output'"
    }
    return [uint32]$output
}

function Wait-Proxy {
    param(
        [int]$Port,
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [string]$ReadyFile
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "Proxy process $($Process.Id) exited with code $($Process.ExitCode)"
        }
        if ($ReadyFile) {
            if (Test-Path $ReadyFile) {
                $readyPort = (Get-Content $ReadyFile -Raw).Trim()
                if ($readyPort -eq "$Port") {
                    return
                }
                if ($readyPort) {
                    throw "Proxy process $($Process.Id) reported unexpected port '$readyPort'"
                }
            }
        } else {
            $listener = Get-NetTCPConnection -LocalPort $Port -State Listen `
                -OwningProcess $Process.Id -ErrorAction SilentlyContinue
            if ($listener) {
                return
            }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Proxy process $($Process.Id) did not listen on port $Port"
}

function Stop-Proxy {
    param([Parameter(Mandatory)][Diagnostics.Process]$Process)

    $Process | Stop-Process -Force
    if (-not $Process.WaitForExit(10000)) {
        throw "Proxy process $($Process.Id) did not exit after termination"
    }
}

function Invoke-Client {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$AllowedPeer,
        [ValidateSet('allow', 'deny')][string]$HostLoopback = 'deny',
        [switch]$ExpectFailure
    )

    $clientCommand = 'powershell.exe -NoProfile -Command "$h=New-Object -ComObject ' +
        'WinHttp.WinHttpRequest.5.1; $h.Open(''GET'',''https://www.example.com'',$false); ' +
        '$h.Send(); if ($h.Status -ne 200) { exit 1 }; Write-Output $h.ResponseText"'
    $config = @{
        version = '0.8.0-alpha'
        containerId = "proxy-client-$Name"
        containment = 'processcontainer'
        process = @{ commandLine = $clientCommand }
        ui = @{ disable = $false }
        network = @{
            egress = @{ default = 'deny' }
            ingress = @{ default = 'allow'; hostLoopback = $HostLoopback }
        }
        runtimeConfig = @{ networkProxy = "http://127.0.0.1:$proxyPort" }
        processContainer = @{}
    }
    if ($AllowedPeer) {
        $config.processContainer.network = @{ allowedProxyPeer = $AllowedPeer }
    }
    $configPath = Join-Path $testRoot "$Name.json"
    [IO.File]::WriteAllText(
        $configPath,
        ($config | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $wxc --config $configPath
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($ExpectFailure) {
        if ($exitCode -eq 0) {
            throw "$Name unexpectedly succeeded"
        }
        return
    }
    if ($exitCode -ne 0) {
        throw "$Name client failed with exit code $exitCode"
    }
}

function Start-PackagedProxy {
    param([Parameter(Mandatory)][string]$PackageName)

    $package = Get-AppxPackage -Name $PackageName
    if (-not $package) {
        throw "Installed package $PackageName was not found"
    }
    $readyFile = Join-Path $env:LOCALAPPDATA `
        "Packages\$($package.PackageFamilyName)\LocalState\proxy-ready-$PID"
    Remove-Item $readyFile -Force -ErrorAction SilentlyContinue
    $pidValue = Invoke-ProxyLauncherPid @(
        'activate-package',
        '--app-user-model-id', "$($package.PackageFamilyName)!Proxy",
        '--port', "$proxyPort",
        '--ready-file', $readyFile
    )
    $process = Get-Process -Id $pidValue
    $script:processes += $process
    Wait-Proxy -Port $proxyPort -Process $process -ReadyFile $readyFile
    Remove-Item $readyFile -Force -ErrorAction SilentlyContinue
    return $package.PackageFamilyName
}

function Start-UnpackagedProxy {
    $process = Start-Process $proxy -ArgumentList '--port', $proxyPort, '--standalone' -PassThru
    $script:processes += $process
    Wait-Proxy -Port $proxyPort -Process $process
}

New-Item -ItemType Directory $testRoot -Force | Out-Null
try {
    $packages = & $packageBuilder -ProxyBinary $proxy -OutputDirectory $PackageOutput
    foreach ($manifestPath in $packages.AppContainerManifest, $packages.FullTrustManifest) {
        Add-AppxPackage -Path $manifestPath -Register
    }

    $wrongPeer = (Get-AppxPackage -Name 'Microsoft.MXC.TestProxy.FullTrust').PackageFamilyName
    $peer = Start-PackagedProxy 'Microsoft.MXC.TestProxy.AppContainer'
    Invoke-Client -Name 'packaged-appcontainer-wrong-peer' -AllowedPeer $wrongPeer `
        -ExpectFailure
    Invoke-Client -Name 'packaged-appcontainer' -AllowedPeer $peer
    Stop-Proxy $processes[-1]

    $peer = Start-PackagedProxy 'Microsoft.MXC.TestProxy.FullTrust'
    Invoke-Client -Name 'packaged-fulltrust' -AllowedPeer $peer
    Stop-Proxy $processes[-1]

    if ($runUnpackaged) {
        $proxyPid = Invoke-ProxyLauncherPid @(
            'launch-appcontainer',
            '--profile', $appContainerProfile,
            '--port', "$proxyPort"
        )
        $process = Get-Process -Id $proxyPid
        $processes += $process
        $profileSid = Invoke-ProxyLauncher @(
            'derive-appcontainer-sid',
            '--profile', $appContainerProfile
        )
        $rule = "MXC proxy test $PID appcontainer"
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $proxyPort -Program $proxy -Package $profileSid | Out-Null
        $firewallRules += $rule

        Wait-Proxy -Port $proxyPort -Process $process
        Invoke-Client -Name 'unpackaged-appcontainer' -AllowedPeer $appContainerProfile
        Stop-Proxy $process

        $rule = "MXC proxy test $PID fulltrust"
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $proxyPort -Program $proxy | Out-Null
        $firewallRules += $rule
        Start-UnpackagedProxy
        Invoke-Client -Name 'unpackaged-fulltrust' -HostLoopback allow
    }
} finally {
    foreach ($process in $processes) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($rule in $firewallRules) {
        Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    }
    Get-AppxPackage -Name 'Microsoft.MXC.TestProxy.AppContainer' |
        Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage -Name 'Microsoft.MXC.TestProxy.FullTrust' |
        Remove-AppxPackage -ErrorAction SilentlyContinue
    if ($packages) {
        foreach ($directory in $packages.AppContainerDirectory, $packages.FullTrustDirectory) {
            Remove-Item $directory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $proxy delete-appcontainer --profile $appContainerProfile 2>$null | Out-Null
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Remove-Item $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
